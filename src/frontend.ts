import { ConfigurationError } from './errors.js';

/**
 * The browser-safe half of the SDK.
 *
 * Everything else in this package assumes a server: it holds a client secret, it exchanges
 * codes, it verifies webhooks. None of that may run in a page, which is why the UI
 * components have always been redirect shells — a page that cannot authenticate itself to
 * the identity provider cannot ask it anything, so it sends the person away and waits.
 *
 * A publishable key changes that. It is public on purpose: it ships in your bundle, it is
 * visible in devtools, and it is safe there because it only works from the origins you
 * registered. What it buys is that a page can read its OWN sign-in configuration — the
 * endpoints, the social buttons, your theme — and render a form itself.
 *
 * This client deliberately has no secret, no token storage and no crypto. It reads two
 * documents. Anything that mints or holds a credential still belongs on your server.
 */

/** How a page identifies itself. Public — put it in your bundle. */
export interface FrontendClientOptions {
  /** Your identity provider's origin, e.g. `https://id.acme.com`. */
  issuer: string;
  /** `pk_live_…` or `pk_test_…`. Safe to publish. */
  publishableKey: string;
  /** Abort after this long. Defaults to 10s. */
  timeoutMs?: number;
  /** Injectable for tests and for runtimes with a non-global fetch. */
  fetch?: typeof globalThis.fetch;
}

/** A social button to draw. Name and provider only — never an internal id. */
export interface SocialProvider {
  provider: string;
  name: string;
}

/** The customer's theme, when they have set one. Absent means "use your own defaults". */
export interface Appearance {
  preset: string;
  radius: string;
  font: string;
  light: Record<string, string>;
  dark: Record<string, string>;
}

/** Everything needed to draw a sign-in box, and nothing that identifies anybody. */
export interface FrontendConfig {
  mode: 'test' | 'live' | null;
  issuer: string;
  endpoints: {
    authorization: string;
    token: string;
    userinfo: string;
    end_session: string;
    jwks: string;
  };
  social: SocialProvider[];
  appearance?: Appearance;
}

/** Who the browser is signed in as, or nobody. */
export interface FrontendSession {
  user: { id: string; email: string; name: string | null } | null;
}

/**
 * Reads the public configuration and the current session from a browser.
 *
 * ```ts
 * const frontend = new CboxIdFrontend({
 *   issuer: 'https://id.acme.com',
 *   publishableKey: 'pk_live_…',
 * })
 *
 * const config = await frontend.config()   // cached for you; safe to call per component
 * const { user } = await frontend.session(accessToken)
 * ```
 */
export class CboxIdFrontend {
  private readonly issuer: string;
  private readonly publishableKey: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof globalThis.fetch;

  /**
   * The config document, and the in-flight promise for it.
   *
   * Deduplicated rather than merely cached: a page with a sign-in form, a user button and
   * an organization switcher mounts three components in the same tick, and three parallel
   * fetches of the same immutable document is a waste the SDK should absorb rather than
   * ask every consumer to.
   */
  private configPromise: Promise<FrontendConfig> | null = null;

  constructor(options: FrontendClientOptions) {
    if (!options.issuer) {
      throw new ConfigurationError('issuer is required.');
    }

    // Caught here rather than at the first request, because the failure otherwise arrives
    // as an opaque 401 from the network tab and the cause — a secret key pasted into a
    // browser bundle — is exactly the mistake worth naming out loud.
    if (!options.publishableKey?.startsWith('pk_')) {
      throw new ConfigurationError(
        'publishableKey must be a pk_test_… or pk_live_… key. Client secrets and API keys must never be put in a browser.',
      );
    }

    this.issuer = options.issuer.replace(/\/$/, '');
    this.publishableKey = options.publishableKey;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Whether this key drives real sign-ins. Handy for a "test mode" badge in your own UI. */
  get isLive(): boolean {
    return this.publishableKey.startsWith('pk_live_');
  }

  /**
   * The public sign-in configuration.
   *
   * Fetched once per client instance. The document is small and changes when somebody
   * edits it in the console, so a long-lived page picks changes up on its next full load
   * rather than mid-session — which is the right trade for something that decides layout.
   */
  async config(): Promise<FrontendConfig> {
    this.configPromise ??= this.get<FrontendConfig>('/frontend/v1/config').catch((error: unknown) => {
      // Cleared so a transient network failure does not poison the instance for the
      // lifetime of the page.
      this.configPromise = null;
      throw error;
    });

    return this.configPromise;
  }

  /**
   * Who is signed in, given an access token your app already holds.
   *
   * Returns `{ user: null }` rather than throwing when nobody is signed in. That is a
   * state, not an error: a user button renders on pages nobody has signed in on, and
   * making callers treat a rejection as a state is how flash-of-signed-out bugs happen.
   *
   * The publishable key grants nothing here — the token is the entire authority.
   */
  async session(accessToken?: string): Promise<FrontendSession> {
    if (!accessToken) {
      return { user: null };
    }

    return this.get<FrontendSession>('/frontend/v1/session', {
      Authorization: `Bearer ${accessToken}`,
    });
  }

  private async get<T>(path: string, extraHeaders: Record<string, string> = {}): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(`${this.issuer}${path}`, {
        headers: {
          // A header, never a query string: a query string puts the key in server logs,
          // in `Referer` on every outbound link, and in browser history.
          'X-Cbox-Publishable-Key': this.publishableKey,
          Accept: 'application/json',
          ...extraHeaders,
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        // A refused request carries no CORS headers by design, so in a browser this
        // usually surfaces as a network error before it ever reaches here. When it does
        // reach here, the overwhelmingly likely cause is the one worth naming.
        throw new ConfigurationError(
          `Cbox ID refused the request (${response.status}). Check that this page's origin is on the key's allow-list, and that the key is not revoked.`,
        );
      }

      return (await response.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }
}
