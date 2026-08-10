import { ConfigurationError, FrontendApiError } from './errors.js';

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
  /**
   * How many times to retry a transient failure. Defaults to 2 (so three attempts).
   *
   * Only the network and 5xx are retried. A refusal is a configuration problem and
   * retrying it just delays the developer finding out; a 429 is honoured rather than
   * hammered.
   */
  retries?: number;
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
  private readonly retries: number;
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
    this.retries = Math.max(0, options.retries ?? 2);
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
    this.configPromise ??= this.get<FrontendConfig>('/frontend/v1/config', {}, isFrontendConfig).catch((error: unknown) => {
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

    return this.get<FrontendSession>(
      '/frontend/v1/session',
      { Authorization: `Bearer ${accessToken}` },
      isFrontendSession,
    );
  }

  private async get<T>(
    path: string,
    extraHeaders: Record<string, string> = {},
    validate?: (body: unknown) => body is T,
  ): Promise<T> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.retries; attempt++) {
      // Linear, not exponential, and only between attempts. This sits inside a page
      // render: a caller waiting on their sign-in box would rather fail in a second than
      // succeed in eight.
      if (attempt > 0) {
        await new Promise((resolve) => setTimeout(resolve, 150 * attempt));
      }

      try {
        return await this.attempt<T>(path, extraHeaders, validate);
      } catch (error) {
        lastError = error;

        // Retry only what a retry can fix. A refusal is a configuration problem and
        // retrying it delays the developer finding out; a rate limit is honoured rather
        // than hammered; a malformed body will be malformed again.
        if (!(error instanceof FrontendApiError) || error.code !== 'unavailable') {
          throw error;
        }
      }
    }

    throw lastError;
  }

  private async attempt<T>(
    path: string,
    extraHeaders: Record<string, string>,
    validate?: (body: unknown) => body is T,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;

    try {
      response = await this.fetchImpl(`${this.issuer}${path}`, {
        headers: {
          // A header, never a query string: a query string puts the key in server logs,
          // in `Referer` on every outbound link, and in browser history.
          'X-Cbox-Publishable-Key': this.publishableKey,
          Accept: 'application/json',
          ...extraHeaders,
        },
        signal: controller.signal,
      });
    } catch (cause) {
      // Includes the abort on timeout, and — in a browser — a refusal, because a refused
      // request deliberately carries no CORS headers and so never becomes a Response.
      throw new FrontendApiError(
        `Could not reach Cbox ID at ${this.issuer}. If this is a browser, check that this page's origin is on the key's allow-list — a refused request fails as a network error by design.`,
        'unavailable',
      );
    } finally {
      clearTimeout(timer);
    }

    if (response.status === 429) {
      const retryAfter = Number(response.headers.get('Retry-After') ?? '');

      throw new FrontendApiError(
        'Cbox ID is rate limiting this key.',
        'rate_limited',
        429,
        Number.isFinite(retryAfter) ? retryAfter : undefined,
      );
    }

    if (response.status === 401 || response.status === 403) {
      throw new FrontendApiError(
        `Cbox ID refused the request (${response.status}). Check that this page's origin is on the key's allow-list, and that the key is not revoked.`,
        'origin_not_allowed',
        response.status,
      );
    }

    if (!response.ok) {
      throw new FrontendApiError(
        `Cbox ID returned ${response.status}.`,
        'unavailable',
        response.status,
      );
    }

    let body: unknown;

    try {
      body = await response.json();
    } catch {
      throw new FrontendApiError('Cbox ID returned a body that is not JSON.', 'malformed', response.status);
    }

    // A 200 whose body is not the document we expect means something between the page and
    // us is rewriting responses — a proxy, an extension, a captive portal. Caught here so
    // it surfaces as that, rather than as `undefined` deep inside somebody's component.
    if (validate && !validate(body)) {
      throw new FrontendApiError(
        'Cbox ID returned a body that is not the expected document.',
        'malformed',
        response.status,
      );
    }

    return body as T;
  }
}

/** The shape check for the config document. Structural, not exhaustive. */
function isFrontendConfig(body: unknown): body is FrontendConfig {
  if (typeof body !== 'object' || body === null) {
    return false;
  }

  const doc = body as Partial<FrontendConfig>;

  return typeof doc.issuer === 'string' && typeof doc.endpoints === 'object' && doc.endpoints !== null;
}

/** The shape check for the session document. `user: null` is valid and expected. */
function isFrontendSession(body: unknown): body is FrontendSession {
  return typeof body === 'object' && body !== null && 'user' in body;
}
