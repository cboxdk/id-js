import type { OrganizationRole } from './claims.js';
import { AuthenticationError, ConfigurationError, oauthError } from './errors.js';
import { assertSecureIssuer } from './issuer.js';

/**
 * A customer API key Cbox ID vouches for: live, bound to YOUR app, and held by an active
 * member of `org`.
 *
 * The field names are the endpoint's own, so the claim helpers read it like a token —
 * `hasPermission(answer, 'invoices:create')`, `organization(answer)?.role`. (A type
 * alias rather than an interface for that reason: only an alias is assignable to the
 * helpers' record type.)
 */
export type ActiveApiKey = {
  active: true;
  /** The key's id — log this, never the key. */
  key_id: string;
  /** The person who holds the key (their subject id). */
  sub: string;
  /** The organization the key acts in. */
  org: string;
  /** The holder's membership tier in `org`; null for a tier this SDK does not know. */
  org_role: OrganizationRole | null;
  /**
   * What the key may do, already re-capped by Cbox ID: the key's own list intersected
   * with what the holder holds for your app right now. A demoted holder's key loses the
   * permission on the next verification, not at the next reissue.
   */
  permissions: string[];
  /** Your app's client id — always, or the answer is refused. */
  client_id: string;
  /** ISO 8601 UTC expiry, or null for a key that does not expire. */
  expires_at: string | null;
};

/**
 * Every refusal: unknown, malformed, revoked, expired, another app's key, a holder who
 * left. Cbox ID never says which, so the endpoint cannot be used to probe keys — and
 * neither does this.
 */
export interface InactiveApiKey {
  active: false;
}

/** What {@link ApiKeyVerifier.verifyApiKey} returns. Narrow on `active`. */
export type ApiKeyVerification = ActiveApiKey | InactiveApiKey;

/** Configuration for an {@link ApiKeyVerifier}. */
export interface ApiKeyVerifierConfig {
  /** Base URL (issuer) of the Cbox ID instance. */
  issuer: string;
  /** Your app's OAuth client id — the app the keys were issued for. */
  clientId: string;
  /** Your app's client secret. Verification is a confidential-client call. */
  clientSecret: string;
  /** Timeout (ms) for the verification request. Defaults to `10000`. */
  timeoutMs?: number;
  /**
   * Cache an ACTIVE answer for this long (ms), so a burst of requests with one key costs
   * one round-trip. Off (`0`) by default and at most {@link MAX_API_KEY_CACHE_TTL_MS}:
   * while an answer is cached, a revoked key keeps working, and a demoted holder keeps
   * the permissions they lost. Never cached past the key's `expires_at`. Refusals are
   * never cached, so a key issued a moment ago works on its first request.
   */
  cacheTtlMs?: number;
}

/** The longest {@link ApiKeyVerifierConfig.cacheTtlMs} allowed: one minute. */
export const MAX_API_KEY_CACHE_TTL_MS = 60_000;

/** Enough for a busy API's working set; oldest entries go first beyond it. */
const MAX_CACHE_ENTRIES = 1_000;

const ORGANIZATION_ROLES: ReadonlySet<string> = new Set<OrganizationRole>([
  'owner',
  'admin',
  'developer',
  'member',
  'viewer',
]);

/**
 * Verifies customer API keys presented to your API: `POST {issuer}/oauth/api-keys/verify`,
 * authenticated with your app's own client credentials.
 *
 * SERVER-SIDE ONLY. It holds your client secret, so it lives in the
 * `@cboxdk/id-js/server` entry and the Next.js adapter, never in the main entry that a
 * browser bundle pulls in — and it refuses to be constructed in a browser at all.
 *
 * ```ts
 * import { ApiKeyVerifier } from '@cboxdk/id-js/server';
 * import { hasPermission } from '@cboxdk/id-js';
 *
 * const keys = new ApiKeyVerifier({ issuer, clientId, clientSecret, cacheTtlMs: 10_000 });
 *
 * const answer = await keys.verifyApiKey(request.headers.get('x-api-key') ?? '');
 * if (!answer.active) return unauthorized();
 * if (!hasPermission(answer, 'invoices:create')) return forbidden();
 * ```
 */
export class ApiKeyVerifier {
  private readonly endpoint: string;
  private readonly timeoutMs: number;
  private readonly cacheTtlMs: number;
  private readonly cache = new Map<string, { answer: ActiveApiKey; until: number }>();

  constructor(private readonly config: ApiKeyVerifierConfig) {
    // A heuristic, and enough of one: a page has a `document`, and no server runtime
    // this SDK supports (Node, Deno, Bun, edge workers) defines one.
    if (typeof (globalThis as { document?: unknown }).document !== 'undefined') {
      throw new ConfigurationError(
        'API key verification uses your client secret and must run on your server, never in a browser.',
      );
    }
    if (!config.issuer || !config.clientId || !config.clientSecret) {
      throw new ConfigurationError('Verifying API keys needs issuer, clientId and clientSecret.');
    }
    assertSecureIssuer(config.issuer);

    const cacheTtlMs = config.cacheTtlMs ?? 0;
    if (!Number.isFinite(cacheTtlMs) || cacheTtlMs < 0 || cacheTtlMs > MAX_API_KEY_CACHE_TTL_MS) {
      throw new ConfigurationError(
        `cacheTtlMs must be between 0 and ${MAX_API_KEY_CACHE_TTL_MS}: a cached answer keeps a revoked key working for that long.`,
      );
    }

    this.endpoint = `${config.issuer.replace(/\/$/, '')}/oauth/api-keys/verify`;
    this.timeoutMs = config.timeoutMs ?? 10_000;
    this.cacheTtlMs = cacheTtlMs;
  }

  /**
   * Ask Cbox ID whether `key` is good for this app, and what it may do.
   *
   * Resolves `{ active: false }` for every kind of bad key, without a request for an empty
   * one. Throws `AuthenticationError` when the call itself fails (wrong client
   * credentials, an unreachable instance) or when the answer cannot be trusted — one that
   * names another app's `client_id`, or does not have the promised shape. Both mean "do
   * not let this request in"; the difference is that a throw is something to look at.
   */
  async verifyApiKey(key: string): Promise<ApiKeyVerification> {
    if (typeof key !== 'string' || key.trim() === '') {
      return { active: false };
    }

    const cacheKey = this.cacheTtlMs > 0 ? await digest(key) : null;
    if (cacheKey !== null) {
      const hit = this.cache.get(cacheKey);
      if (hit && hit.until > Date.now()) {
        return hit.answer;
      }
      this.cache.delete(cacheKey);
    }

    const answer = this.parse(await this.request(key));

    if (cacheKey !== null && answer.active) {
      this.remember(cacheKey, answer);
    }

    return answer;
  }

  private async request(key: string): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          authorization: `Basic ${btoa(`${this.config.clientId}:${this.config.clientSecret}`)}`,
          accept: 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ key }),
        signal: controller.signal,
      });
    } catch (error) {
      throw new AuthenticationError(`API key verification request failed: ${String(error)}`);
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      throw await oauthError(response, 'API key verification failed');
    }

    return response.json().catch(() => null);
  }

  private parse(body: unknown): ApiKeyVerification {
    if (typeof body !== 'object' || body === null) {
      throw new AuthenticationError('API key verification returned a body that is not a JSON object.');
    }

    const record = body as Record<string, unknown>;

    // Only a literal `true` lets anybody in.
    if (record['active'] !== true) {
      return { active: false };
    }

    const keyId = record['key_id'];
    const sub = record['sub'];
    const org = record['org'];
    const clientId = record['client_id'];
    const expiresAt = record['expires_at'];
    const permissions = record['permissions'];

    if (
      !nonEmpty(keyId) ||
      !nonEmpty(sub) ||
      !nonEmpty(org) ||
      !nonEmpty(clientId) ||
      !Array.isArray(permissions) ||
      (expiresAt !== null && expiresAt !== undefined && typeof expiresAt !== 'string')
    ) {
      throw new AuthenticationError('API key verification returned an active answer without the promised fields.');
    }

    // THE BINDING, CHECKED AGAIN HERE. Cbox ID only ever finds a key bound to the calling
    // client, so this cannot fire against a correct instance — which is exactly when a
    // check that it holds is worth having: a proxy, a misrouted base URL, or a shared
    // secret between two apps would otherwise let one app's customers into another's API.
    if (clientId !== this.config.clientId) {
      throw new AuthenticationError(
        `API key verification answered for client ${clientId}, not this app (${this.config.clientId}); refusing it.`,
      );
    }

    // Past its expiry by our clock is expired, whatever the instance thought a moment ago.
    if (typeof expiresAt === 'string') {
      const expiry = Date.parse(expiresAt);
      if (Number.isNaN(expiry) || expiry <= Date.now()) {
        return { active: false };
      }
    }

    const role = record['org_role'];

    return {
      active: true,
      key_id: keyId,
      sub,
      org,
      org_role: typeof role === 'string' && ORGANIZATION_ROLES.has(role) ? (role as OrganizationRole) : null,
      permissions: permissions.filter((value): value is string => nonEmpty(value)),
      client_id: clientId,
      expires_at: typeof expiresAt === 'string' ? expiresAt : null,
    };
  }

  private remember(cacheKey: string, answer: ActiveApiKey): void {
    const expiry = answer.expires_at === null ? Number.POSITIVE_INFINITY : Date.parse(answer.expires_at);
    const until = Math.min(Date.now() + this.cacheTtlMs, expiry);

    if (this.cache.size >= MAX_CACHE_ENTRIES) {
      const oldest = this.cache.keys().next();
      if (!oldest.done) {
        this.cache.delete(oldest.value);
      }
    }

    this.cache.set(cacheKey, { answer, until });
  }
}

function nonEmpty(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

/** The cache is keyed by a hash, so live keys are not sitting in memory as plaintext. */
async function digest(key: string): Promise<string> {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(key));
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
}
