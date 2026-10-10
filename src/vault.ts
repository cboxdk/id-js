import { AuthenticationError, CboxIdError } from './errors.js';

/** A stored vault secret's metadata (never its plaintext). */
export interface VaultSecretRef {
  id: string;
  name: string;
  provider: string;
  ownerType: string | null;
  ownerId: string | null;
  expiresAt: string | null;
  revoked: boolean;
}

/** A brokered credential — the plaintext, for immediate use. */
export interface VaultLease {
  secretId: string;
  provider: string;
  secret: string;
  expiresAt: string;
}

/** A provider a pipe can connect to. */
export type PipeProvider = 'github' | 'google' | 'microsoft' | 'slack' | 'salesforce' | 'hubspot' | 'linear' | 'notion';

/**
 * A fresh access token for one person's connected account at a provider — what
 * {@link VaultClient.leasePipeToken} returns. Use it, drop it, lease again next time.
 */
export interface PipeToken {
  /** The provider's access token. Send it as a bearer token to the provider's API. */
  accessToken: string;
  tokenType: 'Bearer';
  provider: string;
  userId: string;
  connectionId: string;
  /** What the person consented to. */
  scopes: string[];
  /** When the PROVIDER stops accepting it; null for tokens that do not expire. */
  expiresAt: string | null;
  /** When to drop it and lease again. */
  leaseExpiresAt: string;
  /** What some providers need to be called at all — Salesforce's `instance_url`, Slack's `team.id`. */
  metadata: Record<string, string>;
}

/** Where a person connects a provider, and where they come back to afterwards. */
export interface PipeConnectOptions {
  /** Your app's client id — the connect page shows its name and allows its origins. */
  clientId?: string;
  /**
   * Where to land afterwards, with `?provider=…&status=connected|cancelled|failed`. Must be
   * on one of the app's registered redirect origins, or it is ignored.
   */
  returnTo?: string;
}

/**
 * Add `client_id` and `return_to` to a connect URL — the one a lease error carries, or
 * one built with {@link pipeConnectUrl}.
 */
export function withConnectReturn(connectUrl: string, options: PipeConnectOptions = {}): string {
  const url = new URL(connectUrl);
  if (options.clientId) url.searchParams.set('client_id', options.clientId);
  if (options.returnTo) url.searchParams.set('return_to', options.returnTo);
  return url.toString();
}

/**
 * The hosted page where the signed-in person connects their account at `provider`:
 * `{issuer}/account/connected-services/{provider}/connect?client_id=…&return_to=…`.
 */
export function pipeConnectUrl(issuer: string, provider: PipeProvider | string, options: PipeConnectOptions = {}): string {
  return withConnectReturn(
    `${issuer.replace(/\/$/, '')}/account/connected-services/${encodeURIComponent(provider)}/connect`,
    options,
  );
}

/**
 * A pipe token lease was refused. Catch the subclasses for the cases you can act on:
 *
 *  - {@link PipeNotConnectedError} (404) and {@link PipeReauthorizationRequiredError}
 *    (409) — send the person to `connectUrl`.
 *  - {@link PipeTemporarilyUnavailableError} (503) — retry after `retryAfter` seconds.
 *  - {@link PipeLeaseDeniedError} (403) — a configuration problem: the app is not granted
 *    the pipe, it is disabled, or the person is outside the app's organization.
 *
 * Anything else (401, 422, 429) arrives as this base class with `status` and `error`.
 */
export class PipeLeaseError extends CboxIdError {
  constructor(
    message: string,
    /** The server's error code, e.g. `not_connected`. */
    readonly error: string | null,
    readonly status: number,
    /** Where to send the person to (re)connect — set on 404 and 409. */
    readonly connectUrl: string | null = null,
    /** Seconds to wait off `Retry-After`, when the server sent one. */
    readonly retryAfter: number | null = null,
  ) {
    super(message);
  }

  /** `connectUrl` with your `client_id` and `return_to` on it, or null when there is none. */
  connectUrlWith(options: PipeConnectOptions): string | null {
    return this.connectUrl === null ? null : withConnectReturn(this.connectUrl, options);
  }
}

/** The person has not connected this provider (404 `not_connected`). Send them to `connectUrl`. */
export class PipeNotConnectedError extends PipeLeaseError {
  declare readonly connectUrl: string;
}

/**
 * The provider stopped accepting the connection — revoked, or the refresh token expired
 * (409 `reauthorization_required`). Send the person to `connectUrl` to connect again.
 */
export class PipeReauthorizationRequiredError extends PipeLeaseError {
  declare readonly connectUrl: string;
}

/** The provider could not refresh the token just now (503). Retry after `retryAfter`. */
export class PipeTemporarilyUnavailableError extends PipeLeaseError {}

/**
 * The lease was denied (403 `lease_denied`): the app is not granted the pipe, the pipe is
 * disabled or missing, the person is not in the app's organization, or `userId` names
 * someone other than the token's person. One answer for every reason, by design.
 */
export class PipeLeaseDeniedError extends PipeLeaseError {}

export interface StoreSecretInput {
  name: string;
  provider: string;
  secret: string;
  ownerType?: 'organization' | 'user';
  ownerId?: string;
  expiresAt?: string;
}

/**
 * Client for a Cbox ID instance's Token Vault API. Bind it to an access token
 * (obtain one with {@link CboxIdClient.machineToken}, scoped `vault.manage` for
 * provisioning or `vault.lease` for redeeming). All calls are server-to-server.
 */
export class VaultClient {
  private readonly base: string;

  constructor(
    issuer: string,
    private readonly token: string,
    private readonly timeoutMs = 10_000,
  ) {
    this.base = `${issuer.replace(/\/$/, '')}/api/v1/vault`;
  }

  /** Ingest a downstream credential, sealed at rest (scope `vault.manage`). */
  store(input: StoreSecretInput): Promise<VaultSecretRef> {
    return this.json<VaultSecretRef>('POST', '/secrets', {
      name: input.name,
      provider: input.provider,
      secret: input.secret,
      owner_type: input.ownerType,
      owner_id: input.ownerId,
      expires_at: input.expiresAt,
    });
  }

  /** Rotate a secret's value, keeping its id and grants (scope `vault.manage`). */
  rotate(secretId: string, secret: string): Promise<VaultSecretRef> {
    return this.json<VaultSecretRef>('POST', `/secrets/${encodeURIComponent(secretId)}/rotate`, { secret });
  }

  /** Revoke a secret permanently (scope `vault.manage`). */
  async revoke(secretId: string): Promise<void> {
    await this.request('DELETE', `/secrets/${encodeURIComponent(secretId)}`);
  }

  /** Authorize an agent client to lease a secret (scope `vault.manage`). */
  grant(
    secretId: string,
    clientId: string,
    maxTtlSeconds?: number,
  ): Promise<{ secretId: string; clientId: string; maxTtlSeconds: number | null }> {
    return this.json('POST', `/secrets/${encodeURIComponent(secretId)}/grants`, {
      client_id: clientId,
      max_ttl_seconds: maxTtlSeconds,
    }).then((raw) => {
      const r = raw as { secret_id: string; client_id: string; max_ttl_seconds: number | null };
      return { secretId: r.secret_id, clientId: r.client_id, maxTtlSeconds: r.max_ttl_seconds };
    });
  }

  /** Revoke an agent's authorization (scope `vault.manage`). */
  async revokeGrant(secretId: string, clientId: string): Promise<void> {
    await this.request(
      'DELETE',
      `/secrets/${encodeURIComponent(secretId)}/grants/${encodeURIComponent(clientId)}`,
    );
  }

  /**
   * Redeem a leased credential for immediate use (scope `vault.lease`). The caller
   * is identified by the token's client; a lease with no live grant is refused.
   */
  lease(secretId: string, purpose: string): Promise<VaultLease> {
    return this.json('POST', `/secrets/${encodeURIComponent(secretId)}/lease`, { purpose }).then((raw) => {
      const r = raw as { secret_id: string; provider: string; secret: string; expires_at: string };
      return { secretId: r.secret_id, provider: r.provider, secret: r.secret, expiresAt: r.expires_at };
    });
  }

  /**
   * Lease a fresh access token for a person's connected account at `provider` (Pipes,
   * scope `vault.lease`). The token is refreshed first when it is about to expire, so
   * you never handle a refresh token.
   *
   * With a client-credentials token, name the person in `userId`. With a token issued to
   * your app FOR a person, leave it out — the lease is theirs.
   *
   * ```ts
   * try {
   *   const { accessToken } = await vault.leasePipeToken('github', { userId, purpose: 'list-repos' })
   * } catch (e) {
   *   if (e instanceof PipeNotConnectedError || e instanceof PipeReauthorizationRequiredError) {
   *     return redirect(e.connectUrlWith({ clientId, returnTo }))
   *   }
   *   throw e
   * }
   * ```
   */
  async leasePipeToken(
    provider: PipeProvider | string,
    options: { purpose: string; userId?: string },
  ): Promise<PipeToken> {
    const path = `/pipes/${encodeURIComponent(provider)}/token`;
    const response = await this.send('POST', path, {
      purpose: options.purpose,
      ...(options.userId !== undefined ? { user_id: options.userId } : {}),
    });

    let body: Record<string, unknown> = {};
    try {
      const parsed: unknown = await response.json();
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
        body = parsed as Record<string, unknown>;
      }
    } catch {
      // Not JSON — a proxy's error page. The status below is all there is.
    }

    if (!response.ok) {
      throw pipeLeaseError(response, body);
    }

    if (typeof body.access_token !== 'string') {
      throw new PipeLeaseError('The pipe lease answered without an access token.', null, response.status);
    }

    return {
      accessToken: body.access_token,
      tokenType: 'Bearer',
      provider: String(body.provider ?? provider),
      userId: String(body.user_id ?? ''),
      connectionId: String(body.connection_id ?? ''),
      scopes: Array.isArray(body.scopes) ? body.scopes.filter((s): s is string => typeof s === 'string') : [],
      expiresAt: typeof body.expires_at === 'string' ? body.expires_at : null,
      leaseExpiresAt: String(body.lease_expires_at ?? ''),
      metadata: isStringRecord(body.metadata) ? body.metadata : {},
    };
  }

  private async json<T>(method: string, path: string, body: Record<string, unknown>): Promise<T> {
    const response = await this.request(method, path, body);
    return (await response.json()) as T;
  }

  private async request(method: string, path: string, body?: Record<string, unknown>): Promise<Response> {
    const response = await this.send(method, path, body);
    if (!response.ok) {
      throw new AuthenticationError(`Vault ${method} ${path} failed with status ${response.status}.`);
    }
    return response;
  }

  private async send(method: string, path: string, body?: Record<string, unknown>): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const init: RequestInit = {
        method,
        headers: {
          authorization: `Bearer ${this.token}`,
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        signal: controller.signal,
      };
      if (body) {
        init.body = JSON.stringify(body);
      }
      return await fetch(`${this.base}${path}`, init);
    } finally {
      clearTimeout(timer);
    }
  }
}

function pipeLeaseError(response: Response, body: Record<string, unknown>): PipeLeaseError {
  const error = typeof body.error === 'string' ? body.error : null;
  const message = typeof body.message === 'string' && body.message !== ''
    ? body.message
    : `The pipe lease failed with status ${response.status}.`;
  const connectUrl = typeof body.connect_url === 'string' && body.connect_url !== '' ? body.connect_url : null;
  const header = response.headers.get('retry-after')?.trim() ?? '';
  const retryAfter = /^\d+$/.test(header) ? Number(header) : null;

  if (response.status === 404 && connectUrl !== null) {
    return new PipeNotConnectedError(message, error, 404, connectUrl, retryAfter);
  }
  if (response.status === 409 && connectUrl !== null) {
    return new PipeReauthorizationRequiredError(message, error, 409, connectUrl, retryAfter);
  }
  if (response.status === 503) {
    return new PipeTemporarilyUnavailableError(message, error, 503, connectUrl, retryAfter);
  }
  if (response.status === 403 && error !== 'insufficient_scope') {
    return new PipeLeaseDeniedError(message, error, 403, connectUrl, retryAfter);
  }

  return new PipeLeaseError(message, error, response.status, connectUrl, retryAfter);
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.values(value).every((v) => typeof v === 'string')
  );
}
