import { AuthenticationError } from './errors.js';

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

  private async json<T>(method: string, path: string, body: Record<string, unknown>): Promise<T> {
    const response = await this.request(method, path, body);
    return (await response.json()) as T;
  }

  private async request(method: string, path: string, body?: Record<string, unknown>): Promise<Response> {
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
      const response = await fetch(`${this.base}${path}`, init);
      if (!response.ok) {
        throw new AuthenticationError(`Vault ${method} ${path} failed with status ${response.status}.`);
      }
      return response;
    } finally {
      clearTimeout(timer);
    }
  }
}
