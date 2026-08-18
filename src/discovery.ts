import { AuthenticationError, ConfigurationError } from './errors.js';
import type { DiscoveryDocument } from './types.js';

/**
 * Fetches and caches an instance's OIDC discovery document. One instance of this
 * lives per {@link CboxIdClient}; the document is refetched only after the TTL.
 */
export class Discovery {
  private cached: { doc: DiscoveryDocument; expiresAt: number } | null = null;

  constructor(
    private readonly issuer: string,
    private readonly timeoutMs: number,
    private readonly cacheTtlMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  async document(): Promise<DiscoveryDocument> {
    if (this.cached && this.cached.expiresAt > this.now()) {
      return this.cached.doc;
    }

    const url = `${trimSlash(this.issuer)}/.well-known/openid-configuration`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let doc: DiscoveryDocument;
    try {
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) {
        throw new AuthenticationError(`Discovery request failed with status ${response.status}.`);
      }
      doc = (await response.json()) as DiscoveryDocument;
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }
      throw new AuthenticationError(`Discovery request failed: ${String(error)}`);
    } finally {
      clearTimeout(timer);
    }

    if (typeof doc.issuer !== 'string' || doc.issuer === '') {
      throw new AuthenticationError('The discovery document was missing an issuer.');
    }

    // RFC 8414 §3.3: the `issuer` in the document MUST match the one it was fetched for.
    // Without this the SDK sends credentials to whatever endpoints the document names and
    // verifies tokens against whatever JWKS it points at, while the caller still believes
    // it is talking to the issuer it configured — so one tenant's host answering with
    // another tenant's document silently redirects the whole flow.
    if (trimSlash(doc.issuer) !== trimSlash(this.issuer)) {
      throw new AuthenticationError(
        `The discovery document is for a different issuer (${doc.issuer}).`,
      );
    }

    this.cached = { doc, expiresAt: this.now() + this.cacheTtlMs };
    return doc;
  }

  /** A required endpoint from the discovery document. */
  async endpoint(name: keyof DiscoveryDocument): Promise<string> {
    const value = (await this.document())[name];
    if (typeof value !== 'string' || value === '') {
      throw new ConfigurationError(`The instance does not advertise a ${name}.`);
    }
    return value;
  }

  /** An optional endpoint, or null when the instance advertises none. */
  async optionalEndpoint(name: keyof DiscoveryDocument): Promise<string | null> {
    const value = (await this.document())[name];
    return typeof value === 'string' && value !== '' ? value : null;
  }
}

/** Compare issuers without letting a trailing slash decide identity. */
function trimSlash(value: string): string {
  return value.replace(/\/+$/, '');
}
