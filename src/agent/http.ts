import { assertSecureIssuer } from '../issuer.js';
import { AuthenticationError, ConfigurationError } from '../errors.js';
import { GrantCancelledError } from './errors.js';

/**
 * RFC 8414 authorization server metadata, as Cbox ID publishes it at
 * `{issuer}/.well-known/oauth-authorization-server`. Only the members this module reads are
 * typed; the rest pass through.
 */
export interface AuthorizationServerMetadata {
  issuer: string;
  token_endpoint: string;
  registration_endpoint?: string;
  backchannel_authentication_endpoint?: string;
  device_authorization_endpoint?: string;
  backchannel_token_delivery_modes_supported?: string[];
  backchannel_user_code_parameter_supported?: boolean;
  grant_types_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  token_endpoint_auth_signing_alg_values_supported?: string[];
  [member: string]: unknown;
}

/** Transport options every call in this module takes. */
export interface AgentRequestOptions {
  /** A `fetch` to use instead of the global one (tests, proxies, instrumentation). */
  fetch?: typeof fetch;
  /** Per-request timeout in milliseconds. Default 10 000. */
  timeoutMs?: number;
  /** Abort the call (and, for the wait helpers, the whole wait). */
  signal?: AbortSignal;
}

/** Where to find the server: its issuer, and optionally metadata you already discovered. */
export interface AgentServerOptions extends AgentRequestOptions {
  /** The Cbox ID issuer, e.g. `https://acme.cboxid.com`. Must be https (loopback excepted). */
  issuer: string;
  /**
   * Metadata from {@link discoverAuthorizationServer}. Pass it to skip a discovery round
   * trip per call; omitted, each call discovers it (the wait helpers discover once).
   */
  metadata?: AuthorizationServerMetadata;
}

/**
 * Fetch and check the authorization server metadata (RFC 8414).
 *
 * The document's `issuer` must equal the one asked for (§3.3) — otherwise a host answering
 * with another tenant's metadata would receive this client's assertions and codes.
 */
export async function discoverAuthorizationServer(
  issuer: string,
  options: AgentRequestOptions = {},
): Promise<AuthorizationServerMetadata> {
  if (!issuer) {
    throw new ConfigurationError('An `issuer` is required.');
  }
  assertSecureIssuer(issuer);

  const url = `${trimSlash(issuer)}/.well-known/oauth-authorization-server`;
  const response = await send(url, { method: 'GET', headers: { accept: 'application/json' } }, options);

  if (!response.ok) {
    throw new AuthenticationError(`Discovery request failed with status ${response.status}.`, undefined, undefined, response.status);
  }

  let doc: unknown;
  try {
    doc = await response.json();
  } catch {
    throw new AuthenticationError('The authorization server metadata was not JSON.');
  }

  if (typeof doc !== 'object' || doc === null) {
    throw new AuthenticationError('The authorization server metadata was not an object.');
  }

  const metadata = doc as AuthorizationServerMetadata;

  if (typeof metadata.issuer !== 'string' || trimSlash(metadata.issuer) !== trimSlash(issuer)) {
    throw new AuthenticationError(`The authorization server metadata is for a different issuer (${String(metadata.issuer)}).`);
  }
  if (typeof metadata.token_endpoint !== 'string' || metadata.token_endpoint === '') {
    throw new AuthenticationError('The authorization server metadata has no token_endpoint.');
  }

  return metadata;
}

/** Metadata from the options, or discovered. */
export function resolveMetadata(options: AgentServerOptions): Promise<AuthorizationServerMetadata> {
  return options.metadata !== undefined
    ? Promise.resolve(options.metadata)
    : discoverAuthorizationServer(options.issuer, options);
}

/** A named endpoint, or a ConfigurationError saying the server does not offer it. */
export function requireEndpoint(
  metadata: AuthorizationServerMetadata,
  name: 'registration_endpoint' | 'backchannel_authentication_endpoint' | 'device_authorization_endpoint' | 'token_endpoint',
  what: string,
): string {
  const value = metadata[name];
  if (typeof value !== 'string' || value === '') {
    throw new ConfigurationError(`This Cbox ID instance does not advertise a ${name}, so it does not support ${what}.`);
  }
  return value;
}

/**
 * `fetch` with a timeout and the caller's signal combined. A caller abort becomes
 * {@link GrantCancelledError}; a timeout or network failure an {@link AuthenticationError}.
 */
export async function send(url: string, init: RequestInit, options: AgentRequestOptions): Promise<Response> {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
  const onAbort = (): void => controller.abort();

  if (options.signal?.aborted === true) {
    clearTimeout(timer);
    throw new GrantCancelledError('The request was cancelled.');
  }
  options.signal?.addEventListener('abort', onAbort, { once: true });

  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } catch (error) {
    // Re-read through a widened type: the early return above narrowed `aborted` to false,
    // but the signal may have fired while the request was in flight.
    if ((options.signal as AbortSignal | undefined)?.aborted === true) {
      throw new GrantCancelledError('The request was cancelled.');
    }
    if (controller.signal.aborted) {
      throw new AuthenticationError(`The request to ${new URL(url).origin} timed out.`);
    }
    throw new AuthenticationError(`The request to ${new URL(url).origin} failed: ${String(error)}`);
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', onAbort);
  }
}

export function trimSlash(value: string): string {
  return value.replace(/\/+$/, '');
}
