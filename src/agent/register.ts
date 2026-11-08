import { AuthenticationError, ConfigurationError } from '../errors.js';
import { generateClientKeyPair, type ClientAuth, type ClientKeyAlgorithm, type ClientKeyPair } from './client-auth.js';
import { grantError, readOAuthFailure } from './errors.js';
import { requireEndpoint, resolveMetadata, send, type AgentServerOptions } from './http.js';

/** The CIBA grant type (OpenID CIBA Core). */
export const CIBA_GRANT_TYPE = 'urn:openid:params:grant-type:ciba';
/** The device authorization grant type (RFC 8628). */
export const DEVICE_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

export interface RegisterAgentClientOptions extends AgentServerOptions {
  /** Shown to the person approving, so make it recognisable: "Cbox Brain CLI on ada-mbp". */
  clientName: string;
  /** e.g. `[CIBA_GRANT_TYPE, 'refresh_token']` or `[DEVICE_CODE_GRANT_TYPE, 'refresh_token']`. */
  grantTypes: string[];
  /** The scope ceiling to register. A space-separated string or a list. */
  scope?: string | string[];
  /**
   * `private_key_jwt` (default): a key pair is generated (or `keyPair` used) and the
   * public half registered inline as `jwks`. `none`: a public client — the device grant,
   * or CIBA where the resource allows keyless clients. `private_key_jwt` is recommended for CIBA.
   */
  tokenEndpointAuthMethod?: 'private_key_jwt' | 'none';
  /** Algorithm for the generated key pair. Default ES256. */
  alg?: ClientKeyAlgorithm;
  /** Register an existing key pair instead of generating one. */
  keyPair?: ClientKeyPair;
  /** RFC 7591 §3 initial access token, when the instance requires one to register. */
  initialAccessToken?: string;
  /** Further RFC 7591 client metadata, sent as-is (e.g. `software_id`, `client_uri`). */
  extraMetadata?: Record<string, unknown>;
}

export interface RegisteredAgentClient {
  clientId: string;
  /** Present only if the server issued one; a `private_key_jwt` or `none` client has none. */
  clientSecret: string | null;
  /** RFC 7592 credential for reading/updating/deleting the registration. Persist it if you need that. */
  registrationAccessToken: string | null;
  registrationClientUri: string | null;
  tokenEndpointAuthMethod: string;
  grantTypes: string[];
  scope: string | null;
  /** The key pair registered, for `private_key_jwt`. Persist `keyPair.privateJwk`. */
  keyPair: ClientKeyPair | null;
  /** Ready to hand to {@link startBackchannel} / {@link startDeviceAuthorization}. */
  auth: ClientAuth;
  /** The full registration response. */
  raw: Record<string, unknown>;
}

/**
 * Register this agent or CLI as an OAuth client (RFC 7591 dynamic client registration).
 *
 * Do it once per installation and persist the result: `clientId` and, for
 * `private_key_jwt`, `keyPair.privateJwk`. Re-registering on every run fills the
 * environment's app list with copies.
 *
 * @throws ConfigurationError when the instance has dynamic registration switched off.
 * @throws AgentGrantError (e.g. `invalid_client_metadata`) when the server refuses.
 */
export async function registerAgentClient(options: RegisterAgentClientOptions): Promise<RegisteredAgentClient> {
  if (!options.clientName) {
    throw new ConfigurationError('`clientName` is required.');
  }
  if (options.grantTypes.length === 0) {
    throw new ConfigurationError('`grantTypes` must name at least one grant.');
  }

  const metadata = await resolveMetadata(options);
  const endpoint = requireEndpoint(metadata, 'registration_endpoint', 'dynamic client registration');
  const method = options.tokenEndpointAuthMethod ?? 'private_key_jwt';

  const keyPair = method === 'private_key_jwt'
    ? options.keyPair ?? (await generateClientKeyPair(options.alg ?? 'ES256'))
    : null;

  const document: Record<string, unknown> = {
    ...options.extraMetadata,
    client_name: options.clientName,
    grant_types: options.grantTypes,
    token_endpoint_auth_method: method,
    // Neither CIBA nor the device grant has a redirect; say so rather than let the server
    // assume an authorization-code client.
    redirect_uris: [],
    response_types: [],
  };

  if (options.scope !== undefined) {
    document['scope'] = scopeString(options.scope);
  }
  if (keyPair !== null) {
    document['jwks'] = { keys: [keyPair.publicJwk] };
  }

  const headers: Record<string, string> = { 'content-type': 'application/json', accept: 'application/json' };
  if (options.initialAccessToken) {
    headers['authorization'] = `Bearer ${options.initialAccessToken}`;
  }

  const response = await send(endpoint, { method: 'POST', headers, body: JSON.stringify(document) }, options);

  if (!response.ok) {
    throw grantError(await readOAuthFailure(response), 'Client registration failed');
  }

  const raw = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  const clientId = raw?.['client_id'];

  if (raw === null || typeof clientId !== 'string' || clientId === '') {
    throw new AuthenticationError('The registration response carried no client_id.');
  }

  const clientSecret = typeof raw['client_secret'] === 'string' ? raw['client_secret'] : null;
  const registeredMethod = typeof raw['token_endpoint_auth_method'] === 'string' ? raw['token_endpoint_auth_method'] : method;

  let auth: ClientAuth;
  if (keyPair !== null) {
    auth = { method: 'private_key_jwt', clientId, privateKey: keyPair.privateKey, alg: keyPair.alg, kid: keyPair.kid };
  } else if (clientSecret !== null) {
    auth = { method: 'client_secret_basic', clientId, clientSecret };
  } else {
    auth = { method: 'none', clientId };
  }

  return {
    clientId,
    clientSecret,
    registrationAccessToken: typeof raw['registration_access_token'] === 'string' ? raw['registration_access_token'] : null,
    registrationClientUri: typeof raw['registration_client_uri'] === 'string' ? raw['registration_client_uri'] : null,
    tokenEndpointAuthMethod: registeredMethod,
    grantTypes: Array.isArray(raw['grant_types']) ? raw['grant_types'].filter((g): g is string => typeof g === 'string') : options.grantTypes,
    scope: typeof raw['scope'] === 'string' ? raw['scope'] : null,
    keyPair,
    auth,
    raw,
  };
}

export function scopeString(scope: string | string[]): string {
  return (typeof scope === 'string' ? scope.split(/\s+/) : scope).filter((s) => s !== '').join(' ');
}
