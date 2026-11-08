import { AuthenticationError, ConfigurationError } from '../errors.js';
import { applyClientAuth, type ClientAuth } from './client-auth.js';
import { ExpiredTokenError, GrantCancelledError, grantError, readOAuthFailure } from './errors.js';
import {
  requireEndpoint,
  resolveMetadata,
  send,
  type AgentServerOptions,
  type AuthorizationServerMetadata,
} from './http.js';
import { CIBA_GRANT_TYPE, DEVICE_CODE_GRANT_TYPE, scopeString } from './register.js';

/** Tokens from a completed CIBA or device grant. */
export interface AgentTokens {
  accessToken: string;
  tokenType: string;
  /** Seconds, when the server said. */
  expiresIn: number | null;
  refreshToken: string | null;
  /**
   * The id_token, when `openid` was granted — returned as-is, NOT verified here. Verify it
   * with `CboxIdClient` (or `jose` against the JWKS) before trusting anything in it.
   */
  idToken: string | null;
  scope: string | null;
  /** The full token response. */
  raw: Record<string, unknown>;
}

/** One poll's outcome. Final failures are thrown, not returned. */
export type PollResult =
  | { status: 'complete'; tokens: AgentTokens }
  | { status: 'pending' }
  /** Slow down: add 5 s to the interval, and wait at least `retryAfter` seconds if given. */
  | { status: 'slow_down'; retryAfter: number | null };

/** Options shared by the wait helpers. */
export interface WaitOptions {
  /** Replace the timer — tests pass a fake that records the waits. Must honour `signal`. */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  /** Clock in epoch milliseconds. Default `Date.now`. */
  now?: () => number;
}

interface ClientOptions extends AgentServerOptions {
  /** How the client authenticates. See {@link ClientAuth}. */
  client: ClientAuth;
}

// ---------------------------------------------------------------------------------------
// CIBA (poll mode)
// ---------------------------------------------------------------------------------------

export interface StartBackchannelOptions extends ClientOptions {
  /** Who should approve: a Cbox ID user id, or a confirmed email address. */
  loginHint: string;
  /** Space-separated string or list. Bounded by the client's registered scopes. */
  scope: string | string[];
  /**
   * Shown beside Approve. Put a {@link createBindingCode} code in it and print the same
   * code locally. Required by Cbox ID for self-registered clients; at most 255 characters.
   */
  bindingMessage: string;
  /**
   * RFC 8707 resource indicator(s) — the API the token is for. Optional in the type, but
   * REQUIRED by Cbox ID for self-registered clients.
   * Its settings also decide whether a keyless (`none`) client may use CIBA at all.
   */
  resource?: string | string[];
  /** Seconds the request may wait for approval (the server may shorten it). */
  requestedExpiry?: number;
  /** Echoed into the id_token, so you can bind it to this request. */
  nonce?: string;
}

/** A started CIBA request. Persistable as JSON. */
export interface BackchannelAuthorization {
  authReqId: string;
  expiresIn: number;
  /** Seconds between polls. */
  interval: number;
  /** Epoch ms after which polling is pointless. */
  expiresAt: number;
  /** The resource(s) the request named, re-sent on every poll (the server checks they match). */
  resource: string[];
}

/**
 * Start a CIBA request (OpenID CIBA Core §7, poll mode): Cbox ID shows `bindingMessage` to
 * the person named by `loginHint` and waits for Approve.
 *
 * `backchannel_user_code_parameter` is not supported by Cbox ID, so no user code is sent.
 *
 * @throws InvalidClientError, UnknownUserIdError, InvalidBindingMessageError,
 *   InvalidTargetError, SlowDownError, AgentGrantError.
 */
export async function startBackchannel(options: StartBackchannelOptions): Promise<BackchannelAuthorization> {
  const now = Date.now();
  const metadata = await resolveMetadata(options);
  const endpoint = requireEndpoint(metadata, 'backchannel_authentication_endpoint', 'CIBA');

  if (!options.loginHint) {
    throw new ConfigurationError('`loginHint` is required.');
  }

  const resource = resourceList(options.resource);
  const body = new URLSearchParams({ login_hint: options.loginHint, scope: scopeString(options.scope) });

  if (options.bindingMessage !== '') {
    body.set('binding_message', options.bindingMessage);
  }
  for (const r of resource) {
    body.append('resource', r);
  }
  if (options.requestedExpiry !== undefined) {
    body.set('requested_expiry', String(options.requestedExpiry));
  }
  if (options.nonce !== undefined && options.nonce !== '') {
    body.set('nonce', options.nonce);
  }

  const payload = await postForm(endpoint, body, options, metadata, 'Backchannel authentication request failed');
  const authReqId = payload['auth_req_id'];

  if (typeof authReqId !== 'string' || authReqId === '') {
    throw new AuthenticationError('The backchannel authentication response carried no auth_req_id.');
  }

  const expiresIn = positiveNumber(payload['expires_in']) ?? 120;

  return {
    authReqId,
    expiresIn,
    // CIBA Core §7.3: absent means 5 seconds.
    interval: positiveNumber(payload['interval']) ?? 5,
    expiresAt: now + expiresIn * 1000,
    resource,
  };
}

export interface PollBackchannelOptions extends ClientOptions {
  authorization: Pick<BackchannelAuthorization, 'authReqId' | 'resource'>;
}

/**
 * Poll the token endpoint once for a CIBA request.
 *
 * @throws AccessDeniedError, ExpiredTokenError, InvalidGrantError, InvalidTargetError,
 *   InvalidClientError, AgentGrantError.
 */
export async function pollBackchannel(options: PollBackchannelOptions): Promise<PollResult> {
  const body = new URLSearchParams({ grant_type: CIBA_GRANT_TYPE, auth_req_id: options.authorization.authReqId });
  return pollToken(body, options.authorization.resource, options, 'Backchannel token request failed');
}

/**
 * Poll until the person approves, and return the tokens.
 *
 * Waits `interval` seconds before each poll; on `slow_down` (or a 429) adds five seconds
 * for good and waits at least `Retry-After`; keeps going on `authorization_pending`; stops
 * on anything final. Throws {@link ExpiredTokenError} once `expiresAt` passes and
 * {@link GrantCancelledError} when `signal` fires — wire it to Ctrl-C.
 */
export async function waitForBackchannelToken(
  options: PollBackchannelOptions & WaitOptions & { authorization: BackchannelAuthorization },
): Promise<AgentTokens> {
  const metadata = await resolveMetadata(options);
  const authorization = options.authorization;

  return waitLoop(authorization, options, () => pollBackchannel({ ...options, metadata }), 'backchannel request');
}

// ---------------------------------------------------------------------------------------
// Device authorization grant (RFC 8628)
// ---------------------------------------------------------------------------------------

export interface StartDeviceAuthorizationOptions extends ClientOptions {
  scope?: string | string[];
  /** RFC 8707 resource indicator(s). */
  resource?: string | string[];
}

/** A started device authorization. Persistable as JSON. */
export interface DeviceGrantAuthorization {
  deviceCode: string;
  /** Show this to the person. */
  userCode: string;
  /** Where they enter it. */
  verificationUri: string;
  /** The same page with the code filled in — good for a QR code or `open`. */
  verificationUriComplete: string | null;
  expiresIn: number;
  interval: number;
  expiresAt: number;
  resource: string[];
}

/**
 * Start the device authorization grant: you get a `userCode` to show and a
 * `verificationUri` for the person to open on any device.
 *
 * @throws InvalidClientError, InvalidTargetError, SlowDownError, AgentGrantError.
 */
export async function startDeviceAuthorization(options: StartDeviceAuthorizationOptions): Promise<DeviceGrantAuthorization> {
  const now = Date.now();
  const metadata = await resolveMetadata(options);
  const endpoint = requireEndpoint(metadata, 'device_authorization_endpoint', 'the device grant');
  const resource = resourceList(options.resource);
  const body = new URLSearchParams();

  if (options.scope !== undefined) {
    body.set('scope', scopeString(options.scope));
  }
  for (const r of resource) {
    body.append('resource', r);
  }

  const payload = await postForm(endpoint, body, options, metadata, 'Device authorization request failed');
  const deviceCode = payload['device_code'];
  const userCode = payload['user_code'];
  const verificationUri = payload['verification_uri'];

  if (typeof deviceCode !== 'string' || typeof userCode !== 'string' || typeof verificationUri !== 'string') {
    throw new AuthenticationError('The device authorization response was incomplete.');
  }

  const expiresIn = positiveNumber(payload['expires_in']) ?? 600;

  return {
    deviceCode,
    userCode,
    verificationUri,
    verificationUriComplete: typeof payload['verification_uri_complete'] === 'string' ? payload['verification_uri_complete'] : null,
    expiresIn,
    // RFC 8628 §3.2: absent means 5 seconds.
    interval: positiveNumber(payload['interval']) ?? 5,
    expiresAt: now + expiresIn * 1000,
    resource,
  };
}

export interface PollDeviceAuthorizationOptions extends ClientOptions {
  authorization: Pick<DeviceGrantAuthorization, 'deviceCode' | 'resource'>;
}

/** Poll the token endpoint once for a device authorization. */
export async function pollDeviceAuthorization(options: PollDeviceAuthorizationOptions): Promise<PollResult> {
  const body = new URLSearchParams({ grant_type: DEVICE_CODE_GRANT_TYPE, device_code: options.authorization.deviceCode });
  return pollToken(body, options.authorization.resource, options, 'Device token request failed');
}

/** Poll until the person approves the device code. Same rules as {@link waitForBackchannelToken}. */
export async function waitForDeviceToken(
  options: PollDeviceAuthorizationOptions & WaitOptions & { authorization: DeviceGrantAuthorization },
): Promise<AgentTokens> {
  const metadata = await resolveMetadata(options);

  return waitLoop(options.authorization, options, () => pollDeviceAuthorization({ ...options, metadata }), 'device code');
}

// ---------------------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------------------

export interface RefreshAgentTokensOptions extends ClientOptions {
  refreshToken: string;
  /** Narrow the scope (never widen it). */
  scope?: string | string[];
  /** RFC 8707 resource indicator(s) for the new access token. */
  resource?: string | string[];
}

/**
 * Exchange a refresh token, authenticating the same way the grant did (including
 * `private_key_jwt`). Cbox ID rotates refresh tokens and revokes the family on reuse, so
 * ALWAYS persist the returned `refreshToken` and discard the old one.
 *
 * @throws InvalidGrantError when the refresh token is no longer valid — sign in again.
 */
export async function refreshAgentTokens(options: RefreshAgentTokensOptions): Promise<AgentTokens> {
  if (!options.refreshToken) {
    throw new ConfigurationError('`refreshToken` is required.');
  }

  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: options.refreshToken });
  if (options.scope !== undefined) {
    body.set('scope', scopeString(options.scope));
  }

  // `polling: false`: pending and slow_down mean nothing on a refresh, so they are thrown
  // like any other refusal (a 429 as SlowDownError with its Retry-After).
  const result = await pollToken(body, resourceList(options.resource), options, 'Token refresh failed', false);

  return (result as Extract<PollResult, { status: 'complete' }>).tokens;
}

// ---------------------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------------------

async function waitLoop(
  authorization: { interval: number; expiresAt: number },
  options: WaitOptions & { signal?: AbortSignal },
  poll: () => Promise<PollResult>,
  what: string,
): Promise<AgentTokens> {
  const sleep = options.sleep ?? defaultSleep;
  const now = options.now ?? Date.now;
  let intervalMs = Math.max(authorization.interval, 0) * 1000;
  let nextWaitMs = intervalMs;

  for (;;) {
    throwIfAborted(options.signal);

    if (now() >= authorization.expiresAt) {
      throw new ExpiredTokenError(`The ${what} expired before it was approved. Start again.`, 'expired_token');
    }

    await sleep(nextWaitMs, options.signal);
    // A custom sleep may not honour the signal; check again before spending a request.
    throwIfAborted(options.signal);

    if (now() >= authorization.expiresAt) {
      throw new ExpiredTokenError(`The ${what} expired before it was approved. Start again.`, 'expired_token');
    }

    const result = await poll();

    if (result.status === 'complete') {
      return result.tokens;
    }

    if (result.status === 'slow_down') {
      // Permanently, not for one round (RFC 8628 §3.5, CIBA Core §11): returning to the
      // refused rate earns the same answer forever.
      intervalMs += 5000;
      nextWaitMs = Math.max(intervalMs, (result.retryAfter ?? 0) * 1000);
      continue;
    }

    nextWaitMs = intervalMs;
  }
}

async function pollToken(
  body: URLSearchParams,
  resource: readonly string[],
  options: ClientOptions,
  fallback: string,
  polling = true,
): Promise<PollResult> {
  const metadata = await resolveMetadata(options);
  const endpoint = requireEndpoint(metadata, 'token_endpoint', 'token requests');

  // The same resource(s) the request started with; Cbox ID refuses a mismatch with
  // invalid_target.
  for (const r of resource) {
    body.append('resource', r);
  }

  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  await applyClientAuth(options.client, body, headers, metadata.token_endpoint);

  const response = await send(endpoint, { method: 'POST', headers, body }, options);

  if (response.ok) {
    return { status: 'complete', tokens: await tokensFrom(response) };
  }

  const failure = await readOAuthFailure(response);

  if (polling && failure.error === 'authorization_pending') {
    return { status: 'pending' };
  }
  if (polling && failure.error === 'slow_down') {
    return { status: 'slow_down', retryAfter: failure.retryAfter ?? null };
  }

  throw grantError(failure, fallback);
}

async function postForm(
  endpoint: string,
  body: URLSearchParams,
  options: ClientOptions,
  metadata: AuthorizationServerMetadata,
  fallback: string,
): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  await applyClientAuth(options.client, body, headers, metadata.token_endpoint);

  const response = await send(endpoint, { method: 'POST', headers, body }, options);

  if (!response.ok) {
    throw grantError(await readOAuthFailure(response), fallback);
  }

  const payload: unknown = await response.json().catch(() => null);
  if (typeof payload !== 'object' || payload === null) {
    throw new AuthenticationError(`${fallback}: the response was not a JSON object.`);
  }
  return payload as Record<string, unknown>;
}

async function tokensFrom(response: Response): Promise<AgentTokens> {
  const raw = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  const accessToken = raw?.['access_token'];

  if (raw === null || typeof accessToken !== 'string' || accessToken === '') {
    throw new AuthenticationError('The token response carried no access_token.');
  }

  return {
    accessToken,
    tokenType: typeof raw['token_type'] === 'string' ? raw['token_type'] : 'Bearer',
    expiresIn: typeof raw['expires_in'] === 'number' ? raw['expires_in'] : null,
    refreshToken: typeof raw['refresh_token'] === 'string' ? raw['refresh_token'] : null,
    idToken: typeof raw['id_token'] === 'string' ? raw['id_token'] : null,
    scope: typeof raw['scope'] === 'string' ? raw['scope'] : null,
    raw,
  };
}

function resourceList(resource: string | string[] | undefined): string[] {
  if (resource === undefined) {
    return [];
  }
  const list = typeof resource === 'string' ? [resource] : [...resource];
  for (const r of list) {
    // RFC 8707 §2: an absolute URI without a fragment.
    let url: URL;
    try {
      url = new URL(r);
    } catch {
      throw new ConfigurationError(`\`resource\` must be an absolute URI (got ${r}).`);
    }
    if (url.hash !== '') {
      throw new ConfigurationError('`resource` must not contain a fragment.');
    }
  }
  return list;
}

function positiveNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new GrantCancelledError('The wait for approval was cancelled.');
  }
}

/** An interruptible timer: the abort is wired to the timer, so Ctrl-C does not wait out an interval. */
function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(new GrantCancelledError('The wait for approval was cancelled.'));
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new GrantCancelledError('The wait for approval was cancelled.'));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
