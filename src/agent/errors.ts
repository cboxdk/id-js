import { AuthenticationError, CboxIdError } from '../errors.js';

/**
 * A CIBA, device-grant or registration request was refused with an OAuth error.
 *
 * Extends {@link AuthenticationError}, so `error`, `errorDescription`, `status` and
 * `retryAfter` read the same as on every other back-channel failure in this SDK, and a
 * caller already catching `AuthenticationError` keeps working. Branch on the subclass (or
 * on `error`), never on the message.
 *
 * The REQUEST is never part of the error: these calls carry client assertions, secrets and
 * device codes, and production CLIs log what they throw.
 */
export class AgentGrantError extends AuthenticationError {}

/** The person declined (`access_denied`). Final — do not poll again. */
export class AccessDeniedError extends AgentGrantError {}

/**
 * The `auth_req_id` or `device_code` expired before anyone approved it (`expired_token`).
 * Also thrown locally when the wait outlives the request's `expires_in`. Start again.
 */
export class ExpiredTokenError extends AgentGrantError {}

/** The `auth_req_id`, `device_code` or refresh token is not valid (`invalid_grant`). */
export class InvalidGrantError extends AgentGrantError {}

/**
 * The `resource` (RFC 8707) is not one this client may ask for, the poll named a
 * different resource than the request that started it, or the resource lets
 * self-registered clients use CIBA only with `private_key_jwt` and this one is keyless
 * (`invalid_target`).
 */
export class InvalidTargetError extends AgentGrantError {}

/**
 * Client authentication failed (`invalid_client`): an unknown `client_id`, a bad secret, an
 * assertion signed by a key the server does not hold, or a replayed `jti`.
 */
export class InvalidClientError extends AgentGrantError {}

/** The `login_hint` names nobody the server can reach (`unknown_user_id`). */
export class UnknownUserIdError extends AgentGrantError {}

/**
 * The `binding_message` is missing where the server requires one (self-registered clients),
 * or too long to show beside Approve (`invalid_binding_message`).
 */
export class InvalidBindingMessageError extends AgentGrantError {}

/**
 * The server asked us to slow down (`slow_down`, or HTTP 429). `retryAfter` carries the
 * `Retry-After` seconds when the server sent them. The wait helpers absorb this themselves;
 * it is thrown only from a call that does not loop (registration, starting a flow).
 */
export class SlowDownError extends AgentGrantError {}

/** The caller aborted the wait (its `AbortSignal` fired). */
export class GrantCancelledError extends CboxIdError {}

const BY_CODE: Record<string, typeof AgentGrantError> = {
  access_denied: AccessDeniedError,
  expired_token: ExpiredTokenError,
  invalid_grant: InvalidGrantError,
  invalid_target: InvalidTargetError,
  invalid_client: InvalidClientError,
  unknown_user_id: UnknownUserIdError,
  invalid_binding_message: InvalidBindingMessageError,
  slow_down: SlowDownError,
};

/** A parsed `{ error, error_description }` body plus the bits of the response that matter. */
export interface OAuthFailure {
  error: string | undefined;
  errorDescription: string | undefined;
  status: number;
  retryAfter: number | undefined;
}

/**
 * Read an OAuth error body without ever echoing it. A 502 from a proxy is HTML, and an
 * error page that reflects the request would put a client assertion into a log line — so
 * only the server's own `error` code (or the status) reaches the message.
 */
export async function readOAuthFailure(response: Response): Promise<OAuthFailure> {
  const text = await response.text().catch(() => '');
  let error: string | undefined;
  let errorDescription: string | undefined;

  try {
    const parsed: unknown = JSON.parse(text);

    if (typeof parsed === 'object' && parsed !== null) {
      const record = parsed as Record<string, unknown>;
      error = typeof record['error'] === 'string' ? record['error'] : undefined;
      errorDescription = typeof record['error_description'] === 'string' ? record['error_description'] : undefined;
    }
  } catch {
    // Not JSON: the status alone is what there is to report.
  }

  // A 429 IS slow_down, whatever (or whether) the body says — the limiter in front of the
  // endpoint may answer before the OAuth layer does.
  if (response.status === 429 && error === undefined) {
    error = 'slow_down';
  }

  // Seconds only. The HTTP-date form is legal but guessing at clock skew is worse than
  // falling back to the +5s rule.
  const header = response.headers.get('retry-after');
  const retryAfter = header !== null && /^\d+$/.test(header.trim()) ? Number(header.trim()) : undefined;

  return { error, errorDescription, status: response.status, retryAfter };
}

/** The typed error for a failure: a subclass for the codes callers branch on, else the base. */
export function grantError(failure: OAuthFailure, fallback: string): AgentGrantError {
  const Klass = (failure.error !== undefined ? BY_CODE[failure.error] : undefined) ?? AgentGrantError;
  const detail = failure.error ?? `HTTP ${failure.status}`;

  return new Klass(`${fallback}: ${detail}`, failure.error, failure.errorDescription, failure.status, failure.retryAfter);
}
