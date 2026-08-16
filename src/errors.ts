/**
 * Base class for every error this SDK throws, so callers can `catch (e) { if (e
 * instanceof CboxIdError) ... }` in one branch.
 */
export class CboxIdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The client is misconfigured (a required option is missing or empty). */
export class ConfigurationError extends CboxIdError {}

/**
 * The login `state` did not match what was stored — the callback is forged or
 * stale. Treat as a fresh start, not an error to surface to the user.
 */
export class InvalidStateError extends CboxIdError {}

/**
 * Login could not be completed: the provider returned an error, the callback was
 * missing a code, or a token / id_token failed verification.
 *
 * `error` carries the RFC 6749 §5.2 code the authorization server sent, when it sent one.
 * It used to be discarded at every back-channel boundary, leaving a single message string
 * for outcomes that need opposite responses: `invalid_grant` on a refresh means the
 * session is over and the person has to sign in again, while `temporarily_unavailable`
 * means try the same token in a moment. A caller reduced to matching on prose either
 * retries what can never succeed, or signs out somebody who did not need to be.
 */
export class AuthenticationError extends CboxIdError {
  constructor(
    message: string,
    /** RFC 6749 §5.2 error code, when the server sent a parseable one. */
    readonly error?: string,
    /** The server's `error_description`, verbatim. Not end-user copy. */
    readonly errorDescription?: string,
    /** HTTP status, for the cases where the body says nothing useful. */
    readonly status?: number,
    /**
     * Seconds to wait, off the `Retry-After` header — set only on a 429.
     *
     * The distinction it carries is the one a caller most needs and could least infer:
     * a 429 is the ONLY back-channel failure where the same request will succeed
     * unchanged if you simply wait. Every other one needs a different request, or a new
     * sign-in. Without this the SDK reported "token refresh failed" and a caller with a
     * retry loop hammered a limiter that was already telling it exactly how long to stop.
     */
    readonly retryAfter?: number,
  ) {
    super(message);
  }

  /** Whether waiting `retryAfter` seconds and repeating the same request is worth it. */
  get isRateLimited(): boolean {
    return this.status === 429;
  }
}

/**
 * Read an OAuth error out of a failed token-endpoint response.
 *
 * Best-effort by design: a 502 from a proxy is HTML, a captive portal is worse, and the
 * caller still needs an error rather than a parse exception. What it must never do is
 * invent a code — an absent or unparseable `error` stays undefined, so
 * `e.error === 'invalid_grant'` is true only because the server said so.
 */
export async function oauthError(response: Response, fallback: string): Promise<AuthenticationError> {
  const body = await response.text().catch(() => '');

  let code: string | undefined;
  let description: string | undefined;

  try {
    const parsed: unknown = JSON.parse(body);

    if (typeof parsed === 'object' && parsed !== null) {
      const { error, error_description: errorDescription } = parsed as Record<string, unknown>;
      code = typeof error === 'string' ? error : undefined;
      description = typeof errorDescription === 'string' ? errorDescription : undefined;
    }
  } catch {
    // Not JSON. The status and the truncated body below are all there is to report.
  }

  const detail = code ?? (body.trim() === '' ? `HTTP ${response.status}` : body.slice(0, 200));

  // `Retry-After` is seconds here — Laravel's throttler writes the integer form. The
  // HTTP-date form is legal too and is deliberately NOT parsed: guessing at a clock
  // skew is worse than saying nothing, and `status === 429` still tells the caller to
  // back off.
  const retryAfterHeader = response.headers.get('retry-after');
  const retryAfter = retryAfterHeader !== null && /^\d+$/.test(retryAfterHeader.trim())
    ? Number(retryAfterHeader.trim())
    : undefined;

  return new AuthenticationError(`${fallback}: ${detail}`, code, description, response.status, retryAfter);
}

/**
 * The Frontend API refused, or could not be reached.
 *
 * Carries a `code` because the four ways this goes wrong need four different responses
 * from the caller, and telling them apart from a message string is the kind of thing
 * that works until somebody rewords the message:
 *
 *  - `origin_not_allowed` — the overwhelmingly likely cause of a refusal, and a
 *    configuration problem the developer fixes once in the console.
 *  - `rate_limited` — back off; `retryAfter` says for how long, when the server said.
 *  - `unavailable` — the network, or a 5xx. Transient by assumption; already retried.
 *  - `malformed` — a 200 whose body is not the document we expect, which means something
 *    between the page and us is rewriting responses (a proxy, an extension, a captive
 *    portal). Worth distinguishing, because retrying it never helps.
 */
export class FrontendApiError extends CboxIdError {
  constructor(
    message: string,
    readonly code: 'origin_not_allowed' | 'rate_limited' | 'unavailable' | 'malformed',
    readonly status?: number,
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}
