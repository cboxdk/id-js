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
 */
export class AuthenticationError extends CboxIdError {}

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
