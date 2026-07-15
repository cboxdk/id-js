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
