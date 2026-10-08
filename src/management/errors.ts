import { CboxIdError } from '../errors.js';
import type { PendingApproval } from './types.js';

/**
 * The management API answered with an error.
 *
 * Every plane answers a failure with the same envelope — `{ error, message }`, plus a
 * field-keyed `errors` map on `validation_failed` — so one class covers them all. Branch on
 * `error` (the stable machine code), never on `message` (prose, reworded freely).
 *
 * The REQUEST body is never part of the error: management writes carry secrets (a password
 * you set, a key's scopes, a webhook secret) and production apps log thrown errors.
 */
export class CboxIdApiError extends CboxIdError {
  /** HTTP status. */
  readonly status: number;
  /** The stable machine code, e.g. `validation_failed`, `slug_taken`, `not_found`. */
  readonly error: string;
  /**
   * On `validation_failed` only: the offending request fields, each mapped to its messages
   * (`{ name: ['The name field is required.'] }`). Empty otherwise.
   */
  readonly errors: Readonly<Record<string, readonly string[]>>;
  /** The id the server served the request under (`request_id`, else `X-Request-Id`). Quote it when reporting a problem. */
  readonly requestId: string | null;
  /** Seconds to wait, off `Retry-After` — set on a `429` the client gave up retrying. */
  readonly retryAfter: number | undefined;

  constructor(init: {
    status: number;
    error: string;
    message: string;
    errors?: Record<string, readonly string[]>;
    requestId?: string | null;
    retryAfter?: number | undefined;
  }) {
    super(init.message);
    this.status = init.status;
    this.error = init.error;
    this.errors = init.errors ?? {};
    this.requestId = init.requestId ?? null;
    this.retryAfter = init.retryAfter;
  }

  /** Whether this is a `422 validation_failed` with field errors. */
  get isValidationError(): boolean {
    return this.error === 'validation_failed';
  }
}

/**
 * The request never got an answer: DNS, TLS, a reset connection, a timeout — after every
 * retry the client was allowed. A write may or may not have happened; repeating it with the
 * same `idempotencyKey` (`error.idempotencyKey`) is safe and tells you which.
 */
export class ManagementNetworkError extends CboxIdError {
  constructor(
    message: string,
    /** The `Idempotency-Key` the write was sent with, to repeat it safely. */
    readonly idempotencyKey: string | undefined,
    options?: { cause?: unknown },
  ) {
    super(message);
    if (options && 'cause' in options) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

/**
 * An action held for a person's approval did not get it. `reason` says how: `denied` (they
 * said no), `expired` (nobody answered in time), or `consumed` (the approval was already
 * spent by another request).
 */
export class ApprovalError extends CboxIdError {
  constructor(
    message: string,
    readonly reason: 'denied' | 'expired' | 'consumed',
    readonly approval: PendingApproval,
  ) {
    super(message);
  }
}

/** The person declined the action on their device. Do not retry it unprompted. */
export class ApprovalDeniedError extends ApprovalError {
  constructor(approval: PendingApproval) {
    super(`Approval ${approval.id} was denied.`, 'denied', approval);
  }
}

/** Nobody approved the action before the approval expired. Ask again with a new request. */
export class ApprovalExpiredError extends ApprovalError {
  constructor(approval: PendingApproval) {
    super(`Approval ${approval.id} expired before it was approved.`, 'expired', approval);
  }
}
