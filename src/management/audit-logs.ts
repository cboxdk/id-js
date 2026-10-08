/**
 * Ergonomics for the environment plane's Audit Logs product, on top of the generated
 * `env.auditLogs.*` methods: a buffered sender, an export that waits until it is ready, and
 * a client-side check of an organization's hash chain.
 */
import { CboxIdError } from '../errors.js';
import type {
  AuditLogEvent,
  AuditLogExport,
  AuditLogsEventsCreateBody,
  AuditLogsExportsCreateBody,
  EnvironmentClient,
} from './generated/environment.js';
import type { CallOptions } from './types.js';

/** One event as `audit_logs.events.create` takes it. */
export type AuditLogEventInput = AuditLogsEventsCreateBody['events'][number];

/** An event for {@link AuditLogger.record}: `occurred_at` defaults to now. */
export type AuditLogRecord = Omit<AuditLogEventInput, 'occurred_at'> & { occurred_at?: string };

/** The most events one `POST /audit-logs/events` takes. */
export const MAX_AUDIT_BATCH = 100;

/** The `prev_hash` of an organization's first event: 64 zeros. */
export const AUDIT_CHAIN_GENESIS = '0'.repeat(64);

function uuid(): string {
  return crypto.randomUUID();
}

// ── Buffered sender ─────────────────────────────────────────────────────────────────────

export interface AuditLoggerOptions {
  /** Events per request, 1–100. Default 100. */
  batchSize?: number;
  /** Send whatever is buffered this often (ms). Default 5000; `0` sends only on size and `flush()`. */
  flushIntervalMs?: number;
  /**
   * Called when a background flush (the interval, or a full batch from `record()`) fails.
   * The batch stays at the head of the queue with its Idempotency-Key, so the next flush
   * sends it again without recording it twice. Default: nothing — call `flush()` to see errors.
   */
  onError?: (error: unknown, batch: readonly AuditLogEventInput[]) => void;
}

interface Batch {
  events: AuditLogEventInput[];
  /** Fixed when the batch is cut, so every resend of it is the same request to the server. */
  idempotencyKey: string;
}

/**
 * Buffers audit events and sends them in batches of up to 100, each batch under its own
 * `Idempotency-Key`: on a full batch, on an interval, and on `flush()` / `close()`.
 *
 * Batches go out one at a time and in order, because the server appends each to its
 * organization's hash chain in the order received. A batch that fails stays queued with
 * the SAME key, so sending it again can never record an event twice.
 */
export class AuditLogger {
  readonly #client: EnvironmentClient;
  readonly #batchSize: number;
  readonly #onError: AuditLoggerOptions['onError'];
  #buffer: AuditLogEventInput[] = [];
  readonly #queue: Batch[] = [];
  #sending: Promise<void> = Promise.resolve();
  #timer: ReturnType<typeof setInterval> | undefined;
  #closed = false;

  constructor(client: EnvironmentClient, options: AuditLoggerOptions = {}) {
    const batchSize = options.batchSize ?? MAX_AUDIT_BATCH;

    if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > MAX_AUDIT_BATCH) {
      throw new RangeError(`batchSize must be 1–${MAX_AUDIT_BATCH}.`);
    }

    this.#client = client;
    this.#batchSize = batchSize;
    this.#onError = options.onError;

    const interval = options.flushIntervalMs ?? 5_000;

    if (interval > 0) {
      this.#timer = setInterval(() => this.#background(), interval);
      // Never keep a Node process alive just to flush an empty buffer.
      (this.#timer as { unref?: () => void }).unref?.();
    }
  }

  /** Events buffered or queued, not yet acknowledged by the server. */
  get pending(): number {
    return this.#buffer.length + this.#queue.reduce((n, batch) => n + batch.events.length, 0);
  }

  /** Buffer one event. A full batch is sent in the background. */
  record(event: AuditLogRecord): void {
    if (this.#closed) {
      throw new CboxIdError('This AuditLogger is closed.');
    }

    this.#buffer.push({ ...event, occurred_at: event.occurred_at ?? new Date().toISOString() });

    if (this.#buffer.length >= this.#batchSize) {
      this.#background();
    }
  }

  /** Send everything buffered, and resolve once the server has it. Throws if a batch fails. */
  flush(): Promise<void> {
    this.#cut();
    const run = this.#sending.catch(() => undefined).then(() => this.#drain());
    this.#sending = run;
    return run;
  }

  /** Stop the interval and flush. */
  async close(): Promise<void> {
    this.#closed = true;

    if (this.#timer !== undefined) {
      clearInterval(this.#timer);
      this.#timer = undefined;
    }

    await this.flush();
  }

  #background(): void {
    this.flush().catch((error: unknown) => {
      this.#onError?.(error, this.#queue[0]?.events ?? []);
    });
  }

  /** Move the buffer into batches, each with the key every resend of it will carry. */
  #cut(): void {
    while (this.#buffer.length > 0) {
      this.#queue.push({ events: this.#buffer.splice(0, this.#batchSize), idempotencyKey: uuid() });
    }
  }

  async #drain(): Promise<void> {
    while (this.#queue.length > 0) {
      const batch = this.#queue[0]!;
      await this.#client.auditLogs.events.create({ events: batch.events }, { idempotencyKey: batch.idempotencyKey });
      this.#queue.shift();
    }
  }
}

// ── Exports ─────────────────────────────────────────────────────────────────────────────

export interface AuditLogExportOptions {
  /** How often to read the export while it is `pending` (ms). Default 2000. */
  pollIntervalMs?: number;
  /** Give up after this long (ms). Default 10 minutes. */
  timeoutMs?: number;
  signal?: AbortSignal;
  /** The create call's Idempotency-Key, to resume an export you started before. */
  idempotencyKey?: string;
}

/** An export ended `failed` or `expired`, or was not ready in time. */
export class AuditLogExportError extends CboxIdError {
  constructor(
    message: string,
    readonly auditExport: AuditLogExport | undefined,
  ) {
    super(message);
  }
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }

    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Start a CSV export (`audit_logs.exports.create`) and read it (`audit_logs.exports.get`)
 * until it is `ready`. The result's `url` is signed and short-lived: download it straight
 * away, or call `exports.get` again for a fresh one.
 */
export async function exportAuditLogs(
  client: EnvironmentClient,
  filters: AuditLogsExportsCreateBody = {},
  options: AuditLogExportOptions = {},
): Promise<AuditLogExport> {
  const call: CallOptions = {
    ...(options.signal !== undefined ? { signal: options.signal } : {}),
  };
  const created = await client.auditLogs.exports.create(filters, {
    ...call,
    ...(options.idempotencyKey !== undefined ? { idempotencyKey: options.idempotencyKey } : {}),
  });
  const deadline = Date.now() + (options.timeoutMs ?? 600_000);
  const interval = Math.max(0, options.pollIntervalMs ?? 2_000);
  let current = created.data;

  for (;;) {
    switch (current.state) {
      case 'ready':
        return current;
      case 'failed':
      case 'expired':
        throw new AuditLogExportError(`Audit log export ${current.id} is ${current.state}.`, current);
      default:
        break;
    }

    if (Date.now() >= deadline) {
      throw new AuditLogExportError(`Audit log export ${current.id} was not ready in time.`, current);
    }

    await sleep(interval, options.signal);
    current = (await client.auditLogs.exports.get(current.id, call)).data;
  }
}

// ── Chain verification ──────────────────────────────────────────────────────────────────

const encoder = new TextEncoder();

function compareBytes(a: string, b: string): number {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  const n = Math.min(x.length, y.length);

  for (let i = 0; i < n; i++) {
    if (x[i] !== y[i]) return x[i]! - y[i]!;
  }

  return x.length - y.length;
}

/** A float the way PHP's `json_encode` writes it (serialize_precision -1). */
function phpFloat(value: number): string {
  if (!Number.isFinite(value)) {
    throw new TypeError('Canonical JSON cannot encode NaN or Infinity.');
  }

  if (Object.is(value, -0)) return '-0';
  if (Number.isSafeInteger(value)) return String(value);

  const sign = value < 0 ? '-' : '';
  // The shortest round-trip digits — the same digits PHP's mode-0 conversion picks.
  const [mantissa, exp] = Math.abs(value).toExponential().split('e') as [string, string];
  const digits = mantissa.replace('.', '');
  const exponent = Number(exp);
  const decpt = exponent + 1;

  if (decpt < -3 || decpt > 17) {
    return `${sign}${digits[0]}.${digits.slice(1) || '0'}e${exponent < 0 ? '-' : '+'}${Math.abs(exponent)}`;
  }

  if (decpt <= 0) return `${sign}0.${'0'.repeat(-decpt)}${digits}`;
  if (decpt >= digits.length) return `${sign}${digits}${'0'.repeat(decpt - digits.length)}`;

  return `${sign}${digits.slice(0, decpt)}.${digits.slice(decpt)}`;
}

/**
 * Canonical JSON exactly as Cbox ID hashes it (`Cbox\AuditChain\Codec\CanonicalJson`):
 * object keys sorted byte-wise at every depth, lists in order, slashes and Unicode written
 * as-is — plus the two places PHP's arrays show through, so the bytes match:
 *
 * - an object whose sorted keys are `"0"…"n-1"` is a PHP list, and is written as an array;
 * - an empty object is an empty PHP array, written `[]`.
 *
 * And, like PHP, U+2028 and U+2029 are escaped. Floats are written in PHP's form; keep them
 * out of anything you hash if you can (a sender's `1.0` and `1` arrive as the same number).
 */
export function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return phpFloat(value);
  if (typeof value === 'string') return JSON.stringify(value).replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => compareBytes(a, b));

    if (entries.length === 0) return '[]';

    if (entries.every(([key], index) => key === String(index))) {
      return `[${entries.map(([, v]) => canonicalJson(v)).join(',')}]`;
    }

    return `{${entries.map(([k, v]) => `${canonicalJson(k)}:${canonicalJson(v)}`).join(',')}}`;
  }

  throw new TypeError(`Canonical JSON cannot encode a ${typeof value}.`);
}

/** The fields of an audit event its hash covers. */
export type AuditEventHashInput = Pick<
  AuditLogEvent,
  'id' | 'organization_id' | 'sequence' | 'action' | 'occurred_at' | 'actor' | 'targets' | 'context' | 'metadata'
>;

/** Metadata as it is hashed: the value, or null for none — never an empty `[]`/`{}`. */
function metadataOf(value: unknown): unknown {
  if (Array.isArray(value)) return value.length > 0 ? value : null;
  if (typeof value === 'object' && value !== null) return Object.keys(value).length > 0 ? value : null;
  return null;
}

/** The document an event's hash covers, in the server's shape (`AuditLogEventResource::document`). */
export function auditEventDocument(event: AuditEventHashInput): Record<string, unknown> {
  const actor = (event.actor ?? {}) as Partial<AuditLogEvent['actor']>;
  const context = (event.context ?? {}) as Partial<AuditLogEvent['context']>;

  return {
    id: event.id,
    organization_id: event.organization_id,
    sequence: event.sequence,
    action: event.action,
    occurred_at: event.occurred_at,
    actor: { id: actor.id ?? null, type: actor.type ?? null, name: actor.name ?? null, metadata: metadataOf(actor.metadata) },
    targets: (event.targets ?? []).map((target) => ({
      id: target.id ?? null,
      type: target.type ?? null,
      name: target.name ?? null,
      metadata: metadataOf(target.metadata),
    })),
    context: { location: context.location ?? null, user_agent: context.user_agent ?? null },
    metadata: metadataOf(event.metadata),
  };
}

/** `sha256(previousHash ‖ canonicalJson(document))`, lowercase hex. */
export async function auditEventHash(previousHash: string, event: AuditEventHashInput): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(previousHash + canonicalJson(auditEventDocument(event))));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** What {@link verifyAuditChain} found — the server's `AuditLogVerification`, minus its view of the head. */
export interface AuditChainVerification {
  valid: boolean;
  verified_count: number;
  first_sequence: number | null;
  last_sequence: number | null;
  broken_at_sequence: number | null;
  /** `missing` (a sequence gap), `link` (`prev_hash` does not name the event before), `hash` (the event changed). */
  reason: 'missing' | 'link' | 'hash' | null;
}

export interface VerifyAuditChainOptions {
  /**
   * The hash the first event must chain from. Default: 64 zeros when the first event is
   * sequence 1; otherwise the first event's own `prev_hash`, taken on trust — pass the hash
   * you kept for the event before it to check that link too.
   */
  previousHash?: string;
}

/**
 * Check one organization's events the way `GET /audit-logs/verify` does: in sequence order,
 * every sequence present, every `prev_hash` naming the event before, every `hash` matching
 * the event. Takes events as the API returns them, in any order (they are sorted by
 * `sequence`). Unlike the server's check it cannot see the chain's head, so it cannot tell
 * whether events were removed from the end.
 */
export async function verifyAuditChain(
  events: Iterable<AuditLogEvent> | AsyncIterable<AuditLogEvent>,
  options: VerifyAuditChainOptions = {},
): Promise<AuditChainVerification> {
  const all: AuditLogEvent[] = [];

  for await (const event of events) {
    all.push(event);
  }

  all.sort((a, b) => a.sequence - b.sequence);

  const first = all[0];
  let previous = options.previousHash ?? (first === undefined || first.sequence === 1 ? AUDIT_CHAIN_GENESIS : first.prev_hash);
  let expected = first?.sequence ?? 1;
  let verified = 0;

  const result = (reason: AuditChainVerification['reason']): AuditChainVerification => ({
    valid: reason === null,
    verified_count: verified,
    first_sequence: verified === 0 ? null : first!.sequence,
    last_sequence: verified === 0 ? null : expected - 1,
    broken_at_sequence: reason === null ? null : expected,
    reason,
  });

  for (const event of all) {
    if (event.sequence !== expected) return result('missing');
    if (event.prev_hash !== previous) return result('link');
    if ((await auditEventHash(previous, event)) !== event.hash) return result('hash');

    previous = event.hash;
    expected++;
    verified++;
  }

  return result(null);
}

/**
 * Read every event of one organization (`audit_logs.events.list`) and verify its chain on
 * this side, independently of the server's own check (`env.auditLogs.verify()`). The events
 * are held in memory to be put in sequence order — the list is ordered by `occurred_at`,
 * which the sender chose, not by `sequence` — so this suits a chain of thousands, not
 * millions. For a long chain, use the server's check, which pages by sequence.
 */
export async function verifyAuditLogChain(
  client: EnvironmentClient,
  query: { organization_id: string; limit?: number },
  options: VerifyAuditChainOptions = {},
): Promise<AuditChainVerification> {
  return verifyAuditChain(client.auditLogs.events.listAll({ ...query, order: 'asc' }), options);
}
