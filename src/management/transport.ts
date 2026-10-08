import { CboxIdError, ConfigurationError } from '../errors.js';
import type { DPoPSigner } from './dpop.js';
import {
  ApprovalDeniedError,
  ApprovalError,
  ApprovalExpiredError,
  CboxIdApiError,
  ManagementNetworkError,
} from './errors.js';
import type {
  ApiResponse,
  ApprovalContext,
  CallOptions,
  CursorPageMeta,
  NumberedPageMeta,
  OperationSpec,
  Outcome,
  PendingApproval,
  PendingApprovalResult,
} from './types.js';

/** The four management planes, each with its own OpenAPI document. */
export type Plane = 'environment' | 'workspace' | 'platform' | 'account';

/** Retry behaviour for network failures, `5xx`, `429` and `409 idempotency_in_progress`. */
export interface RetryOptions {
  /** Retries after the first attempt. Default `3`; `0` turns retrying off. */
  maxRetries?: number;
  /** First backoff delay (ms), doubled per attempt with jitter. Default `500`. */
  baseDelayMs?: number;
  /**
   * The longest the client will wait before one retry (ms). Default `30000`. A `Retry-After`
   * longer than this is not waited out: the `429`/`503` is thrown, with `retryAfter` set.
   */
  maxDelayMs?: number;
}

/** Options every management client takes. Exactly one of `apiKey` and `accessToken`. */
export interface ManagementClientOptions {
  /**
   * Where the plane is served: an environment's own host (`https://acme.cboxid.com`) for the
   * environment and account planes, the platform-root host for the workspace and platform
   * planes. `/api/v1` is appended unless it is already there.
   */
  baseUrl?: string;
  /** A management key: `cbid_env_…` (environment plane) or `cbid_ws_…` (workspace plane). */
  apiKey?: string;
  /**
   * A delegated OAuth access token, or a function returning one (called before every request,
   * so it can refresh). Platform and account planes accept nothing else.
   */
  accessToken?: string | (() => string | Promise<string>);
  /**
   * Environment plane only, with a person's access token on the PLATFORM ROOT's host: the
   * environment to act in, by id or slug, sent as `Cbox-Environment` on every request. One
   * root token and the root `baseUrl` can then drive any environment of the person's
   * workspace. Not used with a key, which is bound to its own environment's host.
   */
  environment?: string;
  /** Present `accessToken` as a DPoP-bound token, with a proof per request. */
  dpop?: DPoPSigner;
  /**
   * Called when a write is held for a person's approval, before the client starts polling —
   * show `approval.binding_code` so they can match it on their device. Defaults to nothing.
   */
  onApprovalRequired?: (approval: PendingApproval, context: ApprovalContext) => void | Promise<void>;
  /** How often to poll an approval (ms) when the server sends no `Retry-After`. Default `2000`. */
  approvalPollIntervalMs?: number;
  retry?: RetryOptions;
  /** Per-attempt timeout (ms). Default `30000`. */
  timeoutMs?: number;
  /** A `fetch` implementation. Defaults to the global one. */
  fetch?: typeof fetch;
  /** Headers sent on every request (e.g. a `User-Agent` on Node). Cannot override `Authorization`. */
  headers?: Record<string, string>;
}

const KEY_PREFIX: Record<Plane, string | null> = {
  environment: 'cbid_env_',
  workspace: 'cbid_ws_',
  platform: null,
  account: null,
};

/** Where each plane serves `GET …/action-approvals/{id}`, relative to `/api/v1`. */
const APPROVAL_MOUNT: Record<Plane, string> = {
  environment: '',
  workspace: '/workspace',
  platform: '/platform',
  account: '/me',
};

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** How many approvals one call will go through before giving up (a policy loop guard). */
const MAX_APPROVAL_ROUNDS = 3;

interface SendOptions {
  idempotencyKey?: string | undefined;
  approvalId?: string | undefined;
  signal?: AbortSignal | undefined;
  headers?: Record<string, string> | undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function uuid(): string {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** `Retry-After` in milliseconds: delta-seconds or an HTTP date. Undefined when absent or unparseable. */
export function retryAfterMs(headers: Headers): number | undefined {
  const raw = headers.get('retry-after')?.trim();

  if (raw === undefined || raw === '') {
    return undefined;
  }

  if (/^\d+$/.test(raw)) {
    return Number(raw) * 1000;
  }

  const date = Date.parse(raw);

  return Number.isNaN(date) ? undefined : Math.max(0, date - Date.now());
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (ms <= 0) {
    return signal?.aborted ? Promise.reject(signal.reason) : Promise.resolve();
  }

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

function normalizeBaseUrl(raw: string): string {
  let url: URL;

  try {
    url = new URL(raw);
  } catch {
    throw new ConfigurationError('Management client `baseUrl` is not a valid URL.');
  }

  const loopback = ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname);

  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    // Every request carries a management credential. Over http a network attacker reads it.
    throw new ConfigurationError(`Management client \`baseUrl\` must be https (got ${url.protocol}//${url.hostname}).`);
  }

  const path = url.pathname.replace(/\/+$/, '');

  return `${url.origin}${path.endsWith('/api/v1') ? path : `${path}/api/v1`}`;
}

function appendQuery(params: URLSearchParams, key: string, value: unknown): void {
  if (value === undefined || value === null) {
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      appendQuery(params, `${key}[]`, item);
    }
    return;
  }

  if (typeof value === 'boolean') {
    // Laravel's `boolean` rule takes 1/0, not the strings "true"/"false".
    params.append(key, value ? '1' : '0');
    return;
  }

  params.append(key, typeof value === 'object' ? JSON.stringify(value) : String(value));
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();

  if (text === '') {
    return undefined;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * The hand-written core every generated client runs on: authentication, idempotency keys,
 * retries, the approval loop, error typing and pagination. Generated code only describes
 * operations; it never talks to the network itself.
 */
export class ManagementTransport {
  readonly plane: Plane;
  readonly baseUrl: string;
  readonly #options: ManagementClientOptions;
  readonly #fetch: typeof fetch;
  readonly #maxRetries: number;
  readonly #baseDelayMs: number;
  readonly #maxDelayMs: number;
  #dpopNonce: string | undefined;

  constructor(plane: Plane, options: ManagementClientOptions, defaultBaseUrl?: string) {
    const baseUrl = options.baseUrl ?? defaultBaseUrl;

    if (baseUrl === undefined || baseUrl === '') {
      throw new ConfigurationError(`The ${plane} management client needs a \`baseUrl\` (the environment's own host).`);
    }

    const hasKey = options.apiKey !== undefined;
    const hasToken = options.accessToken !== undefined;

    if (hasKey === hasToken) {
      throw new ConfigurationError('Pass exactly one of `apiKey` and `accessToken` to a management client.');
    }

    if (hasKey) {
      const key = options.apiKey ?? '';
      const expected = KEY_PREFIX[plane];

      if (key === '') {
        throw new ConfigurationError('Management client `apiKey` is empty.');
      }

      if (expected === null) {
        throw new ConfigurationError(
          `The ${plane} plane accepts no management key — only an access token a person delegated (\`accessToken\`).`,
        );
      }

      const wrong = Object.values(KEY_PREFIX).find((prefix) => prefix !== null && prefix !== expected && key.startsWith(prefix));

      if (wrong !== undefined) {
        // Credentials never cross planes: the server would answer 401 to every request.
        throw new ConfigurationError(`A \`${wrong}…\` key cannot call the ${plane} plane; it takes \`${expected}…\` keys.`);
      }

      if (options.dpop !== undefined) {
        throw new ConfigurationError('`dpop` applies to an `accessToken`, not a management key.');
      }
    }

    if (options.environment !== undefined) {
      if (plane !== 'environment') {
        throw new ConfigurationError(`\`environment\` applies to the environment plane, not the ${plane} plane.`);
      }

      if (options.environment === '') {
        throw new ConfigurationError('Management client `environment` is empty.');
      }

      if (hasKey) {
        throw new ConfigurationError(
          '`environment` names the environment for a root access token. A `cbid_env_…` key is bound to its own environment\'s host: use that host as `baseUrl` instead.',
        );
      }
    }

    this.plane = plane;
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.#options = options;
    this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
    this.#maxRetries = Math.max(0, options.retry?.maxRetries ?? 3);
    this.#baseDelayMs = Math.max(0, options.retry?.baseDelayMs ?? 500);
    this.#maxDelayMs = Math.max(0, options.retry?.maxDelayMs ?? 30_000);
  }

  /** Run one operation. Generated methods call this; so can you, with an operation spec. */
  async call<TBody, O extends CallOptions = CallOptions>(
    op: OperationSpec,
    pathArgs: readonly string[],
    input?: unknown,
    options?: O,
  ): Promise<Outcome<TBody, O>> {
    const url = this.#url(op, pathArgs, op.body ? undefined : input);
    const payload = op.body ? input : undefined;
    const idempotencyKey = WRITE_METHODS.has(op.method) ? options?.idempotencyKey ?? uuid() : undefined;
    const send: SendOptions = {
      idempotencyKey,
      approvalId: options?.approvalId,
      signal: options?.signal,
      headers: options?.headers,
    };
    const context: ApprovalContext = { action: op.action, danger: op.danger, method: op.method, path: op.path };

    const response = await this.#send(op.method, url, payload, send);
    const held = await this.#heldApproval(response);

    if (held !== null && options?.approval === 'return') {
      const result: PendingApprovalResult<TBody> = {
        pending: true,
        status: 202,
        approval: held.approval,
        idempotencyKey,
        action: op.action,
        resume: (resumeOptions) =>
          this.#approveAndRepeat<TBody>(op.method, url, payload, { ...send, signal: resumeOptions?.signal ?? send.signal }, held, context, false),
      };

      return result as Outcome<TBody, O>;
    }

    if (held !== null) {
      return (await this.#approveAndRepeat<TBody>(op.method, url, payload, send, held, context, true)) as Outcome<TBody, O>;
    }

    return (await this.#result<TBody>(response, idempotencyKey)) as Outcome<TBody, O>;
  }

  /**
   * Every item of a paged list, fetching pages as the iteration reaches them. Works for both
   * cursor (`after` / `meta.next_cursor`) and numbered (`page` / `meta.next_page`) lists.
   */
  async *paginate<TItem>(
    op: OperationSpec,
    pathArgs: readonly string[],
    input?: Record<string, unknown>,
    options?: Omit<CallOptions, 'approval'>,
  ): AsyncGenerator<TItem, void, undefined> {
    let query: Record<string, unknown> = { ...(input ?? {}) };

    for (;;) {
      const page = await this.call<{ data?: TItem[]; meta?: CursorPageMeta & NumberedPageMeta }>(op, pathArgs, query, {
        ...options,
        approval: 'wait',
      });
      const items = Array.isArray(page.data) ? page.data : [];

      yield* items;

      const meta = page.meta;

      if (items.length === 0 || meta?.has_more !== true) {
        return;
      }

      if (op.pagination === 'page') {
        const current = typeof query.page === 'number' ? query.page : Number(query.page ?? 1);
        query = { ...query, page: meta.next_page ?? current + 1 };
      } else {
        if (typeof meta.next_cursor !== 'string' || meta.next_cursor === '') {
          return;
        }
        query = { ...query, after: meta.next_cursor };
      }
    }
  }

  /**
   * An escape hatch for a route the generated surface does not cover. `path` is relative to
   * `/api/v1`. Writes get an `Idempotency-Key` and the approval loop like any operation.
   */
  request<TBody = unknown, O extends CallOptions = CallOptions>(
    method: OperationSpec['method'],
    path: string,
    input?: { query?: Record<string, unknown>; body?: unknown },
    options?: O,
  ): Promise<Outcome<TBody, O>> {
    const op: OperationSpec = {
      action: null,
      operationId: null,
      method,
      path,
      pathParams: [],
      scope: null,
      danger: null,
      approval: true,
      body: input?.body !== undefined,
      pagination: null,
    };

    return this.call<TBody, O>(op, [], input?.body ?? input?.query, options);
  }

  #url(op: OperationSpec, pathArgs: readonly string[], query: unknown): string {
    let index = 0;
    const path = op.path.replace(/\{([^}]+)\}/g, (_, name: string) => {
      const value = pathArgs[index++];

      if (value === undefined || value === '') {
        throw new TypeError(`${op.action ?? op.path}: missing path parameter \`${name}\`.`);
      }

      return encodeURIComponent(value);
    });

    const url = new URL(`${this.baseUrl}${path}`);

    if (isRecord(query)) {
      for (const [key, value] of Object.entries(query)) {
        appendQuery(url.searchParams, key, value);
      }
    }

    return url.toString();
  }

  async #headers(method: string, url: string, send: SendOptions, hasBody: boolean): Promise<Headers> {
    const headers = new Headers({ ...this.#options.headers, ...send.headers });
    headers.set('accept', 'application/json');

    if (hasBody) {
      headers.set('content-type', 'application/json');
    }

    if (send.idempotencyKey !== undefined) {
      headers.set('idempotency-key', send.idempotencyKey);
    }

    if (send.approvalId !== undefined) {
      headers.set('cbox-approval', send.approvalId);
    }

    if (this.#options.environment !== undefined) {
      headers.set('cbox-environment', this.#options.environment);
    }

    if (this.#options.apiKey !== undefined) {
      headers.set('authorization', `Bearer ${this.#options.apiKey}`);
      return headers;
    }

    const source = this.#options.accessToken;
    const token = typeof source === 'function' ? await source() : source;

    if (typeof token !== 'string' || token === '') {
      throw new ConfigurationError('The management client `accessToken` provider returned no token.');
    }

    const dpop = this.#options.dpop;

    if (dpop === undefined) {
      headers.set('authorization', `Bearer ${token}`);
      return headers;
    }

    headers.set('authorization', `DPoP ${token}`);
    headers.set(
      'dpop',
      await dpop.proof({
        method,
        url,
        accessToken: token,
        ...(this.#dpopNonce !== undefined ? { nonce: this.#dpopNonce } : {}),
      }),
    );

    return headers;
  }

  /** One HTTP exchange, plus the single DPoP-nonce challenge retry RFC 9449 §8 describes. */
  async #exchange(method: string, url: string, payload: unknown, send: SendOptions): Promise<Response> {
    for (let nonceRetry = 0; ; nonceRetry++) {
      const headers = await this.#headers(method, url, send, payload !== undefined);
      const timeout = AbortSignal.timeout(this.#options.timeoutMs ?? 30_000);
      const signal = send.signal ? AbortSignal.any([send.signal, timeout]) : timeout;
      const init: RequestInit = { method, headers, signal };

      if (payload !== undefined) {
        init.body = JSON.stringify(payload);
      }

      const response = await this.#fetch(url, init);
      const nonce = response.headers.get('dpop-nonce');

      if (nonce !== null && this.#options.dpop !== undefined) {
        const challenged = response.status === 401 && nonce !== this.#dpopNonce && nonceRetry === 0;
        this.#dpopNonce = nonce;

        if (challenged) {
          await response.body?.cancel();
          continue;
        }
      }

      return response;
    }
  }

  async #shouldRetry(response: Response): Promise<boolean> {
    if (response.status >= 500 || response.status === 429) {
      return true;
    }

    if (response.status === 409) {
      // The first request with this Idempotency-Key is still running: its answer is coming.
      const body = await readJson(response.clone());
      return isRecord(body) && body.error === 'idempotency_in_progress';
    }

    return false;
  }

  #backoff(attempt: number): number {
    const exponential = this.#baseDelayMs * 2 ** attempt;
    return Math.min(this.#maxDelayMs, exponential / 2 + Math.random() * (exponential / 2));
  }

  /** Send with retries. Every attempt carries the SAME Idempotency-Key, so a write lands once. */
  async #send(method: string, url: string, payload: unknown, send: SendOptions): Promise<Response> {
    for (let attempt = 0; ; attempt++) {
      let response: Response;

      try {
        response = await this.#exchange(method, url, payload, send);
      } catch (error) {
        if (send.signal?.aborted) {
          throw send.signal.reason ?? error;
        }

        if (error instanceof CboxIdError || attempt >= this.#maxRetries) {
          if (error instanceof CboxIdError) {
            throw error;
          }

          throw new ManagementNetworkError(
            `${method} ${new URL(url).pathname} failed: ${error instanceof Error ? error.message : String(error)}`,
            send.idempotencyKey,
            { cause: error },
          );
        }

        await sleep(this.#backoff(attempt), send.signal);
        continue;
      }

      if (attempt >= this.#maxRetries || !(await this.#shouldRetry(response))) {
        return response;
      }

      const delay = retryAfterMs(response.headers) ?? this.#backoff(attempt);

      if (delay > this.#maxDelayMs) {
        return response;
      }

      await response.body?.cancel();
      await sleep(delay, send.signal);
    }
  }

  async #heldApproval(response: Response): Promise<{ approval: PendingApproval; retryAfter: number | undefined } | null> {
    if (response.status !== 202) {
      return null;
    }

    const body = await readJson(response.clone());

    if (!isRecord(body) || body.error !== 'approval_required' || !isRecord(body.approval)) {
      return null;
    }

    const approval = body.approval;

    if (typeof approval.id !== 'string' || approval.id === '') {
      return null;
    }

    return {
      approval: {
        id: approval.id,
        status: typeof approval.status === 'string' ? approval.status : 'pending',
        binding_code: typeof approval.binding_code === 'string' ? approval.binding_code : '',
        expires_at: typeof approval.expires_at === 'string' ? approval.expires_at : '',
        poll_url:
          typeof approval.poll_url === 'string'
            ? approval.poll_url
            : `${this.baseUrl}${APPROVAL_MOUNT[this.plane]}/action-approvals/${encodeURIComponent(approval.id)}`,
      },
      retryAfter: retryAfterMs(response.headers),
    };
  }

  async #approveAndRepeat<TBody>(
    method: string,
    url: string,
    payload: unknown,
    send: SendOptions,
    first: { approval: PendingApproval; retryAfter: number | undefined },
    context: ApprovalContext,
    notify: boolean,
  ): Promise<ApiResponse<TBody>> {
    let held = first;

    for (let round = 1; ; round++) {
      if (notify || round > 1) {
        await this.#options.onApprovalRequired?.(held.approval, context);
      }

      await this.#awaitApproval(held.approval, held.retryAfter, send.signal);

      const response = await this.#send(method, url, payload, { ...send, approvalId: held.approval.id });
      const again = await this.#heldApproval(response);

      if (again === null) {
        return this.#result<TBody>(response, send.idempotencyKey);
      }

      if (round >= MAX_APPROVAL_ROUNDS) {
        throw new ApprovalError(
          `The request was held for approval ${round} times; giving up.`,
          'consumed',
          again.approval,
        );
      }

      held = again;
    }
  }

  /** Poll an approval until the person decides. Resolves on `approved`; throws otherwise. */
  async #awaitApproval(approval: PendingApproval, initialDelay: number | undefined, signal: AbortSignal | undefined): Promise<void> {
    const pollUrl = new URL(approval.poll_url, this.baseUrl);

    if (pollUrl.origin !== new URL(this.baseUrl).origin) {
      // The poll carries the same credential as the request. Never hand it to another host.
      throw new CboxIdError(`Refusing to poll approval ${approval.id} at another origin (${pollUrl.origin}).`);
    }

    const fallback = Math.max(0, this.#options.approvalPollIntervalMs ?? 2_000);
    const expiresAt = Date.parse(approval.expires_at);
    let delay = initialDelay ?? fallback;

    for (;;) {
      await sleep(Math.min(delay, 60_000), signal);

      const response = await this.#send('GET', pollUrl.toString(), undefined, { signal });

      if (!response.ok) {
        throw await this.#error(response);
      }

      const body = await readJson(response);
      const data = isRecord(body) && isRecord(body.data) ? body.data : {};
      const status = typeof data.status === 'string' ? data.status : 'pending';

      switch (status) {
        case 'approved':
          return;
        case 'denied':
          throw new ApprovalDeniedError(approval);
        case 'expired':
          throw new ApprovalExpiredError(approval);
        case 'consumed':
          throw new ApprovalError(`Approval ${approval.id} was already used by another request.`, 'consumed', approval);
        default:
          break;
      }

      if (!Number.isNaN(expiresAt) && Date.now() > expiresAt + 30_000) {
        throw new ApprovalExpiredError(approval);
      }

      delay = retryAfterMs(response.headers) ?? fallback;
    }
  }

  async #result<TBody>(response: Response, idempotencyKey: string | undefined): Promise<ApiResponse<TBody>> {
    if (!response.ok) {
      throw await this.#error(response);
    }

    const body = response.status === 204 ? undefined : await readJson(response);
    const envelope = isRecord(body) && 'data' in body;

    return {
      pending: false,
      status: response.status,
      data: (envelope ? body.data : body) as ApiResponse<TBody>['data'],
      meta: (envelope ? body.meta : undefined) as ApiResponse<TBody>['meta'],
      body: body as TBody,
      replayed: response.headers.get('idempotent-replayed')?.toLowerCase() === 'true',
      idempotencyKey,
      requestId: response.headers.get('x-request-id'),
      headers: response.headers,
    };
  }

  async #error(response: Response): Promise<CboxIdApiError> {
    const body = await readJson(response);
    const fields = isRecord(body) ? body : {};
    const code = typeof fields.error === 'string' ? fields.error : `http_${response.status}`;
    // A bearer challenge (RFC 6750) says `error_description`, the management envelope `message`.
    const message =
      typeof fields.message === 'string'
        ? fields.message
        : typeof fields.error_description === 'string'
          ? fields.error_description
          : `HTTP ${response.status}`;
    const errors: Record<string, string[]> = {};

    if (isRecord(fields.errors)) {
      for (const [field, messages] of Object.entries(fields.errors)) {
        errors[field] = Array.isArray(messages) ? messages.map(String) : [String(messages)];
      }
    }

    const retryAfter = retryAfterMs(response.headers);

    // The envelope's `request_id` first: a proxy in between may rewrite or drop the header.
    const requestId = typeof fields.request_id === 'string' && fields.request_id !== '' ? fields.request_id : response.headers.get('x-request-id');

    return new CboxIdApiError({
      status: response.status,
      error: code,
      message,
      errors,
      requestId,
      retryAfter: retryAfter === undefined ? undefined : Math.ceil(retryAfter / 1000),
    });
  }
}
