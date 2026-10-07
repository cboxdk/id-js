/** How much harm an action can do, as the server declares it (`Danger: …`). */
export type Danger = 'read' | 'write' | 'destructive' | 'critical';

/** How a list operation pages: an opaque `after` cursor, or a `page` number. */
export type Pagination = 'cursor' | 'page';

/**
 * What the generator knows about one operation. Exported per plane (e.g.
 * `environmentOperations`) so tooling can show an action's scope and danger before running it.
 */
export interface OperationSpec {
  /** The action name (`x-action`), e.g. `apps.secrets.rotate`. Null for a route that is not an action. */
  readonly action: string | null;
  readonly operationId: string | null;
  readonly method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Path relative to `/api/v1`, with `{param}` placeholders. */
  readonly path: string;
  /** Path parameter names, in the order the method takes them. */
  readonly pathParams: readonly string[];
  /** The scope the credential must carry, when the spec names one. */
  readonly scope: string | null;
  /** The declared danger, when the spec names one. */
  readonly danger: Danger | null;
  /** Whether the operation can answer `202 approval_required`. */
  readonly approval: boolean;
  /** Whether the input travels as a JSON body (otherwise as the query string). */
  readonly body: boolean;
  readonly pagination: Pagination | null;
}

/** An approval a key's policy asked for — what a `202 approval_required` carries. */
export interface PendingApproval {
  id: string;
  status: string;
  /** Show this to the person: the same code appears on the device they approve on. */
  binding_code: string;
  expires_at: string;
  poll_url: string;
}

/** Cursor-paged `meta` (environment plane). */
export interface CursorPageMeta {
  limit?: number;
  has_more?: boolean;
  next_cursor?: string | null;
}

/** Page-numbered `meta` (workspace plane). */
export interface NumberedPageMeta {
  limit?: number;
  page?: number;
  total?: number;
  has_more?: boolean;
  next_page?: number | null;
}

type DataOf<TBody> = TBody extends { data: infer D }
  ? D
  : TBody extends { data?: infer D }
    ? D | undefined
    : TBody extends void
      ? undefined
      : TBody;
type MetaOf<TBody> = TBody extends { meta?: infer M } ? M | undefined : undefined;

/** A successful answer. `data` is the envelope's `data`; `body` is the whole document. */
export interface ApiResponse<TBody> {
  readonly pending: false;
  readonly status: number;
  readonly data: DataOf<TBody>;
  readonly meta: MetaOf<TBody>;
  readonly body: TBody;
  /**
   * True when the server answered from its idempotency store (`Idempotent-Replayed: true`):
   * this is the FIRST request's answer, and any secret it carried (a client secret, a key's
   * token) is `null` — it was shown once, to the request that created it.
   */
  readonly replayed: boolean;
  /** The `Idempotency-Key` a write was sent with. */
  readonly idempotencyKey: string | undefined;
  /** The `X-Request-Id` response header, when something set one. */
  readonly requestId: string | null;
  readonly headers: Headers;
}

/**
 * A write held for approval, returned (instead of waited on) when the call passed
 * `{ approval: 'return' }`. `resume()` polls until the person decides and repeats the
 * request with the approval and the same `Idempotency-Key`.
 */
export interface PendingApprovalResult<TBody> {
  readonly pending: true;
  readonly status: 202;
  readonly approval: PendingApproval;
  readonly idempotencyKey: string | undefined;
  /** The action that was held, e.g. `apps.secrets.rotate`. */
  readonly action: string | null;
  resume(options?: { signal?: AbortSignal }): Promise<ApiResponse<TBody>>;
}

/** Per-call options every generated method takes last. */
export interface CallOptions {
  /** Your own `Idempotency-Key` for a write. Default: a fresh UUID per call (reused on its retries). */
  idempotencyKey?: string;
  /**
   * `wait` (default): on `202 approval_required`, call `onApprovalRequired`, poll until the
   * person decides, and repeat the request. `return`: hand the pending approval back
   * instead, as a {@link PendingApprovalResult}.
   */
  approval?: 'wait' | 'return';
  /** Send `Cbox-Approval: <id>` yourself — for an approval you obtained and waited on elsewhere. */
  approvalId?: string;
  signal?: AbortSignal;
  /** Extra request headers. Cannot override `Authorization`. */
  headers?: Record<string, string>;
}

/** What a generated method resolves to, given the options it was called with. */
export type Outcome<TBody, O> = O extends { approval: 'return' }
  ? ApiResponse<TBody> | PendingApprovalResult<TBody>
  : ApiResponse<TBody>;

/** Context handed to `onApprovalRequired` alongside the approval. */
export interface ApprovalContext {
  /** The action held, e.g. `apps.secrets.rotate`. */
  action: string | null;
  danger: Danger | null;
  method: string;
  path: string;
}
