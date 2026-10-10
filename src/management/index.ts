/**
 * `@cboxdk/id-js/management` — typed clients for Cbox ID's management planes, generated from
 * the OpenAPI documents the server publishes (see `openapi/` and `npm run generate`).
 *
 * - {@link EnvironmentClient}: one environment's tenancy, on its own host (`cbid_env_…` key
 *   or a delegated access token).
 * - {@link WorkspaceClient}: the workspace above its environments (`cbid_ws_…` key).
 * - {@link PlatformClient}: the deployment itself, for operators (delegated token only).
 * - {@link AccountClient}: a person's own account (delegated token only).
 *
 * Server-side code: every client holds a management credential.
 */
export { EnvironmentClient, environmentOperations } from './generated/environment.js';
export type { EnvironmentClientOptions } from './generated/environment.js';
export { WorkspaceClient, workspaceOperations } from './generated/workspace.js';
export type { WorkspaceClientOptions } from './generated/workspace.js';
export { PlatformClient, platformOperations } from './generated/platform.js';
export type { PlatformClientOptions } from './generated/platform.js';
export { AccountClient, accountOperations } from './generated/account.js';
export type { AccountClientOptions } from './generated/account.js';

/** Every schema and operation type of each plane, as a namespace: `EnvironmentApi.App`. */
export type * as EnvironmentApi from './generated/environment.js';
export type * as WorkspaceApi from './generated/workspace.js';
export type * as PlatformApi from './generated/platform.js';
export type * as AccountApi from './generated/account.js';

export { ManagementTransport, retryAfterMs } from './transport.js';
export type { ManagementClientOptions, Plane, RetryOptions } from './transport.js';
export {
  CboxIdApiError,
  ManagementNetworkError,
  ApprovalError,
  ApprovalDeniedError,
  ApprovalExpiredError,
} from './errors.js';
export { CboxIdError, ConfigurationError } from '../errors.js';
export { createDPoPSigner, generateDPoPKeyPair } from './dpop.js';
export {
  AuditLogger,
  AuditLogExportError,
  exportAuditLogs,
  verifyAuditChain,
  verifyAuditLogChain,
  canonicalJson,
  auditEventDocument,
  auditEventHash,
  AUDIT_CHAIN_GENESIS,
  MAX_AUDIT_BATCH,
} from './audit-logs.js';
export type {
  AuditLogEventInput,
  AuditLogRecord,
  AuditLoggerOptions,
  AuditLogExportOptions,
  AuditEventHashInput,
  AuditChainVerification,
  VerifyAuditChainOptions,
} from './audit-logs.js';
export type { DPoPSigner } from './dpop.js';
export { fgaTuple } from './fga.js';
export type { FgaSubjectRef, FgaTupleRef } from './fga.js';
export type {
  ApiResponse,
  ApprovalContext,
  CallOptions,
  CursorPageMeta,
  Danger,
  NumberedPageMeta,
  OperationSpec,
  Outcome,
  Pagination,
  PendingApproval,
  PendingApprovalResult,
} from './types.js';
