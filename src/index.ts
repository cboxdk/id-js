export { createLegacyVerifier } from './legacy.js';
export type { LegacyUser, LegacyVerifierOptions } from './legacy.js';
export { CboxIdFrontend } from './frontend.js';
export { FrontendApiError } from './errors.js';
export type {
  FrontendClientOptions,
  FrontendConfig,
  FrontendSession,
  SocialProvider,
  Appearance,
} from './frontend.js';
export { CboxIdClient } from './client.js';
export type { CallbackParams, StoredAuthState } from './client.js';
export { verifyWebhook } from './webhook.js';
export type { VerifyWebhookOptions } from './webhook.js';
export { VaultClient } from './vault.js';
export type { VaultSecretRef, VaultLease, StoreSecretInput } from './vault.js';
export {
  CboxIdError,
  ConfigurationError,
  InvalidStateError,
  AuthenticationError,
} from './errors.js';
export { createVerifier, challenge, randomToken } from './pkce.js';
export { defineAuthz, buildManifest, publishManifest } from './authz.js';
export type {
  PermissionDefinition,
  RoleDefinition,
  AuthzDeclaration,
  AuthzManifest,
  ManifestPublisherConfig,
  ManifestSyncSummary,
} from './authz.js';
export type {
  CboxIdConfig,
  CboxUser,
  AuthorizationRequest,
  TokenResponse,
  RefreshedTokens,
  DiscoveryDocument,
  TokenTypeHint,
} from './types.js';
