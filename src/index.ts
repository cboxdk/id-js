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
  SignInResult,
  PasskeyOptions,
} from './frontend.js';
export { CboxIdClient } from './client.js';
export type { CallbackParams, StoredAuthState } from './client.js';
export type { DeviceAuthorization } from './types.js';
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
export {
  organization,
  actor,
  isSupportSession,
  roles,
  permissions,
  hasRole,
  hasPermission,
} from './claims.js';
export type {
  OrganizationRole,
  CboxActiveOrganization,
  CboxActor,
  ClaimSource,
} from './claims.js';
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
  CboxOrganization,
  AuthorizationPrompt,
  AuthorizationRequest,
  AuthorizationRequestOptions,
  TokenResponse,
  RefreshedTokens,
  DiscoveryDocument,
  TokenTypeHint,
} from './types.js';
