/**
 * `@cboxdk/id-js/agent` — OAuth for agents and CLIs that act for a person: OpenID CIBA
 * (poll mode) and the RFC 8628 device grant against Cbox ID, plus RFC 7591 registration
 * with a WebCrypto-generated `private_key_jwt` key.
 *
 * Needs only `fetch` and WebCrypto, so it runs on Node 20+, Deno, Bun and edge runtimes.
 * See `docs/ciba-and-device-grant.md`.
 */
export { discoverAuthorizationServer } from './http.js';
export type { AuthorizationServerMetadata, AgentRequestOptions, AgentServerOptions } from './http.js';
export { generateClientKeyPair, createClientAssertion } from './client-auth.js';
export type { ClientAuth, ClientKeyAlgorithm, ClientKeyPair } from './client-auth.js';
export { registerAgentClient, CIBA_GRANT_TYPE, DEVICE_CODE_GRANT_TYPE } from './register.js';
export type { RegisterAgentClientOptions, RegisteredAgentClient } from './register.js';
export {
  startBackchannel,
  pollBackchannel,
  waitForBackchannelToken,
  startDeviceAuthorization,
  pollDeviceAuthorization,
  waitForDeviceToken,
  refreshAgentTokens,
} from './grants.js';
export type {
  AgentTokens,
  PollResult,
  WaitOptions,
  StartBackchannelOptions,
  BackchannelAuthorization,
  PollBackchannelOptions,
  StartDeviceAuthorizationOptions,
  DeviceGrantAuthorization,
  PollDeviceAuthorizationOptions,
  RefreshAgentTokensOptions,
} from './grants.js';
export { createBindingCode, BINDING_CODE_ALPHABET } from './binding.js';
export {
  AgentGrantError,
  AccessDeniedError,
  ExpiredTokenError,
  InvalidGrantError,
  InvalidTargetError,
  InvalidClientError,
  UnknownUserIdError,
  InvalidBindingMessageError,
  SlowDownError,
  GrantCancelledError,
} from './errors.js';
export { CboxIdError, ConfigurationError, AuthenticationError } from '../errors.js';
