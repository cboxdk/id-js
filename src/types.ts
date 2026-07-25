/** Configuration for a {@link CboxIdClient}. */
export interface CboxIdConfig {
  /**
   * Base URL (issuer) of the Cbox ID instance, e.g. `https://id.acme.com`. Every
   * endpoint is discovered from `{issuer}/.well-known/openid-configuration`, so this
   * is usually the only endpoint you configure.
   */
  issuer: string;
  /** Your registered OAuth client id. */
  clientId: string;
  /**
   * Your client secret. Required for confidential (server-side) apps, machine
   * tokens and introspection. Omit for public clients (SPA/native) that only do
   * PKCE login.
   */
  clientSecret?: string;
  /** Your callback URL — must exactly match one registered on the client. */
  redirectUri: string;
  /** Scopes requested at login. Defaults to `['openid', 'profile', 'email']`. */
  scopes?: string[];
  /**
   * Path of the instance's hosted account page that {@link CboxIdClient.profileUrl}
   * points at. Defaults to `/settings`.
   */
  accountPath?: string;
  /** Timeout (ms) for back-channel HTTP calls. Defaults to `10000`. */
  timeoutMs?: number;
  /** How long (ms) the discovery document is cached. Defaults to `3600000` (1h). */
  cacheTtlMs?: number;
}

/** The OIDC discovery document fields this SDK uses. */
export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  introspection_endpoint?: string;
  revocation_endpoint?: string;
  end_session_endpoint?: string;
}

/**
 * RFC 7009 `token_type_hint`: which token store the server should search first.
 * Only a hint — the server must still find the token if the hint is wrong.
 */
export type TokenTypeHint = 'access_token' | 'refresh_token';

/**
 * The values {@link CboxIdClient.createAuthorizationRequest} returns. Persist
 * `state`, `codeVerifier` and `nonce` (e.g. in signed, httpOnly cookies) and hand
 * them back to {@link CboxIdClient.authenticate} on the callback.
 */
export interface AuthorizationRequest {
  /** The URL to redirect the user to. */
  url: string;
  state: string;
  codeVerifier: string;
  nonce: string;
}

/** The raw token-endpoint response. */
export interface TokenResponse {
  access_token: string;
  token_type?: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}

/**
 * The tokens returned by {@link CboxIdClient.refresh}. Cbox ID ROTATES refresh
 * tokens and detects reuse, so `refreshToken` is a NEW value — store it and discard
 * the one you presented; replaying a rotated token revokes the whole family.
 */
export interface RefreshedTokens {
  accessToken: string;
  refreshToken: string;
  idToken: string | null;
  expiresIn: number;
  scope: string | null;
}

/** One organization a user belongs to, from the `organizations` claim when present. */
export interface CboxOrganization {
  id: string;
  name: string;
  /** The member's role in this organization, when the claim carries it. */
  role?: string | null;
}

/**
 * The authenticated Cbox ID user. `id` is the stable opaque subject (`sub`) you key
 * your local account on. `claims` is the full verified id_token + userinfo claim
 * set; the named fields are conveniences over it.
 */
export interface CboxUser {
  id: string;
  email: string | null;
  name: string | null;
  /** The active organization's id (`org` claim). */
  organizationId: string | null;
  /**
   * The organizations this user belongs to, when the instance emits an
   * `organizations` claim. Undefined when the claim is absent (single-org apps, or
   * an instance that doesn't include it). Pass straight to `<OrganizationSwitcher>`.
   */
  organizations?: CboxOrganization[];
  claims: Record<string, unknown>;
  accessToken: string;
  refreshToken: string | null;
  idToken: string | null;
  expiresIn: number;
}
