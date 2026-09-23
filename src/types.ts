import type { CboxActiveOrganization, CboxActor } from './claims.js';

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
  /**
   * Your callback URL — must exactly match one registered on the client.
   *
   * OPTIONAL, because not every flow has one. The device grant (RFC 8628) exists
   * precisely for programs with no browser to be returned to, so a CLI has none to give;
   * requiring it here made every CLI invent `'http://localhost'` and note that it is
   * unused. It is required by {@link CboxIdClient.createAuthorizationRequest} and
   * {@link CboxIdClient.authenticate}, which is where its absence actually breaks
   * something.
   */
  redirectUri?: string;
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
  /**
   * Leeway (seconds) when checking the id_token's `auth_time` against the `maxAge` you
   * requested at login. Defaults to `60`.
   *
   * Some slack is required, not optional: `maxAge` bounds the age of the
   * AUTHENTICATION, but `auth_time` is read after a browser redirect and a token
   * exchange, so even a just-completed re-authentication is already several seconds
   * old — and the RP's clock and the instance's need not agree. Sixty seconds absorbs
   * that while still catching what this check exists for: a session hours or days old
   * being passed off as fresh.
   */
  authTimeToleranceSeconds?: number;
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
  device_authorization_endpoint?: string;
}

/**
 * A pending device authorization (RFC 8628) — what a CLI shows the person while it waits.
 */
export interface DeviceAuthorization {
  /** The secret this program polls with. Never show it to the person. */
  deviceCode: string;
  /** The short code the person types on the verification page. */
  userCode: string;
  /** Where the person goes to approve. Print this. */
  verificationUri: string;
  /** The same page with the code filled in — for a clickable link or a QR code. */
  verificationUriComplete: string | null;
  /** Seconds until the code stops being valid. */
  expiresIn: number;
  /** The minimum seconds between polls. Never poll faster; the server will say so. */
  interval: number;
}

/**
 * RFC 7009 `token_type_hint`: which token store the server should search first.
 * Only a hint — the server must still find the token if the hint is wrong.
 */
export type TokenTypeHint = 'access_token' | 'refresh_token';

/**
 * An OIDC `prompt` value Cbox ID understands. The first four are OIDC Core §3.1.2.1; the
 * last two are Cbox ID's organization steps:
 *
 * - `select_organization` — always show the hosted organization picker, even to someone
 *   in a single organization.
 * - `create_organization` — the hosted "create a team" step: the person creates an
 *   organization, becomes its owner, and the sign-in continues bound to it.
 */
export type AuthorizationPrompt =
  | 'none'
  | 'login'
  | 'consent'
  | 'select_account'
  | 'select_organization'
  | 'create_organization';

/** Options for {@link CboxIdClient.createAuthorizationRequest}. */
export interface AuthorizationRequestOptions {
  /** Scopes for this sign-in; defaults to the configured set. */
  scopes?: string[];
  /** Overrides the configured callback for this sign-in. */
  redirectUri?: string;
  /** Your own `state`; a random one is generated when omitted. */
  state?: string;
  /**
   * One prompt, or several (sent space-separated). `none` cannot be combined with
   * anything else — OIDC Core §3.1.2.1 makes that an error at the server, so it is
   * refused here, where the stack trace still points at your code.
   */
  prompt?: AuthorizationPrompt | readonly AuthorizationPrompt[];
  /** Prefills the email on the sign-in page (`login_hint`). */
  loginHint?: string;
  /** Demand an authentication no older than this many seconds (`max_age`). */
  maxAge?: number;
  /**
   * Bind this sign-in to one organization (`organization`). The person must hold an
   * active membership in it; if they do not, the callback carries
   * `error=access_denied` and {@link CboxIdClient.authenticate} throws an
   * `AuthenticationError` whose `error` is `'access_denied'`.
   *
   * This is how an app switches organization: a new authorization bound to the other
   * one. See {@link CboxIdClient.switchOrganization}.
   */
  organization?: string;
  /**
   * Preselect an organization in the hosted picker (`organization_hint`) without binding
   * to it — the person can still choose another. Pair it with
   * `prompt: 'select_organization'` to always show the picker with your guess on top.
   */
  organizationHint?: string;
}

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
  /**
   * Echoed back when you passed `maxAge`. Persist it with the rest and hand it to
   * {@link CboxIdClient.authenticate}, which then verifies the id_token's `auth_time`
   * against it — a step-up nobody checks is not a step-up.
   */
  maxAge?: number;
  /**
   * Echoed back when you passed `organization`. Persist it and hand it to
   * {@link CboxIdClient.authenticate}, which then refuses tokens bound to any other
   * organization — see {@link StoredAuthState.organization}.
   */
  organization?: string;
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
  /** The active organization's id (`org` claim). Same as `organization?.id`. */
  organizationId: string | null;
  /**
   * The organization this session is bound to — id, name and the person's membership
   * tier in it (`org`, `org_name`, `org_role`) — or null when it is bound to none.
   */
  organization: CboxActiveOrganization | null;
  /** App roles held in this session (`roles` claim); empty when there are none. */
  roles: string[];
  /** Permissions held in this session (`permissions` claim); empty when there are none. */
  permissions: string[];
  /**
   * Set when this is a SUPPORT SESSION — a staff member acting as this person (the RFC
   * 8693 `act` claim). Null for an ordinary sign-in. Show it: see `isSupportSession()`.
   */
  actor: CboxActor | null;
  /**
   * The Cbox ID sign-in session (the ID Token's `sid`), or null when none was sent. Keep
   * it with your session to match a back-channel logout to it. See `sessionId()`.
   */
  sessionId: string | null;
  /**
   * The organizations this user belongs to — the UserInfo `organizations` claim, which
   * Cbox ID only sends when you requested the `organizations` scope (it lists every
   * organization the person is in, so a plain `profile` sign-in does not get it).
   * Undefined when the claim is absent. Pass straight to `<OrganizationSwitcher>`.
   */
  organizations?: CboxOrganization[];
  claims: Record<string, unknown>;
  accessToken: string;
  refreshToken: string | null;
  idToken: string | null;
  expiresIn: number;
}
