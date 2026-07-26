import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { Discovery } from './discovery.js';
import { AuthenticationError, ConfigurationError, InvalidStateError } from './errors.js';
import { challenge, createVerifier, randomToken } from './pkce.js';
import type {
  AuthorizationRequest,
  CboxIdConfig,
  CboxOrganization,
  CboxUser,
  RefreshedTokens,
  TokenResponse,
  TokenTypeHint,
} from './types.js';
import { VaultClient } from './vault.js';
import { verifyWebhook, type VerifyWebhookOptions } from './webhook.js';

type JwksResolver = ReturnType<typeof createRemoteJWKSet>;

/** Query parameters as they arrive on your callback route. */
export interface CallbackParams {
  code?: string | null;
  state?: string | null;
  error?: string | null;
  error_description?: string | null;
}

/** The values you persisted from {@link CboxIdClient.createAuthorizationRequest}. */
export interface StoredAuthState {
  state: string;
  codeVerifier: string;
  nonce: string;
  /** The `maxAge` this login demanded, if any. See {@link AuthorizationRequest.maxAge}. */
  maxAge?: number;
}

/**
 * Turnkey Cbox ID client for JavaScript/TypeScript. It speaks standard OpenID
 * Connect against a Cbox ID instance — so integrating is a redirect and a callback,
 * not a rewrite — and adds the conveniences a hosted-identity product needs: a
 * redirect to the instance's hosted profile page, and back-channel helpers (machine
 * tokens, userinfo, introspection, webhook verification).
 *
 * Login is hardened by default: PKCE (S256), a CSRF state check, a nonce, and full
 * id_token signature + issuer + audience verification against the instance's JWKS
 * (via `jose`).
 *
 * The class is framework-agnostic: {@link createAuthorizationRequest} hands you the
 * `state`, `codeVerifier` and `nonce` to persist however you like, and
 * {@link authenticate} takes them back. For Next.js, the `@cboxdk/id-js/nextjs`
 * entry wires this to cookies for you.
 */
export class CboxIdClient {
  private readonly discovery: Discovery;
  private readonly jwksByUri = new Map<string, JwksResolver>();

  constructor(private readonly config: CboxIdConfig) {
    if (!config.issuer) {
      throw new ConfigurationError('Cbox ID config `issuer` is required.');
    }
    if (!config.clientId) {
      throw new ConfigurationError('Cbox ID config `clientId` is required.');
    }
    if (!config.redirectUri) {
      throw new ConfigurationError('Cbox ID config `redirectUri` is required.');
    }
    this.discovery = new Discovery(
      config.issuer,
      config.timeoutMs ?? 10_000,
      config.cacheTtlMs ?? 3_600_000,
    );
  }

  /**
   * Begin login. Returns the authorize URL plus the `state`, `codeVerifier` and
   * `nonce` — persist those (signed, httpOnly cookies are ideal) and hand them back
   * to {@link authenticate} on the callback.
   */
  async createAuthorizationRequest(options: {
    scopes?: string[];
    redirectUri?: string;
    state?: string;
    prompt?: string;
    loginHint?: string;
    maxAge?: number;
  } = {}): Promise<AuthorizationRequest> {
    const codeVerifier = createVerifier();
    const state = options.state ?? randomToken(16);
    const nonce = randomToken(16);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: options.redirectUri ?? this.config.redirectUri,
      scope: (options.scopes ?? this.scopes()).join(' '),
      state,
      nonce,
      code_challenge: await challenge(codeVerifier),
      code_challenge_method: 'S256',
    });
    if (options.prompt) {
      params.set('prompt', options.prompt);
    }
    if (options.loginHint) {
      params.set('login_hint', options.loginHint);
    }
    if (typeof options.maxAge === 'number') {
      params.set('max_age', String(options.maxAge));
    }

    const endpoint = await this.discovery.endpoint('authorization_endpoint');
    return {
      url: `${endpoint}?${params.toString()}`,
      state,
      codeVerifier,
      nonce,
      // Carried through so authenticate() can hold the instance to it. Only present
      // when requested (exactOptionalPropertyTypes).
      ...(typeof options.maxAge === 'number' ? { maxAge: options.maxAge } : {}),
    };
  }

  /**
   * Complete login on your callback route: verify state, exchange the code with the
   * PKCE verifier, verify the id_token, and return the authenticated user.
   *
   * @throws InvalidStateError when state does not match (forged/stale request)
   * @throws AuthenticationError on any other failure
   */
  async authenticate(input: {
    params: CallbackParams;
    stored: StoredAuthState;
    redirectUri?: string;
  }): Promise<CboxUser> {
    const { params, stored } = input;

    if (!params.state || !stored.state || !timingSafeEqualString(params.state, stored.state)) {
      throw new InvalidStateError('The login state did not match — the request may be forged or stale.');
    }

    if (params.error) {
      throw new AuthenticationError(
        `Cbox ID returned an error: ${params.error}${params.error_description ? ` (${params.error_description})` : ''}`,
      );
    }

    if (!params.code) {
      throw new AuthenticationError('The callback was missing an authorization code.');
    }

    const tokens = await this.exchange(params.code, stored.codeVerifier, input.redirectUri);

    if (!tokens.access_token) {
      throw new AuthenticationError('No access token was returned.');
    }

    let claims: Record<string, unknown> = {};
    if (tokens.id_token) {
      claims = await this.verifyIdToken(tokens.id_token, stored.nonce, stored.maxAge);
    } else if (typeof stored.maxAge === 'number') {
      // No id_token means no auth_time, and therefore no evidence the demanded
      // re-authentication happened. Accepting that silently is the whole defect.
      throw new AuthenticationError(
        'A max_age was requested but no id_token was returned, so the authentication age could not be verified.',
      );
    }
    // Enrich with userinfo (email/name/org a minimal id_token may omit).
    claims = { ...claims, ...(await this.userinfo(tokens.access_token)) };

    const sub = claims['sub'];
    if (typeof sub !== 'string' || sub === '') {
      throw new AuthenticationError('The verified token carried no subject.');
    }

    const organizations = parseOrganizations(claims['organizations']);

    return {
      id: sub,
      email: typeof claims['email'] === 'string' ? claims['email'] : null,
      name: typeof claims['name'] === 'string' ? claims['name'] : null,
      organizationId: typeof claims['org'] === 'string' ? claims['org'] : null,
      // Only present when the instance emitted the claim (exactOptionalPropertyTypes).
      ...(organizations ? { organizations } : {}),
      claims,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token ?? null,
      idToken: tokens.id_token ?? null,
      expiresIn: typeof tokens.expires_in === 'number' ? tokens.expires_in : 0,
    };
  }

  /**
   * Exchange a refresh token for a fresh access token (OAuth 2.0 `refresh_token`
   * grant). Cbox ID rotates refresh tokens and detects reuse, so ALWAYS persist the
   * returned `refreshToken` and discard the one you passed — presenting a rotated
   * token again revokes the entire token family.
   *
   * @throws AuthenticationError when the refresh token is invalid, expired, or already rotated.
   */
  async refresh(refreshToken: string): Promise<RefreshedTokens> {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.config.clientId,
      refresh_token: refreshToken,
    });
    if (this.config.clientSecret) {
      body.set('client_secret', this.config.clientSecret);
    }

    const response = await this.post(await this.discovery.endpoint('token_endpoint'), body);
    if (!response.ok) {
      throw new AuthenticationError(`Token refresh failed: ${await response.text()}`);
    }

    const tokens = (await response.json()) as TokenResponse;
    if (!tokens.access_token) {
      throw new AuthenticationError('The refresh response carried no access token.');
    }

    return {
      accessToken: tokens.access_token,
      // Keep the presented token when the server does not rotate (OAuth 2.0 §6);
      // callers persist this value, so it must never come back null.
      refreshToken: tokens.refresh_token ?? refreshToken,
      idToken: tokens.id_token ?? null,
      expiresIn: typeof tokens.expires_in === 'number' ? tokens.expires_in : 0,
      scope: typeof tokens.scope === 'string' ? tokens.scope : null,
    };
  }

  /**
   * The URL of the instance's hosted account/profile page (self-service password,
   * MFA, passkeys, sessions). A signed-in user is authenticated there by their Cbox
   * ID session; `returnTo` is passed so the page can link back to your app.
   */
  profileUrl(returnTo?: string): string {
    const base = `${this.config.issuer.replace(/\/$/, '')}${this.accountPath()}`;
    return returnTo ? `${base}?${new URLSearchParams({ return_to: returnTo }).toString()}` : base;
  }

  /**
   * The RP-initiated logout URL, or null when the instance advertises none.
   *
   * `client_id` is always sent, even without a `returnTo`: the OP validates
   * `post_logout_redirect_uri` against the registered allow-list of THAT client
   * (OIDC RP-Initiated Logout 1.0 §2). With no way to name the RP the OP cannot
   * check the list, so it silently drops the return URL and strands the user on a
   * bare "you are signed out" page. `idTokenHint` — the user's `id_token`, if you
   * still hold it — is the spec's other way to identify the RP, and additionally
   * tells the OP which subject is logging out.
   */
  async logoutUrl(returnTo?: string, idTokenHint?: string): Promise<string | null> {
    const endpoint = await this.discovery.optionalEndpoint('end_session_endpoint');
    if (!endpoint) {
      return null;
    }
    const params = new URLSearchParams({ client_id: this.config.clientId });
    if (returnTo) {
      params.set('post_logout_redirect_uri', returnTo);
    }
    if (idTokenHint) {
      params.set('id_token_hint', idTokenHint);
    }
    return `${endpoint}?${params.toString()}`;
  }

  /**
   * A machine (client-credentials) access token for calling Cbox ID APIs as your
   * app, not on a user's behalf. Requires a client secret.
   */
  async machineToken(options: { scopes?: string[]; resource?: string } = {}): Promise<string> {
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.config.clientId,
      client_secret: this.requireSecret(),
    });
    if (options.scopes && options.scopes.length > 0) {
      body.set('scope', options.scopes.join(' '));
    }
    if (options.resource) {
      body.set('resource', options.resource);
    }

    const response = await this.post(await this.discovery.endpoint('token_endpoint'), body);
    if (!response.ok) {
      throw new AuthenticationError(`Machine token request failed: ${await response.text()}`);
    }
    const json = (await response.json()) as { access_token?: unknown };
    if (typeof json.access_token !== 'string') {
      throw new AuthenticationError('The token response had no access_token.');
    }
    return json.access_token;
  }

  /** The OIDC userinfo claims for an access token. */
  async userinfo(accessToken: string): Promise<Record<string, unknown>> {
    const endpoint = await this.discovery.optionalEndpoint('userinfo_endpoint');
    if (!endpoint) {
      return {};
    }
    const response = await this.fetchWithTimeout(endpoint, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) {
      throw new AuthenticationError('Userinfo request failed.');
    }
    return (await response.json()) as Record<string, unknown>;
  }

  /**
   * RFC 7662 token introspection (confidential-client auth). Returns the raw
   * response; `active` tells you if the token is currently valid. Requires a secret.
   */
  async introspect(token: string): Promise<Record<string, unknown>> {
    const endpoint = await this.discovery.endpoint('introspection_endpoint');
    const basic = btoa(`${this.config.clientId}:${this.requireSecret()}`);
    const response = await this.post(
      endpoint,
      new URLSearchParams({ token }),
      { authorization: `Basic ${basic}` },
    );
    if (!response.ok) {
      throw new AuthenticationError('Introspection request failed.');
    }
    return (await response.json()) as Record<string, unknown>;
  }

  /**
   * RFC 7009 token revocation (confidential-client auth). Revokes an access or
   * refresh token; revoking a refresh token also drops the whole token family, so
   * this is what a real "sign out everywhere" does. Requires a secret.
   *
   * Per RFC 7009 the server answers 200 for an unknown or already-revoked token, so
   * a successful call means "the token is not valid any more", not "it existed".
   *
   * @param tokenTypeHint which store to search first — only a hint, never required.
   */
  async revoke(token: string, tokenTypeHint?: TokenTypeHint): Promise<void> {
    const endpoint = await this.discovery.endpoint('revocation_endpoint');
    const basic = btoa(`${this.config.clientId}:${this.requireSecret()}`);
    const body = new URLSearchParams({ token });
    if (tokenTypeHint) {
      body.set('token_type_hint', tokenTypeHint);
    }
    const response = await this.post(endpoint, body, { authorization: `Basic ${basic}` });
    if (!response.ok) {
      throw new AuthenticationError('Revocation request failed.');
    }
  }

  /** Verify a Cbox ID webhook / inline-action signature. See {@link verifyWebhook}. */
  verifyWebhook(options: VerifyWebhookOptions): Promise<boolean> {
    return verifyWebhook(options);
  }

  /**
   * A Token Vault client bound to an access token. Obtain the token with
   * {@link machineToken} (scope `vault.manage` to provision/grant, `vault.lease` to
   * redeem), then call `store` / `grant` / `lease` etc.
   */
  vault(accessToken: string): VaultClient {
    return new VaultClient(this.config.issuer, accessToken, this.config.timeoutMs ?? 10_000);
  }

  private async exchange(code: string, verifier: string, redirectUri?: string): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri ?? this.config.redirectUri,
      client_id: this.config.clientId,
      code_verifier: verifier,
    });
    if (this.config.clientSecret) {
      body.set('client_secret', this.config.clientSecret);
    }

    const response = await this.post(await this.discovery.endpoint('token_endpoint'), body);
    if (!response.ok) {
      throw new AuthenticationError(`Token exchange failed: ${await response.text()}`);
    }
    return (await response.json()) as TokenResponse;
  }

  private async verifyIdToken(
    idToken: string,
    nonce: string,
    maxAge?: number,
  ): Promise<Record<string, unknown>> {
    const jwksUri = await this.discovery.endpoint('jwks_uri');
    let resolver = this.jwksByUri.get(jwksUri);
    if (!resolver) {
      resolver = createRemoteJWKSet(new URL(jwksUri));
      this.jwksByUri.set(jwksUri, resolver);
    }

    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(idToken, resolver, {
        issuer: this.config.issuer,
        audience: this.config.clientId,
        // Pin the accepted signature algorithms explicitly. `jose` already refuses
        // `alg: none` and key-type confusion, so this is belt-and-braces — but it
        // states the contract in code rather than relying on a library default.
        algorithms: ['RS256', 'ES256'],
      }));
    } catch (error) {
      throw new AuthenticationError(`The id_token could not be verified: ${String(error)}`);
    }

    if (nonce && payload['nonce'] !== nonce) {
      throw new AuthenticationError('The id_token nonce did not match — possible replay.');
    }

    // OIDC Core §3.1.3.7 step 12: when max_age was requested, `auth_time` is REQUIRED
    // and the relying party MUST check it. `max_age` is the control you reach for
    // before a payment or an admin grant, and the whole point is that the person
    // authenticated JUST NOW — so a login({maxAge}) whose result is never checked is a
    // step-up in name only: a day-old session comes back carrying its original
    // auth_time and nothing anywhere says so.
    if (typeof maxAge === 'number') {
      const authTime = payload['auth_time'];

      if (typeof authTime !== 'number') {
        throw new AuthenticationError(
          'A max_age was requested but the id_token carried no auth_time, so the authentication age could not be verified.',
        );
      }

      const tolerance = this.config.authTimeToleranceSeconds ?? 60;
      const age = Math.floor(Date.now() / 1000) - authTime;

      if (age > maxAge + tolerance) {
        throw new AuthenticationError(
          `The authentication is ${age}s old but max_age required ${maxAge}s — the user did not re-authenticate.`,
        );
      }
    }

    return payload as Record<string, unknown>;
  }

  private scopes(): string[] {
    const scopes = this.config.scopes;
    return scopes && scopes.length > 0 ? scopes : ['openid', 'profile', 'email'];
  }

  private accountPath(): string {
    const path = this.config.accountPath;
    return path && path !== '' ? `/${path.replace(/^\//, '')}` : '/settings';
  }

  private requireSecret(): string {
    if (!this.config.clientSecret) {
      throw new ConfigurationError('This call requires a `clientSecret`, but none is configured.');
    }
    return this.config.clientSecret;
  }

  private post(url: string, body: URLSearchParams, headers: Record<string, string> = {}): Promise<Response> {
    return this.fetchWithTimeout(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body,
    });
  }

  private async fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs ?? 10_000);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Constant-time string compare, so state validation doesn't leak via timing. */
function timingSafeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

/**
 * Parse an `organizations` claim into typed orgs, ignoring anything malformed. The
 * claim is optional and instance-specific; absent or non-array → undefined, so
 * callers can tell "no claim" from "empty".
 */
function parseOrganizations(claim: unknown): CboxOrganization[] | undefined {
  if (!Array.isArray(claim)) {
    return undefined;
  }
  const orgs: CboxOrganization[] = [];
  for (const entry of claim) {
    if (typeof entry !== 'object' || entry === null) {
      continue;
    }
    const record = entry as Record<string, unknown>;
    const id = record['id'];
    const name = record['name'];
    if (typeof id === 'string' && id !== '' && typeof name === 'string' && name !== '') {
      orgs.push({ id, name, role: typeof record['role'] === 'string' ? record['role'] : null });
    }
  }
  return orgs;
}
