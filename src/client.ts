import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { Discovery } from './discovery.js';
import { assertSecureIssuer } from './issuer.js';
import { AuthenticationError, ConfigurationError, InvalidStateError, oauthError } from './errors.js';
import { challenge, createVerifier, randomToken } from './pkce.js';
import { actor, organization, permissions, roles, sessionId } from './claims.js';
import type {
  AuthorizationPrompt,
  AuthorizationRequest,
  AuthorizationRequestOptions,
  CboxIdConfig,
  DeviceAuthorization,
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
  /**
   * The organization this sign-in was bound to, if any. See
   * {@link AuthorizationRequest.organization}.
   *
   * Checked, not trusted: a binding nobody verifies is a binding in name only. An
   * instance that predates the `organization` parameter ignores it and returns tokens for
   * whichever organization the session already had — and an app that switched to "Globex"
   * would then show Globex's name over Acme's data.
   */
  organization?: string;
  /**
   * The scopes THIS authorization asked for, when you overrode the configured set.
   *
   * Read so `authenticate()` can judge the response against what was requested rather
   * than against the config: a login that asked for `openid` and came back without an
   * id_token is a protocol violation, and one that never asked cannot be held to it.
   * Omitted, the configured scopes are assumed — which is what a caller who did not
   * override them actually sent.
   */
  scopes?: string[];
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
    assertSecureIssuer(config.issuer);
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
  async createAuthorizationRequest(options: AuthorizationRequestOptions = {}): Promise<AuthorizationRequest> {
    const prompt = promptValue(options.prompt);
    assertOrganizationOptions(options, prompt);

    const codeVerifier = createVerifier();
    const state = options.state ?? randomToken(16);
    const nonce = randomToken(16);

    const redirectUri = options.redirectUri ?? this.config.redirectUri;

    if (redirectUri === undefined || redirectUri === '') {
      // Checked where it is needed rather than at construction, so a CLI can build a
      // client at all. An authorize URL without `redirect_uri` would fail at the
      // authorization server instead, describing a request the caller never knowingly
      // made — see the device grant, which has no callback to name.
      throw new ConfigurationError(
        'A `redirectUri` is required to start the browser sign-in flow. Set it in the config, or pass it to createAuthorizationRequest.',
      );
    }

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      scope: (options.scopes ?? this.scopes()).join(' '),
      state,
      nonce,
      code_challenge: await challenge(codeVerifier),
      code_challenge_method: 'S256',
    });
    if (prompt.length > 0) {
      params.set('prompt', prompt.join(' '));
    }
    if (options.loginHint) {
      params.set('login_hint', options.loginHint);
    }
    if (typeof options.maxAge === 'number') {
      params.set('max_age', String(options.maxAge));
    }
    if (options.organization !== undefined) {
      params.set('organization', options.organization);
    }
    if (options.organizationHint !== undefined) {
      params.set('organization_hint', options.organizationHint);
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
      ...(options.organization !== undefined ? { organization: options.organization } : {}),
    };
  }

  /**
   * Switch the signed-in person to another organization: a new authorization bound to
   * `organizationId`. Persist and redirect exactly as for
   * {@link createAuthorizationRequest} — it is one, with `organization` set.
   *
   * Cbox ID already holds the person's session, so this is normally a redirect there and
   * straight back with no sign-in form. The tokens that come back carry the new `org`,
   * `org_role`, `roles` and `permissions`; replace your session with them rather than
   * patching the old one, because every one of those can differ between organizations.
   *
   * A person who is not (or is no longer) an active member of that organization comes
   * back with `error=access_denied`, which {@link authenticate} throws as an
   * `AuthenticationError` with `error === 'access_denied'`.
   */
  switchOrganization(
    organizationId: string,
    options: Omit<AuthorizationRequestOptions, 'organization' | 'organizationHint'> = {},
  ): Promise<AuthorizationRequest> {
    return this.createAuthorizationRequest({ ...options, organization: organizationId });
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
      // The code travels as `error`, not only in the message: `access_denied` after a
      // switchOrganization() means "not a member of that organization", which an app
      // answers by switching back — not by signing the person out.
      throw new AuthenticationError(
        `Cbox ID returned an error: ${params.error}${params.error_description ? ` (${params.error_description})` : ''}`,
        params.error,
        params.error_description ?? undefined,
      );
    }

    if (!params.code) {
      throw new AuthenticationError('The callback was missing an authorization code.');
    }

    const tokens = await this.exchange(params.code, stored.codeVerifier, input.redirectUri);

    if (!tokens.access_token) {
      throw new AuthenticationError('No access token was returned.');
    }

    let verified: Record<string, unknown> = {};

    if (tokens.id_token) {
      verified = await this.verifyIdToken(tokens.id_token, stored.nonce, stored.maxAge);
    } else if ((stored.scopes ?? this.scopes()).includes('openid')) {
      // AN `openid` REQUEST WITHOUT AN ID_TOKEN IS A PROTOCOL VIOLATION, and refusing it
      // is the difference between an authenticated login and a bearer token. Without this
      // the identity below came from UserInfo alone — a bearer-authenticated endpoint
      // whose response nothing signed — and the `nonce` pulled from storage was never used.
      //
      // Asked of the SCOPES REQUESTED, not of the response: a caller who never asked for
      // `openid` is running an OAuth flow and is not held to an OIDC rule.
      throw new AuthenticationError(
        'An openid login returned no id_token, so the identity could not be verified.',
      );
    } else if (typeof stored.maxAge === 'number') {
      // No id_token means no auth_time, and therefore no evidence the demanded
      // re-authentication happened. Accepting that silently is the whole defect.
      throw new AuthenticationError(
        'A max_age was requested but no id_token was returned, so the authentication age could not be verified.',
      );
    }

    const user = await this.identityFrom(tokens, verified);

    if (stored.organization !== undefined && user.organizationId !== stored.organization) {
      throw new AuthenticationError(
        `The sign-in was bound to organization ${stored.organization}, but the tokens are for ${user.organizationId ?? 'no organization'}. The instance may not support organization selection.`,
      );
    }

    return user;
  }

  /**
   * Turn a token response into the verified {@link CboxUser} every flow returns.
   *
   * Shared by the browser flow and the device flow rather than written twice: the checks
   * in here — the UserInfo subject matching the id_token's, the merge that lets UserInfo
   * enrich but never overwrite signed claims — are the ones that decide whether an
   * identity is trustworthy. A second copy is a second place for one of them to be
   * quietly missing, and the flow it was missing from would look exactly as correct.
   */
  private async identityFrom(
    tokens: TokenResponse,
    verified: Record<string, unknown>,
  ): Promise<CboxUser> {
    const profile = await this.userinfo(tokens.access_token);

    // OIDC Core §5.3.2: the UserInfo `sub` MUST match the id_token's, and when it does
    // not the response MUST NOT be used. UserInfo is fetched with a bearer token and its
    // body carries no signature, so without this an IdP — or anything able to answer as
    // one — hands back `{"sub":"somebody-else"}` and the SDK returns it as the identity.
    const verifiedSub = verified['sub'];
    const profileSub = profile['sub'];

    if (typeof verifiedSub === 'string' && typeof profileSub === 'string' && !timingSafeEqualString(verifiedSub, profileSub)) {
      throw new AuthenticationError('The UserInfo subject does not match the verified id_token.');
    }

    // ENRICHES, NEVER REPLACES. UserInfo fills in what a minimal id_token omits (email,
    // name, org) and the verified claims go back on top, so the merge cannot move `sub`,
    // `iss`, `aud`, `nonce` or anything else the signature covered. The spread used to run
    // the other way round.
    const claims: Record<string, unknown> = { ...profile, ...verified };

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
      organization: organization(claims),
      roles: roles(claims),
      permissions: permissions(claims),
      actor: actor(claims),
      sessionId: sessionId(claims),
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
   * Start the device authorization grant (RFC 8628) — the flow for a program with no
   * browser of its own: a CLI, a CI job, a container, a TV.
   *
   * Print `userCode` and `verificationUri`, then call
   * {@link CboxIdClient.pollDeviceToken}. If the machine has a desktop you may also open
   * `verificationUriComplete`, which fills the code in — but print the code anyway: the
   * machine running your program is often not the one the person is looking at.
   *
   * The scopes are bounded by what the app is REGISTERED for. A device request naming one
   * outside that ceiling is refused with `invalid_scope` rather than quietly reduced,
   * because no browser is in front of it to notice a smaller grant.
   *
   * @throws ConfigurationError when the instance advertises no device endpoint.
   */
  async requestDeviceAuthorization(scopes?: string[]): Promise<DeviceAuthorization> {
    const endpoint = await this.discovery.optionalEndpoint('device_authorization_endpoint');

    if (endpoint === null) {
      throw new ConfigurationError(
        'This instance does not advertise a device_authorization_endpoint, so it does not support CLI sign-in.',
      );
    }

    const body = new URLSearchParams({
      client_id: this.config.clientId,
      scope: (scopes ?? this.scopes()).join(' '),
    });
    if (this.config.clientSecret) {
      body.set('client_secret', this.config.clientSecret);
    }

    const response = await this.post(endpoint, body);
    if (!response.ok) {
      throw await oauthError(response, 'Device authorization request failed');
    }

    const payload = (await response.json()) as Record<string, unknown>;

    const deviceCode = payload['device_code'];
    const userCode = payload['user_code'];
    const verificationUri = payload['verification_uri'];

    if (typeof deviceCode !== 'string' || typeof userCode !== 'string' || typeof verificationUri !== 'string') {
      throw new AuthenticationError('The device authorization response was incomplete.');
    }

    return {
      deviceCode,
      userCode,
      verificationUri,
      verificationUriComplete:
        typeof payload['verification_uri_complete'] === 'string'
          ? payload['verification_uri_complete']
          : null,
      expiresIn: typeof payload['expires_in'] === 'number' ? payload['expires_in'] : 600,
      // RFC 8628 §3.2: absent means 5 seconds. Polling faster than the server allows is
      // answered with `slow_down`, so the default is the one the server assumes too.
      interval: typeof payload['interval'] === 'number' ? payload['interval'] : 5,
    };
  }

  /**
   * Poll until the person approves, and return them.
   *
   * Blocks. It honours the server's `interval`, backs off permanently by five seconds on
   * `slow_down` (RFC 8628 §3.5), and stops on the three answers that are final: they
   * declined, the code expired, or tokens arrived. Pass an `AbortSignal` to give up
   * early — a CLI should let Ctrl-C work.
   *
   * @throws AuthenticationError when the person declines or the code expires.
   */
  async pollDeviceToken(
    authorization: DeviceAuthorization,
    options: { signal?: AbortSignal } = {},
  ): Promise<CboxUser> {
    const endpoint = await this.discovery.endpoint('token_endpoint');
    const deadline = Date.now() + authorization.expiresIn * 1000;
    let intervalMs = authorization.interval * 1000;

    for (;;) {
      if (options.signal?.aborted === true) {
        throw new AuthenticationError('Device sign-in was cancelled.');
      }
      if (Date.now() > deadline) {
        throw new AuthenticationError(
          'The device code expired before it was approved. Start the sign-in again.',
        );
      }

      await sleep(intervalMs, options.signal);

      const body = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: authorization.deviceCode,
        client_id: this.config.clientId,
      });
      if (this.config.clientSecret) {
        body.set('client_secret', this.config.clientSecret);
      }

      const response = await this.post(endpoint, body);

      if (response.ok) {
        const tokens = (await response.json()) as TokenResponse;

        if (!tokens.access_token) {
          throw new AuthenticationError('The device token response carried no access token.');
        }

        // No nonce: RFC 8628 has no browser leg to carry one, so there is nothing to
        // bind. Everything else about the id_token — signature, issuer, audience,
        // expiry — is verified exactly as it is on the browser flow.
        const verified = tokens.id_token ? await this.verifyIdToken(tokens.id_token, '') : {};

        return await this.identityFrom(tokens, verified);
      }

      const payload = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      const error = typeof payload['error'] === 'string' ? payload['error'] : 'invalid_request';

      if (error === 'authorization_pending') {
        continue;
      }

      if (error === 'slow_down') {
        // Permanently, not for one round: the server is telling us our rate is wrong,
        // and returning to it next tick earns the same answer forever.
        intervalMs += 5000;
        continue;
      }

      if (error === 'access_denied') {
        throw new AuthenticationError('Sign-in was declined.');
      }

      if (error === 'expired_token') {
        throw new AuthenticationError(
          'The device code expired before it was approved. Start the sign-in again.',
        );
      }

      throw await oauthError(response, 'Device sign-in failed');
    }
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
      // The most consequential of these: `invalid_grant` means the refresh token is
      // spent, revoked or replayed and the person must sign in again, while a 5xx or
      // `temporarily_unavailable` means the same token is still good in a moment. One
      // message string for both is what makes callers guess.
      throw await oauthError(response, 'Token refresh failed');
    }

    const tokens = (await response.json()) as TokenResponse;
    if (!tokens.access_token) {
      throw new AuthenticationError('The refresh response carried no access token.');
    }

    // VERIFIED BEFORE IT IS HANDED BACK. A refresh response carries a fresh id_token, and
    // this returned it unchecked — so an application that refreshes its session claims
    // from `refresh().idToken` accepted a forged, expired, wrong-audience or wrong-issuer
    // token, having verified only the one it got at login. The nonce is not re-checked:
    // RFC 6749 has no nonce on this leg, and OIDC Core §12.2 says an id_token from a
    // refresh need not carry one.
    if (tokens.id_token) {
      await this.verifyIdToken(tokens.id_token, '');
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
   * The hosted page where a person creates and revokes API keys for your API — Cbox ID's
   * `/account/api-keys`, preselected to this app (or `clientId`). Keys made there are
   * checked with `ApiKeyVerifier` from `@cboxdk/id-js/server`.
   *
   * `returnTo` becomes a link back to your app, honoured only for an origin the app
   * registered. `organization` picks which of the person's organizations the keys act in;
   * omitted, the page uses the one they are in.
   */
  apiKeysUrl(options: { clientId?: string; returnTo?: string; organization?: string } = {}): string {
    const params = new URLSearchParams({ client_id: options.clientId ?? this.config.clientId });
    if (options.returnTo) {
      params.set('return_to', options.returnTo);
    }
    if (options.organization) {
      params.set('organization', options.organization);
    }

    return `${this.config.issuer.replace(/\/$/, '')}/account/api-keys?${params.toString()}`;
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
   *
   * PASS THE HINT IF YOU WANT "SIGN OUT EVERYWHERE". Cbox ID revokes every session
   * the person holds only when a hint it can VERIFY names the subject holding the
   * browser; with no hint it signs this browser out and leaves their other devices
   * alone. That is deliberate: the endpoint is unauthenticated and reached by a
   * redirect, so a request carrying no proof of who it concerns could otherwise be
   * forged into ending anyone's sessions everywhere. See laravel-id UPGRADING.md
   * for 1.8.0.
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
      throw await oauthError(response, 'Machine token request failed');
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
      throw await oauthError(response, 'Userinfo request failed');
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
      throw await oauthError(response, 'Introspection request failed');
    }
    return (await response.json()) as Record<string, unknown>;
  }

  /**
   * RFC 7009 token revocation. Revokes an access or refresh token; revoking a refresh
   * token drops the whole token family, so this is what a real "sign out everywhere" does.
   *
   * **PUBLIC CLIENTS TOO.** This demanded a secret and threw `ConfigurationError` without
   * one — so the clients that most need it were the ones that could not call it. A PKCE
   * browser or native app authenticates with `none`, holds no secret, and is exactly the
   * case where a refresh token sits in storage on a device somebody has just signed out
   * of. Cbox ID's revocation endpoint accepts a public client, and its discovery document
   * advertises `none` among the revocation auth methods; RFC 7009 §2.1 scopes every
   * revocation to the calling client, so the only capability here is "destroy a token you
   * are already holding". The SDK was the half saying no.
   *
   * A confidential client still authenticates with Basic; a public one names itself in the
   * body, the same shape {@link exchange} already uses for the token endpoint.
   *
   * Per RFC 7009 the server answers 200 for an unknown or already-revoked token, so
   * success means "this token is not valid any more", not "it existed".
   *
   * @param tokenTypeHint which store to search first — only a hint, never required.
   */
  async revoke(token: string, tokenTypeHint?: TokenTypeHint): Promise<void> {
    const endpoint = await this.discovery.endpoint('revocation_endpoint');
    const body = new URLSearchParams({ token, client_id: this.config.clientId });
    if (tokenTypeHint) {
      body.set('token_type_hint', tokenTypeHint);
    }

    const headers: Record<string, string> = {};
    if (this.config.clientSecret) {
      headers.authorization = `Basic ${btoa(`${this.config.clientId}:${this.config.clientSecret}`)}`;
    }

    const response = await this.post(endpoint, body, headers);
    if (!response.ok) {
      throw await oauthError(response, 'Revocation request failed');
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
    const callback = redirectUri ?? this.config.redirectUri;

    if (callback === undefined || callback === '') {
      throw new ConfigurationError(
        'A `redirectUri` is required to exchange an authorization code. It must be the same one the authorization request used.',
      );
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: callback,
      client_id: this.config.clientId,
      code_verifier: verifier,
    });
    if (this.config.clientSecret) {
      body.set('client_secret', this.config.clientSecret);
    }

    const response = await this.post(await this.discovery.endpoint('token_endpoint'), body);
    if (!response.ok) {
      throw await oauthError(response, 'Token exchange failed');
    }
    return (await response.json()) as TokenResponse;
  }

  private async verifyIdToken(
    idToken: string,
    // Empty skips the nonce comparison below, which is what a refresh leg needs: RFC 6749
    // has no nonce there and OIDC Core §12.2 says the id_token from a refresh need not
    // carry one. Signature, issuer, audience and expiry are checked either way.
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
    // `/account`, not `/settings`. The latter is the organization-admin page: it
    // redirects a non-admin to `/account` and drops `return_to` on the way, so a member
    // following this link arrives at the right screen having lost where they came from.
    return path && path !== '' ? `/${path.replace(/^\//, '')}` : '/account';
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

/** Normalise `prompt` to a de-duplicated list, refusing what the server would refuse. */
function promptValue(prompt: AuthorizationRequestOptions['prompt']): AuthorizationPrompt[] {
  if (prompt === undefined) {
    return [];
  }

  const values = [...new Set(typeof prompt === 'string' ? [prompt] : prompt)];

  // OIDC Core §3.1.2.1: `none` with any other value is an error. Failing here names the
  // call that built it; failing at the server names nothing the caller can find.
  if (values.includes('none') && values.length > 1) {
    throw new ConfigurationError("`prompt: 'none'` cannot be combined with another prompt value.");
  }

  return values;
}

/**
 * Refuse organization options that contradict each other. Each of these would reach the
 * server as a request with two incompatible meanings and come back as a generic error
 * after a full redirect — far from the line that built it.
 */
function assertOrganizationOptions(options: AuthorizationRequestOptions, prompt: AuthorizationPrompt[]): void {
  // An empty id is not "no organization" at the server — it is a parameter that is
  // present and names nothing. Omit the option instead.
  if (options.organization === '') {
    throw new ConfigurationError('`organization` is empty. Omit it to sign in without binding to an organization.');
  }
  if (options.organizationHint === '') {
    throw new ConfigurationError('`organizationHint` is empty. Omit it when you have no organization to suggest.');
  }

  if (options.organization === undefined) {
    return;
  }

  // `organization` binds to an existing organization; both prompts below ask the person
  // to choose or create one. Sending both leaves the server to guess which you meant.
  if (prompt.includes('select_organization')) {
    throw new ConfigurationError(
      "`organization` binds the sign-in to one organization, so `prompt: 'select_organization'` has nothing to choose. Use `organizationHint` to preselect an organization in the picker instead.",
    );
  }
  if (prompt.includes('create_organization')) {
    throw new ConfigurationError(
      "`organization` binds the sign-in to an existing organization and `prompt: 'create_organization'` creates a new one. Send one or the other.",
    );
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

/**
 * Wait, but stay interruptible.
 *
 * A CLI that ignores Ctrl-C for five seconds at a time feels broken, and a bare
 * `setTimeout` promise cannot be cancelled — so the abort is wired to the same timer
 * rather than checked after it.
 */
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(new AuthenticationError('Device sign-in was cancelled.'));
      return;
    }

    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);

    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new AuthenticationError('Device sign-in was cancelled.'));
    };

    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
