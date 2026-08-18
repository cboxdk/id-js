import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AuthenticationError,
  CboxIdClient,
  ConfigurationError,
  InvalidStateError,
} from '../src/index.js';
import { challenge } from '../src/pkce.js';
import { discovery, fakeInstance, ISSUER, NONCE } from './helpers.js';

const baseConfig = {
  issuer: ISSUER,
  clientId: 'client-abc',
  clientSecret: 'secret-xyz',
  redirectUri: 'https://app.test/auth/callback',
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('createAuthorizationRequest', () => {
  it('builds an authorize URL with PKCE S256 and a matching challenge', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const req = await client.createAuthorizationRequest();
    const url = new URL(req.url);

    expect(url.origin + url.pathname).toBe(`${ISSUER}/oauth/authorize`);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe('client-abc');
    expect(url.searchParams.get('redirect_uri')).toBe('https://app.test/auth/callback');
    expect(url.searchParams.get('scope')).toBe('openid profile email');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('state')).toBe(req.state);
    expect(url.searchParams.get('nonce')).toBe(req.nonce);
    // The challenge in the URL is genuinely S256(verifier).
    expect(url.searchParams.get('code_challenge')).toBe(await challenge(req.codeVerifier));
  });

  it('honours custom scopes, prompt and login_hint', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const req = await client.createAuthorizationRequest({
      scopes: ['openid', 'reports.read'],
      prompt: 'login',
      loginHint: 'ada@acme.com',
    });
    const url = new URL(req.url);

    expect(url.searchParams.get('scope')).toBe('openid reports.read');
    expect(url.searchParams.get('prompt')).toBe('login');
    expect(url.searchParams.get('login_hint')).toBe('ada@acme.com');
  });
});

describe('authenticate', () => {
  const stored = { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE };

  it('completes login and returns the verified user', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const user = await client.authenticate({
      params: { code: 'auth-code', state: 'state-1' },
      stored,
    });

    expect(user.id).toBe('user-1');
    expect(user.email).toBe('ada@acme.com');
    expect(user.name).toBe('Ada');
    expect(user.organizationId).toBe('org-1');
    expect(user.accessToken).toBe('access-abc');
    expect(user.refreshToken).toBe('refresh-abc');
    expect(user.expiresIn).toBe(3600);
    expect(user.claims['sub']).toBe('user-1');
  });

  it('maps an organizations claim into typed orgs, dropping malformed entries', async () => {
    const inst = await fakeInstance({
      userinfo: {
        sub: 'user-1',
        email: 'ada@acme.com',
        name: 'Ada',
        org: 'org-1',
        organizations: [
          { id: 'org-1', name: 'Acme', role: 'admin' },
          { id: 'org-2', name: 'Globex' }, // no role → null
          { id: '', name: 'Nameless id' }, // malformed → dropped
          'not-an-object', // ignored
        ],
      },
    });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const user = await client.authenticate({ params: { code: 'auth-code', state: 'state-1' }, stored });

    expect(user.organizations).toEqual([
      { id: 'org-1', name: 'Acme', role: 'admin' },
      { id: 'org-2', name: 'Globex', role: null },
    ]);
  });

  it('omits organizations when the instance emits no such claim', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const user = await client.authenticate({ params: { code: 'auth-code', state: 'state-1' }, stored });

    expect(user.organizations).toBeUndefined();
  });

  it('rejects a mismatched state (CSRF)', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({ params: { code: 'auth-code', state: 'forged' }, stored }),
    ).rejects.toBeInstanceOf(InvalidStateError);
  });

  it('surfaces a provider error parameter', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({
        params: { state: 'state-1', error: 'access_denied', error_description: 'user said no' },
        stored,
      }),
    ).rejects.toThrowError(/access_denied/);
  });

  it('rejects a replayed nonce', async () => {
    const inst = await fakeInstance();
    const wrongNonce = await inst.signIdToken({
      iss: ISSUER,
      aud: 'client-abc',
      sub: 'user-1',
      nonce: 'a-different-nonce',
    });
    inst.setTokenResponse({ access_token: 'access-abc', id_token: wrongNonce });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({ params: { code: 'auth-code', state: 'state-1' }, stored }),
    ).rejects.toThrowError(/nonce/);
  });

  it('rejects an id_token from the wrong issuer', async () => {
    const inst = await fakeInstance();
    const wrongIssuer = await inst.signIdToken({
      iss: 'https://evil.test',
      aud: 'client-abc',
      sub: 'user-1',
      nonce: NONCE,
    });
    inst.setTokenResponse({ access_token: 'access-abc', id_token: wrongIssuer });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({ params: { code: 'auth-code', state: 'state-1' }, stored }),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('rejects an id_token with the wrong audience', async () => {
    const inst = await fakeInstance();
    const wrongAud = await inst.signIdToken({
      iss: ISSUER,
      aud: 'someone-else',
      sub: 'user-1',
      nonce: NONCE,
    });
    inst.setTokenResponse({ access_token: 'access-abc', id_token: wrongAud });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({ params: { code: 'auth-code', state: 'state-1' }, stored }),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('rejects an id_token signed by a key the JWKS does not advertise', async () => {
    const inst = await fakeInstance();
    // Signed with a foreign keypair; the JWKS only advertises the real key, so the
    // signature must fail to verify. A regression that skipped the signature check
    // would let this token through.
    const forged = await inst.foreignIdToken({
      iss: ISSUER,
      aud: 'client-abc',
      sub: 'user-1',
      nonce: NONCE,
    });
    inst.setTokenResponse({ access_token: 'access-abc', id_token: forged });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({ params: { code: 'auth-code', state: 'state-1' }, stored }),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('rejects an id_token whose payload was tampered after signing', async () => {
    const inst = await fakeInstance();
    const valid = await inst.signIdToken({
      iss: ISSUER,
      aud: 'client-abc',
      sub: 'user-1',
      nonce: NONCE,
    });
    // Escalate the subject but re-attach the ORIGINAL signature — verification must reject.
    const [header, payload, signature] = valid.split('.');
    const decoded = JSON.parse(Buffer.from(payload!, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    decoded['sub'] = 'attacker';
    const tampered = `${header}.${Buffer.from(JSON.stringify(decoded)).toString('base64url')}.${signature}`;
    inst.setTokenResponse({ access_token: 'access-abc', id_token: tampered });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({ params: { code: 'auth-code', state: 'state-1' }, stored }),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('rejects an expired id_token', async () => {
    const inst = await fakeInstance();
    const past = Math.floor(Date.now() / 1000) - 60;
    const expired = await inst.signIdToken(
      { iss: ISSUER, aud: 'client-abc', sub: 'user-1', nonce: NONCE },
      { expiresAt: past, issuedAt: past - 300 },
    );
    inst.setTokenResponse({ access_token: 'access-abc', id_token: expired });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({ params: { code: 'auth-code', state: 'state-1' }, stored }),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });
});

describe('refresh', () => {
  it('exchanges a refresh token for rotated tokens', async () => {
    const inst = await fakeInstance();
    inst.setTokenResponse({
      access_token: 'access-2',
      refresh_token: 'refresh-2',
      expires_in: 3600,
      token_type: 'Bearer',
      scope: 'openid offline_access',
    });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const tokens = await client.refresh('refresh-abc');

    expect(tokens.accessToken).toBe('access-2');
    expect(tokens.refreshToken).toBe('refresh-2');
    expect(tokens.expiresIn).toBe(3600);
    expect(tokens.scope).toBe('openid offline_access');
  });
});

describe('back-channel calls', () => {
  it('mints a machine (client-credentials) token', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const token = await client.machineToken({ scopes: ['reports.read'], resource: 'https://api.test' });
    expect(token).toBe('machine-token');
  });

  it('introspects a token', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const result = await client.introspect('some-token');
    expect(result['active']).toBe(true);
  });

  it('revokes a token with confidential-client auth and the type hint (RFC 7009)', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(client.revoke('refresh-abc', 'refresh_token')).resolves.toBeUndefined();

    const sent = inst.revocation();
    expect(sent?.url).toBe(`${ISSUER}/oauth/revoke`);
    expect(sent?.authorization).toBe(`Basic ${btoa('client-abc:secret-xyz')}`);
    expect(sent?.body.get('token')).toBe('refresh-abc');
    expect(sent?.body.get('token_type_hint')).toBe('refresh_token');
  });

  it('omits token_type_hint when none is given', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await client.revoke('access-abc');

    expect(inst.revocation()?.body.has('token_type_hint')).toBe(false);
  });

  /**
   * The clients that most need revocation were the ones that could not call it.
   *
   * A PKCE browser or native app authenticates with `none` and holds no secret — and it
   * is exactly the case where a refresh token sits in storage on a device somebody has
   * just signed out of. This threw `ConfigurationError` before reaching the network, so
   * every such sign-out left the token valid for its whole lifetime.
   *
   * The server opened this on 2026-08-12 (`authenticate()`, not
   * `authenticateConfidential()`), and its discovery document advertises `none` among the
   * revocation auth methods. The assertion this replaces was written on 2026-07-25 and
   * described the world before that. RFC 7009 §2.1 scopes a revocation to the calling
   * client, so the only capability is destroying a token you already hold.
   */
  it('revokes for a public client, naming itself in the body instead of a Basic header', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const { clientSecret: _omitted, ...publicConfig } = baseConfig;
    const client = new CboxIdClient(publicConfig);

    await expect(client.revoke('refresh-abc', 'refresh_token')).resolves.toBeUndefined();

    const sent = inst.revocation();
    expect(sent?.url).toBe(`${ISSUER}/oauth/revoke`);
    // No secret to put in one, and inventing an empty Basic header would authenticate
    // as a confidential client with a blank password — which the server must refuse.
    expect(sent?.authorization).toBeNull();
    expect(sent?.body.get('client_id')).toBe('client-abc');
    expect(sent?.body.get('token')).toBe('refresh-abc');
  });

  /**
   * The RFC 6749 §5.2 code survives the boundary.
   *
   * Every back-channel failure collapsed into one message string, and the two that matter
   * most demand opposite responses: `invalid_grant` on a refresh means the session is over
   * and the person must sign in again; a 503 means the same token is still good shortly.
   * A caller left matching on prose either retries what can never succeed or signs out
   * somebody who did not need to be.
   */
  it('carries the OAuth error code and description off a failed refresh', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    inst.failNextToken({ error: 'invalid_grant', error_description: 'Refresh token was revoked.' }, 400);

    const client = new CboxIdClient(baseConfig);

    await expect(client.refresh('spent-token')).rejects.toMatchObject({
      error: 'invalid_grant',
      errorDescription: 'Refresh token was revoked.',
      status: 400,
    });
  });

  it('does not invent an error code when the body is not an OAuth error', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    // A proxy or captive portal answering HTML — the caller still needs an error rather
    // than a parse exception, and `e.error === 'invalid_grant'` must stay false.
    inst.failNextToken('<html>502 Bad Gateway</html>', 502);

    const client = new CboxIdClient(baseConfig);

    await expect(client.refresh('some-token')).rejects.toMatchObject({
      error: undefined,
      status: 502,
    });
  });
});

describe('hosted profile & logout', () => {
  it('builds the profile URL with and without return_to', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    // `/account`, not `/settings`. The latter is the organization-admin page: it
    // redirects a non-admin to `/account` and drops `return_to` on the way, so the
    // link worked for admins and silently lost the return path for everyone else.
    // Pinned, because the wrong default reads perfectly plausible.
    expect(client.profileUrl()).toBe(`${ISSUER}/account`);
    expect(client.profileUrl('https://app.test/home')).toBe(
      `${ISSUER}/account?return_to=https%3A%2F%2Fapp.test%2Fhome`,
    );
  });

  // The OP validates post_logout_redirect_uri against the requesting client's
  // registered allow-list, so a logout URL WITHOUT client_id can never redirect —
  // it strands the user on a bare "signed out" page. Assert on the parsed params
  // so a regression that drops client_id fails loudly.
  it('always carries client_id on the RP-initiated logout URL', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const url = new URL((await client.logoutUrl('https://app.test')) as string);
    expect(`${url.origin}${url.pathname}`).toBe(`${ISSUER}/oauth/logout`);
    expect(url.searchParams.get('client_id')).toBe('client-abc');
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe('https://app.test');
    expect(url.searchParams.get('id_token_hint')).toBeNull();

    const bare = new URL((await client.logoutUrl()) as string);
    expect(bare.searchParams.get('client_id')).toBe('client-abc');
    expect(bare.searchParams.get('post_logout_redirect_uri')).toBeNull();
  });

  it('passes an id_token_hint when one is supplied', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const url = new URL((await client.logoutUrl('https://app.test', 'header.payload.sig')) as string);
    expect(url.searchParams.get('id_token_hint')).toBe('header.payload.sig');
    expect(url.searchParams.get('client_id')).toBe('client-abc');
  });
});

/**
 * A 429 is the ONLY back-channel failure where the same request succeeds unchanged if you
 * wait — every other one needs a different request or a new sign-in. The limiter says how
 * long, and the SDK dropped the header, so a caller with a retry loop hammered a server
 * that was already telling it to stop.
 */
describe('rate limiting', () => {
  it('carries Retry-After off a 429 so a caller can back off for the stated time', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    inst.failNextToken({ message: 'Too Many Requests' }, 429, { 'retry-after': '42' });

    const client = new CboxIdClient(baseConfig);

    await expect(client.refresh('some-token')).rejects.toMatchObject({
      status: 429,
      retryAfter: 42,
      isRateLimited: true,
    });
  });

  it('leaves retryAfter unset when the header is an HTTP-date rather than seconds', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    // Legal per RFC 9110 and deliberately not parsed: guessing at clock skew is worse
    // than saying nothing, and `isRateLimited` still tells the caller to back off.
    inst.failNextToken({ message: 'slow down' }, 429, { 'retry-after': 'Wed, 21 Oct 2026 07:28:00 GMT' });

    const client = new CboxIdClient(baseConfig);

    await expect(client.refresh('some-token')).rejects.toMatchObject({
      status: 429,
      retryAfter: undefined,
      isRateLimited: true,
    });
  });
});

/**
 * OIDC Core §5.3.2 — the UserInfo response is bound to the id_token, or it is not used.
 *
 * UserInfo is fetched with a bearer token and its body carries no signature. The SDK
 * spread it OVER the verified claims, so whatever it returned won: `sub`, `org`, and
 * every other claim the id_token's signature covered. Nothing tested it, and the sibling
 * `cboxdk/laravel-id-client` had checked this from the start — so the two SDKs disagreed
 * about who the user is.
 */
describe('UserInfo is bound to the verified id_token', () => {
  const stored = { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE };

  it('refuses a UserInfo response naming a different subject', async () => {
    // The whole attack in one line: the signed token says user-1, the unsigned body says
    // somebody else, and the SDK used to believe the body.
    const inst = await fakeInstance({ userinfo: { sub: 'victim-9', email: 'victim@acme.com' } });
    vi.stubGlobal('fetch', inst.fetchMock);

    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({ params: { code: 'auth-code', state: 'state-1' }, stored }),
    ).rejects.toThrow(/UserInfo subject does not match/i);
  });

  it('lets UserInfo enrich but never override a signed claim', async () => {
    // `org` is an authorization claim: whoever sets it decides which tenant this session
    // belongs to. The id_token says org-1; UserInfo tries to say org-admin.
    const inst = await fakeInstance({
      userinfo: { sub: 'user-1', email: 'ada@acme.com', name: 'Ada', org: 'org-admin', title: 'Engineer' },
    });
    vi.stubGlobal('fetch', inst.fetchMock);

    const user = await new CboxIdClient(baseConfig).authenticate({
      params: { code: 'auth-code', state: 'state-1' },
      stored,
    });

    expect(user.organizationId).toBe('org-1');
    // …and the enrichment still happens, which is why the merge exists at all.
    expect(user.claims['title']).toBe('Engineer');
  });

  it('refuses an openid login that came back without an id_token', async () => {
    // Identity would otherwise come from UserInfo alone — a bearer-authenticated endpoint
    // whose response nothing signed — and the stored nonce would never be used.
    const inst = await fakeInstance();
    inst.setTokenResponse({ access_token: 'access-abc', expires_in: 3600, token_type: 'Bearer' });
    vi.stubGlobal('fetch', inst.fetchMock);

    await expect(
      new CboxIdClient(baseConfig).authenticate({
        params: { code: 'auth-code', state: 'state-1' },
        stored: { ...stored, scopes: ['openid', 'email'] },
      }),
    ).rejects.toThrow(/no id_token/i);
  });

  it('allows a non-openid flow to complete without an id_token', async () => {
    // The other side of the rule: a caller who never asked for `openid` is running an
    // OAuth flow and must not be held to an OIDC requirement.
    const inst = await fakeInstance();
    inst.setTokenResponse({ access_token: 'access-abc', expires_in: 3600, token_type: 'Bearer' });
    vi.stubGlobal('fetch', inst.fetchMock);

    const user = await new CboxIdClient(baseConfig).authenticate({
      params: { code: 'auth-code', state: 'state-1' },
      stored: { ...stored, scopes: ['api.read'] },
    });

    expect(user.id).toBe('user-1');
  });
});

/**
 * Findings from the second security pass, each of which the suite could not see.
 */
describe('transport and document trust', () => {
  const stored = { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE };

  it('refuses a plaintext issuer', () => {
    // Everything this SDK sends the issuer carries a credential — the code, the PKCE
    // verifier, the client secret, the refresh token. Over http a network attacker reads
    // all of them AND replaces the discovery document and JWKS, after which a forged
    // id_token verifies cleanly and the whole verification chain proves nothing.
    expect(() => new CboxIdClient({ ...baseConfig, issuer: 'http://id.acme.com' })).toThrow(
      /must be https/i,
    );
  });

  it('allows plaintext loopback, which is what a native app and a dev instance use', () => {
    // RFC 8252: a native app's own callback listener is loopback by definition.
    expect(() => new CboxIdClient({ ...baseConfig, issuer: 'http://127.0.0.1:8000' })).not.toThrow();
    expect(() => new CboxIdClient({ ...baseConfig, issuer: 'http://localhost:8000' })).not.toThrow();
  });

  it('refuses a discovery document issued for a different issuer', async () => {
    const inst = await fakeInstance();
    // The same host answering with another tenant's document: RFC 8414 §3.3 says the
    // `issuer` inside MUST match the one it was fetched for. Without the check the SDK
    // sends credentials to that tenant's endpoints and verifies against its JWKS, while
    // the caller still believes it is talking to the issuer it configured.
    const original = inst.fetchMock;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: unknown, init?: RequestInit): Promise<Response> => {
        if (String(input).endsWith('/.well-known/openid-configuration')) {
          return new Response(JSON.stringify({ ...discovery, issuer: 'https://someone-else.test' }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }
        return (original as unknown as typeof fetch)(input as RequestInfo, init);
      }),
    );

    await expect(
      new CboxIdClient(baseConfig).authenticate({
        params: { code: 'auth-code', state: 'state-1' },
        stored,
      }),
    ).rejects.toThrow(/different issuer/i);
  });

  it('verifies the id_token a refresh returns, instead of handing it back unchecked', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    // A token signed by the wrong key, presenting the advertised kid. An application that
    // updates its session claims from refresh().idToken used to accept this.
    inst.setTokenResponse({
      access_token: 'access-abc',
      id_token: await inst.foreignIdToken({ iss: ISSUER, aud: 'client-abc', sub: 'user-1' }),
      expires_in: 3600,
      token_type: 'Bearer',
    });

    await expect(new CboxIdClient(baseConfig).refresh('refresh-abc')).rejects.toThrow(
      /id_token could not be verified/i,
    );
  });

  it('does not echo a failed response body, which carries the credentials it was sent', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    // A debug proxy or upstream error page that reflects the request it received. The
    // request body for this call holds client_secret and the refresh token.
    inst.failNextToken('client_secret=csec_REALSECRET&refresh_token=rt_REALTOKEN', 502);

    await expect(new CboxIdClient(baseConfig).refresh('rt_REALTOKEN')).rejects.toSatisfy(
      (e: Error) => !e.message.includes('csec_REALSECRET') && !e.message.includes('rt_REALTOKEN'),
    );
  });
});
