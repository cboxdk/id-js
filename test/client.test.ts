import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AuthenticationError,
  CboxIdClient,
  ConfigurationError,
  InvalidStateError,
} from '../src/index.js';
import { challenge } from '../src/pkce.js';
import { fakeInstance, ISSUER, NONCE } from './helpers.js';

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

  it('refuses to revoke without a client secret', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const { clientSecret: _omitted, ...publicConfig } = baseConfig;
    const client = new CboxIdClient(publicConfig);

    await expect(client.revoke('some-token')).rejects.toBeInstanceOf(ConfigurationError);
  });
});

describe('hosted profile & logout', () => {
  it('builds the profile URL with and without return_to', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    expect(client.profileUrl()).toBe(`${ISSUER}/settings`);
    expect(client.profileUrl('https://app.test/home')).toBe(
      `${ISSUER}/settings?return_to=https%3A%2F%2Fapp.test%2Fhome`,
    );
  });

  it('returns the RP-initiated logout URL from discovery', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    expect(await client.logoutUrl('https://app.test')).toBe(
      `${ISSUER}/oauth/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.test`,
    );
  });
});
