import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthenticationError, CboxIdClient } from '../src/index.js';
import { fakeInstance, ISSUER, NONCE } from './helpers.js';

const baseConfig = {
  issuer: ISSUER,
  clientId: 'client-abc',
  clientSecret: 'secret-xyz',
  redirectUri: 'https://app.test/auth/callback',
};

const now = (): number => Math.floor(Date.now() / 1000);

afterEach(() => {
  vi.unstubAllGlobals();
});

/**
 * `max_age` is the control an RP reaches for before a payment or an admin grant: it
 * says "I will only accept an authentication newer than this". The SDK sent the
 * parameter and then never looked at the `auth_time` that came back — so a code minted
 * from a day-old session, carrying its ORIGINAL auth_time, was accepted in silence and
 * the application believed the user had just re-authenticated.
 *
 * OIDC Core §3.1.3.7 step 12 makes the check the relying party's job.
 */
describe('max_age enforcement', () => {
  it('carries the requested maxAge back on the authorization request', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const req = await client.createAuthorizationRequest({ maxAge: 0 });

    expect(new URL(req.url).searchParams.get('max_age')).toBe('0');
    // Round-trips like the nonce — a requirement the callback cannot see is no
    // requirement at all.
    expect(req.maxAge).toBe(0);
  });

  it('leaves maxAge unset when none was requested', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const req = await client.createAuthorizationRequest();

    expect(req.maxAge).toBeUndefined();
    expect(new URL(req.url).searchParams.has('max_age')).toBe(false);
  });

  it('rejects an id_token whose auth_time is older than the requested max_age', async () => {
    const inst = await fakeInstance();
    inst.setTokenResponse({
      access_token: 'access-abc',
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: await inst.signIdToken({
        iss: ISSUER,
        aud: 'client-abc',
        sub: 'user-1',
        nonce: NONCE,
        // Signed in yesterday: exactly the case the server used to hand back unchanged.
        auth_time: now() - 86_400,
      }),
    });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({
        params: { code: 'auth-code', state: 'state-1' },
        stored: { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE, maxAge: 0 },
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('accepts an id_token whose auth_time is within the requested max_age', async () => {
    const inst = await fakeInstance();
    inst.setTokenResponse({
      access_token: 'access-abc',
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: await inst.signIdToken({
        iss: ISSUER,
        aud: 'client-abc',
        sub: 'user-1',
        nonce: NONCE,
        auth_time: now() - 120,
      }),
    });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const user = await client.authenticate({
      params: { code: 'auth-code', state: 'state-1' },
      stored: { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE, maxAge: 300 },
    });

    expect(user.id).toBe('user-1');
  });

  /**
   * A just-completed re-authentication is already several seconds old by the time the
   * redirect and the token exchange are done, so `maxAge: 0` must not reject the very
   * step-up it forced.
   */
  it('tolerates the round-trip delay on a max_age of zero', async () => {
    const inst = await fakeInstance();
    inst.setTokenResponse({
      access_token: 'access-abc',
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: await inst.signIdToken({
        iss: ISSUER,
        aud: 'client-abc',
        sub: 'user-1',
        nonce: NONCE,
        auth_time: now() - 5,
      }),
    });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const user = await client.authenticate({
      params: { code: 'auth-code', state: 'state-1' },
      stored: { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE, maxAge: 0 },
    });

    expect(user.id).toBe('user-1');
  });

  it('honours a configured auth-time tolerance', async () => {
    const inst = await fakeInstance();
    inst.setTokenResponse({
      access_token: 'access-abc',
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: await inst.signIdToken({
        iss: ISSUER,
        aud: 'client-abc',
        sub: 'user-1',
        nonce: NONCE,
        auth_time: now() - 30,
      }),
    });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient({ ...baseConfig, authTimeToleranceSeconds: 5 });

    await expect(
      client.authenticate({
        params: { code: 'auth-code', state: 'state-1' },
        stored: { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE, maxAge: 0 },
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('refuses an id_token that carries no auth_time at all when max_age was demanded', async () => {
    const inst = await fakeInstance();
    inst.setTokenResponse({
      access_token: 'access-abc',
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: await inst.signIdToken({ iss: ISSUER, aud: 'client-abc', sub: 'user-1', nonce: NONCE }),
    });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    await expect(
      client.authenticate({
        params: { code: 'auth-code', state: 'state-1' },
        stored: { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE, maxAge: 60 },
      }),
    ).rejects.toThrow(/auth_time/);
  });

  it('refuses a token response with no id_token when max_age was demanded', async () => {
    const inst = await fakeInstance();
    inst.setTokenResponse({ access_token: 'access-abc', token_type: 'Bearer', expires_in: 3600 });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    // No id_token means no auth_time, and therefore no evidence the demanded
    // re-authentication happened.
    await expect(
      client.authenticate({
        params: { code: 'auth-code', state: 'state-1' },
        stored: { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE, maxAge: 60 },
      }),
    ).rejects.toThrow(AuthenticationError);
  });

  it('ignores auth_time entirely when no max_age was requested', async () => {
    const inst = await fakeInstance();
    inst.setTokenResponse({
      access_token: 'access-abc',
      token_type: 'Bearer',
      expires_in: 3600,
      id_token: await inst.signIdToken({
        iss: ISSUER,
        aud: 'client-abc',
        sub: 'user-1',
        nonce: NONCE,
        auth_time: now() - 86_400,
      }),
    });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient(baseConfig);

    const user = await client.authenticate({
      params: { code: 'auth-code', state: 'state-1' },
      stored: { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE },
    });

    expect(user.id).toBe('user-1');
  });
});
