import { afterEach, describe, expect, it, vi } from 'vitest';
import { CboxIdClient, FEATURE_FLAGS_SCOPE, featureFlags, hasFeature } from '../src/index.js';
import { fakeInstance, ISSUER, NONCE } from './helpers.js';

const baseConfig = {
  issuer: ISSUER,
  clientId: 'client-abc',
  clientSecret: 'secret-xyz',
  redirectUri: 'https://app.test/auth/callback',
};

const stored = { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('feature flags on the signed-in user', () => {
  it('maps the feature_flags claim and answers hasFeature', async () => {
    const inst = await fakeInstance({ userinfo: { sub: 'user-1', feature_flags: ['acme-beta', 'new-dashboard'] } });
    vi.stubGlobal('fetch', inst.fetchMock);

    const user = await new CboxIdClient(baseConfig).authenticate({ params: { code: 'c', state: 'state-1' }, stored });

    expect(user.featureFlags).toEqual(['acme-beta', 'new-dashboard']);
    expect(hasFeature(user, 'new-dashboard')).toBe(true);
    expect(hasFeature(user, 'old-reports')).toBe(false);
  });

  it('reports an absent claim as null, not as an empty list', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);

    const user = await new CboxIdClient(baseConfig).authenticate({ params: { code: 'c', state: 'state-1' }, stored });

    expect(user.featureFlags).toBeNull();
    expect(hasFeature(user, 'anything')).toBe(false);
  });

  it('requests the scope like any other', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);

    const { url } = await new CboxIdClient({ ...baseConfig, scopes: ['openid', FEATURE_FLAGS_SCOPE] }).createAuthorizationRequest();

    expect(FEATURE_FLAGS_SCOPE).toBe('feature_flags');
    expect(new URL(url).searchParams.get('scope')).toBe('openid feature_flags');
  });
});

describe('feature flag helpers on a raw claim set', () => {
  it('tells "not requested" from "nothing on"', () => {
    expect(featureFlags({})).toBeNull();
    expect(featureFlags({ feature_flags: [] })).toEqual([]);
    expect(hasFeature({ feature_flags: [] }, 'x')).toBe(false);
  });

  it('drops anything that is not a key, and matches exactly', () => {
    const payload = { feature_flags: ['billing.v2', 7, '', null] };

    expect(featureFlags(payload)).toEqual(['billing.v2']);
    expect(hasFeature(payload, 'billing.v2')).toBe(true);
    expect(hasFeature(payload, 'billing')).toBe(false);
  });

  it('treats a malformed claim as absent — every feature off, never on', () => {
    expect(featureFlags({ feature_flags: 'new-dashboard' })).toBeNull();
    expect(hasFeature({ feature_flags: 'new-dashboard' }, 'new-dashboard')).toBe(false);
  });
});
