import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthenticationError, CboxIdClient, ConfigurationError, hasPermission, organization } from '../src/index.js';
import { ApiKeyVerifier, type ApiKeyVerification } from '../src/server.js';
import * as mainEntry from '../src/index.js';
import { ISSUER } from './helpers.js';

const config = { issuer: ISSUER, clientId: 'client-abc', clientSecret: 'secret-xyz' };
const ENDPOINT = `${ISSUER}/oauth/api-keys/verify`;

const live = {
  active: true,
  key_id: 'key_01',
  sub: 'user-1',
  org: 'org-acme',
  org_role: 'admin',
  permissions: ['invoices:read', 'invoices:create'],
  client_id: 'client-abc',
  expires_at: null as string | null,
};

function answer(body: unknown, status = 200) {
  const calls: { url: string; init: RequestInit }[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: unknown, init?: RequestInit) => {
      calls.push({ url: String(input), init: init ?? {} });
      return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
    }),
  );
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('ApiKeyVerifier.verifyApiKey', () => {
  it('posts the key with HTTP Basic client auth and returns the typed answer', async () => {
    const calls = answer(live);

    const result = await new ApiKeyVerifier(config).verifyApiKey('ctx_live_abc');

    expect(result).toEqual(live);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(ENDPOINT);
    expect(calls[0]!.init.method).toBe('POST');
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers.authorization).toBe(`Basic ${btoa('client-abc:secret-xyz')}`);
    expect(headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(new URLSearchParams(String(calls[0]!.init.body)).get('key')).toBe('ctx_live_abc');
    // The secret travels in the header only, never the body.
    expect(String(calls[0]!.init.body)).not.toContain('secret-xyz');
  });

  it('reads like a token to the claim helpers', async () => {
    answer(live);
    const result = await new ApiKeyVerifier(config).verifyApiKey('ctx_live_abc');

    expect(result.active && hasPermission(result, 'invoices:create')).toBe(true);
    expect(result.active && hasPermission(result, 'invoices:refund')).toBe(false);
    expect(result.active ? organization(result) : null).toEqual({ id: 'org-acme', name: null, role: 'admin' });
  });

  it('passes a refusal through as exactly { active: false }', async () => {
    answer({ active: false });

    await expect(new ApiKeyVerifier(config).verifyApiKey('ctx_live_revoked')).resolves.toEqual({ active: false });
  });

  it('lets only a literal true in', async () => {
    answer({ ...live, active: 'true' });

    await expect(new ApiKeyVerifier(config).verifyApiKey('ctx_live_abc')).resolves.toEqual({ active: false });
  });

  it('does not ask about an empty key', async () => {
    const calls = answer(live);

    await expect(new ApiKeyVerifier(config).verifyApiKey('  ')).resolves.toEqual({ active: false });
    expect(calls).toHaveLength(0);
  });

  it("refuses an answer for another app's client_id", async () => {
    answer({ ...live, client_id: 'client-other' });

    await expect(new ApiKeyVerifier(config).verifyApiKey('ctx_live_abc')).rejects.toThrow(
      'API key verification answered for client client-other, not this app (client-abc); refusing it.',
    );
  });

  it('refuses an active answer without the promised fields', async () => {
    answer({ active: true, permissions: ['invoices:read'], client_id: 'client-abc' });

    await expect(new ApiKeyVerifier(config).verifyApiKey('ctx_live_abc')).rejects.toThrow(
      'API key verification returned an active answer without the promised fields.',
    );
  });

  it('treats a key already past its expires_at as inactive', async () => {
    answer({ ...live, expires_at: new Date(Date.now() - 1_000).toISOString() });

    await expect(new ApiKeyVerifier(config).verifyApiKey('ctx_live_abc')).resolves.toEqual({ active: false });
  });

  it('reads an unknown org_role as null, never a guessed tier', async () => {
    answer({ ...live, org_role: 'superuser' });

    const result = (await new ApiKeyVerifier(config).verifyApiKey('ctx_live_abc')) as ApiKeyVerification & { org_role: unknown };
    expect(result.org_role).toBeNull();
  });

  it('throws on bad client credentials, with the server code', async () => {
    answer({ error: 'invalid_client' }, 401);

    const failure = await new ApiKeyVerifier(config).verifyApiKey('ctx_live_abc').catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(AuthenticationError);
    expect((failure as AuthenticationError).error).toBe('invalid_client');
  });
});

describe('the cache', () => {
  it('is off by default', async () => {
    const calls = answer(live);
    const keys = new ApiKeyVerifier(config);

    await keys.verifyApiKey('ctx_live_abc');
    await keys.verifyApiKey('ctx_live_abc');

    expect(calls).toHaveLength(2);
  });

  it('serves an active answer for cacheTtlMs, then asks again', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const calls = answer(live);
    const keys = new ApiKeyVerifier({ ...config, cacheTtlMs: 10_000 });

    await keys.verifyApiKey('ctx_live_abc');
    vi.setSystemTime(Date.now() + 9_000);
    await keys.verifyApiKey('ctx_live_abc');
    expect(calls).toHaveLength(1);

    vi.setSystemTime(Date.now() + 2_000);
    await keys.verifyApiKey('ctx_live_abc');
    expect(calls).toHaveLength(2);
  });

  it('never serves an answer past the key expiry', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const now = Date.now();
    const calls = answer({ ...live, expires_at: new Date(now + 3_000).toISOString() });
    const keys = new ApiKeyVerifier({ ...config, cacheTtlMs: 60_000 });

    await keys.verifyApiKey('ctx_live_abc');
    vi.setSystemTime(now + 4_000);
    // Past expiry: not from the cache, and the fresh (same) answer is itself expired.
    await expect(keys.verifyApiKey('ctx_live_abc')).resolves.toEqual({ active: false });
    expect(calls).toHaveLength(2);
  });

  it('never caches a refusal, so a key issued a moment later works at once', async () => {
    const calls = answer({ active: false });
    const keys = new ApiKeyVerifier({ ...config, cacheTtlMs: 60_000 });

    await keys.verifyApiKey('ctx_live_new');
    answer(live);
    await expect(keys.verifyApiKey('ctx_live_new')).resolves.toMatchObject({ active: true });
    expect(calls).toHaveLength(1);
  });

  it('refuses a cache long enough to keep revoked keys alive', () => {
    expect(() => new ApiKeyVerifier({ ...config, cacheTtlMs: 60_001 })).toThrowError(
      'cacheTtlMs must be between 0 and 60000: a cached answer keeps a revoked key working for that long.',
    );
  });
});

describe('server-side only', () => {
  it('refuses to be built in a browser', () => {
    vi.stubGlobal('document', {});

    expect(() => new ApiKeyVerifier(config)).toThrowError(
      'API key verification uses your client secret and must run on your server, never in a browser.',
    );
  });

  it('needs the client secret', () => {
    expect(() => new ApiKeyVerifier({ ...config, clientSecret: '' })).toThrowError(ConfigurationError);
  });

  it('is not exported from the main entry a browser bundle pulls in', () => {
    expect(Object.keys(mainEntry)).not.toContain('ApiKeyVerifier');
    expect(Object.keys(mainEntry).some((name) => /apikey/i.test(name) && name !== 'apiKeysUrl')).toBe(false);
  });
});

describe('apiKeysUrl', () => {
  const client = new CboxIdClient({ issuer: ISSUER, clientId: 'client-abc', redirectUri: 'https://app.test/cb' });

  it('links to the hosted API-keys page for this app', () => {
    expect(client.apiKeysUrl()).toBe(`${ISSUER}/account/api-keys?client_id=client-abc`);
  });

  it('carries return_to, organization and another client when given', () => {
    const url = new URL(
      client.apiKeysUrl({ clientId: 'client-api', returnTo: 'https://app.test/settings', organization: 'org-acme' }),
    );

    expect(`${url.origin}${url.pathname}`).toBe(`${ISSUER}/account/api-keys`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: 'client-api',
      return_to: 'https://app.test/settings',
      organization: 'org-acme',
    });
  });
});

describe('Next.js adapter', () => {
  it('verifies with the adapter credentials and links to the API-keys page', async () => {
    const { createCboxId } = await import('../src/nextjs.js');
    const cboxId = createCboxId({ ...config, redirectUri: 'https://app.test/cb' });
    const calls = answer(live);

    await expect(cboxId.verifyApiKey('ctx_live_abc')).resolves.toEqual(live);
    expect((calls[0]!.init.headers as Record<string, string>).authorization).toBe(
      `Basic ${btoa('client-abc:secret-xyz')}`,
    );
    expect(cboxId.apiKeysUrl({ returnTo: 'https://app.test/' })).toBe(
      `${ISSUER}/account/api-keys?client_id=client-abc&return_to=https%3A%2F%2Fapp.test%2F`,
    );
  });

  it('needs a client secret only when a key is verified', async () => {
    const { createCboxId } = await import('../src/nextjs.js');
    vi.stubEnv('CBOX_ID_CLIENT_SECRET', '');
    const cboxId = createCboxId({ issuer: ISSUER, clientId: 'client-abc', redirectUri: 'https://app.test/cb' });

    expect(() => cboxId.verifyApiKey('ctx_live_abc')).toThrowError(
      'Verifying API keys needs issuer, clientId and clientSecret.',
    );
    vi.unstubAllEnvs();
  });
});
