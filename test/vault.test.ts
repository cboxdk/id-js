import { afterEach, describe, expect, it, vi } from 'vitest';
import { VaultClient } from '../src/index.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

function fetchMock(handler: (url: string, init: RequestInit) => Response) {
  return vi.fn(async (input: unknown, init?: RequestInit) =>
    handler(String(input), init ?? {}),
  );
}

const ISSUER = 'https://id.test';

describe('VaultClient', () => {
  it('stores a secret and sends a bearer token', async () => {
    const mock = fetchMock((url, init) => {
      expect(url).toBe(`${ISSUER}/api/v1/vault/secrets`);
      expect(init.method).toBe('POST');
      expect((init.headers as Record<string, string>).authorization).toBe('Bearer tok');
      return new Response(
        JSON.stringify({ id: 's1', name: 'openai', provider: 'openai', ownerType: null, ownerId: null, expiresAt: null, revoked: false }),
        { status: 201, headers: { 'content-type': 'application/json' } },
      );
    });
    vi.stubGlobal('fetch', mock);

    const vault = new VaultClient(ISSUER, 'tok');
    const ref = await vault.store({ name: 'openai', provider: 'openai', secret: 'sk-x' });

    expect(ref.id).toBe('s1');
    expect(ref.provider).toBe('openai');
    const sent = JSON.parse(String(mock.mock.calls[0]![1]!.body)) as Record<string, unknown>;
    expect(sent.secret).toBe('sk-x');
  });

  it('leases a secret and maps the snake_case response', async () => {
    const mock = fetchMock((url) => {
      expect(url).toBe(`${ISSUER}/api/v1/vault/secrets/s1/lease`);
      return new Response(
        JSON.stringify({ secret_id: 's1', provider: 'openai', secret: 'sk-live', expires_at: '2026-01-01T00:00:00Z' }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });
    vi.stubGlobal('fetch', mock);

    const lease = await new VaultClient(ISSUER, 'tok').lease('s1', 'call openai');
    expect(lease.secret).toBe('sk-live');
    expect(lease.provider).toBe('openai');
    expect(lease.expiresAt).toBe('2026-01-01T00:00:00Z');
  });

  it('throws on a denied lease', async () => {
    vi.stubGlobal('fetch', fetchMock(() => new Response(JSON.stringify({ error: 'lease_denied' }), { status: 403 })));
    await expect(new VaultClient(ISSUER, 'tok').lease('s1', 'x')).rejects.toThrowError(/403/);
  });
});
