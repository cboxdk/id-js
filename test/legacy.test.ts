import { describe, expect, it, vi } from 'vitest';

import { createLegacyVerifier } from '../src/legacy.js';
import { ConfigurationError } from '../src/errors.js';

const SECRET = 'a-secret-that-is-long-enough-to-mean-something';

async function sign(body: string, secret = SECRET, timestamp = Math.floor(Date.now() / 1000)) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${body}`));
  const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');

  return `t=${timestamp},v1=${hex}`;
}

function request(body: string, signature?: string): Request {
  return new Request('https://acme.test/cbox-legacy', {
    method: 'POST',
    body,
    headers: signature ? { 'X-Cbox-Signature': signature } : {},
  });
}

describe('createLegacyVerifier', () => {
  it('refuses a secret too short to mean anything', () => {
    expect(() => createLegacyVerifier({ secret: 'short', verify: async () => null })).toThrow(ConfigurationError);
  });

  it('answers with the person when the credentials are good', async () => {
    const handler = createLegacyVerifier({
      secret: SECRET,
      verify: async () => ({ email: 'ada@acme.test', name: 'Ada', emailVerified: true }),
    });

    const body = JSON.stringify({ email: 'ada@acme.test', password: 'pw' });
    const response = await handler(request(body, await sign(body)));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({ email: 'ada@acme.test', email_verified: true });
  });

  /**
   * The check the whole factory exists to own. Without it every customer writes it
   * themselves, and this is the one people get wrong.
   */
  it('refuses an unsigned request, a wrongly signed one, and a stale one', async () => {
    const verify = vi.fn().mockResolvedValue({ email: 'ada@acme.test' });
    const handler = createLegacyVerifier({ secret: SECRET, verify });

    const body = JSON.stringify({ email: 'ada@acme.test', password: 'pw' });

    expect((await handler(request(body))).status).toBe(401);
    expect((await handler(request(body, await sign(body, 'a-different-secret-of-adequate-length')))).status).toBe(401);

    // Outside the freshness window: a captured request must stop working.
    const stale = await sign(body, SECRET, Math.floor(Date.now() / 1000) - 400);
    expect((await handler(request(body, stale))).status).toBe(401);

    // Never reached the customer's code — the point of checking first.
    expect(verify).not.toHaveBeenCalled();
  });

  /**
   * The signature covers the RAW body. Re-serializing parsed JSON produces different
   * bytes and would refuse every valid request — a mistake that looks like a broken
   * secret and takes a day to find.
   */
  it('verifies against the exact bytes it was sent', async () => {
    const handler = createLegacyVerifier({ secret: SECRET, verify: async () => ({ email: 'ada@acme.test' }) });

    // Deliberately unusual spacing: a re-serialize would normalise it away.
    const body = '{"email":"ada@acme.test",  "password":"pw"}';

    expect((await handler(request(body, await sign(body)))).status).toBe(200);
  });

  it('says no without ceremony when the password is wrong', async () => {
    const handler = createLegacyVerifier({ secret: SECRET, verify: async () => null });

    const body = JSON.stringify({ email: 'ada@acme.test', password: 'wrong' });
    const response = await handler(request(body, await sign(body)));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ user: null });
  });

  /**
   * A throw means the store could not DECIDE, which is not the same as a wrong password —
   * and Cbox ID must be able to tell them apart in its own logs.
   */
  it('answers 503 when the customer store throws, not 401', async () => {
    const handler = createLegacyVerifier({
      secret: SECRET,
      verify: async () => {
        throw new Error('database is down');
      },
    });

    const body = JSON.stringify({ email: 'ada@acme.test', password: 'pw' });

    expect((await handler(request(body, await sign(body)))).status).toBe(503);
  });

  it('answers a password-less probe without consulting the store', async () => {
    const verify = vi.fn();
    const handler = createLegacyVerifier({ secret: SECRET, verify });

    const body = JSON.stringify({ email: 'ada@acme.test' });
    const response = await handler(request(body, await sign(body)));

    expect(response.status).toBe(200);
    expect(verify).not.toHaveBeenCalled();
  });

  it('passes a stored hash through when the customer can expose one', async () => {
    const handler = createLegacyVerifier({
      secret: SECRET,
      verify: async () => ({ email: 'ada@acme.test', passwordHash: '$2y$10$abcdefghijklmnopqrstuv' }),
    });

    const body = JSON.stringify({ email: 'ada@acme.test', password: 'pw' });
    const response = await handler(request(body, await sign(body)));

    await expect(response.json()).resolves.toMatchObject({ password_hash: '$2y$10$abcdefghijklmnopqrstuv' });
  });
});
