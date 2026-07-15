import { describe, expect, it } from 'vitest';
import { verifyWebhook } from '../src/webhook.js';

const secret = 'whsec_test';
const payload = '{"event":"user.updated","id":"user-1"}';

async function sign(timestamp: number, body: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${body}`));
  const hex = Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `t=${timestamp},v1=${hex}`;
}

describe('verifyWebhook', () => {
  const now = 1_700_000_000;

  it('accepts a fresh, correctly-signed payload', async () => {
    const header = await sign(now, payload);
    expect(await verifyWebhook({ payload, signatureHeader: header, secret, now })).toBe(true);
  });

  it('rejects a tampered payload', async () => {
    const header = await sign(now, payload);
    expect(
      await verifyWebhook({ payload: payload + 'x', signatureHeader: header, secret, now }),
    ).toBe(false);
  });

  it('rejects the wrong secret', async () => {
    const header = await sign(now, payload);
    expect(
      await verifyWebhook({ payload, signatureHeader: header, secret: 'whsec_other', now }),
    ).toBe(false);
  });

  it('rejects a stale timestamp outside the tolerance', async () => {
    const header = await sign(now - 10_000, payload);
    expect(await verifyWebhook({ payload, signatureHeader: header, secret, now })).toBe(false);
  });

  it('rejects a missing or malformed header', async () => {
    expect(await verifyWebhook({ payload, signatureHeader: null, secret, now })).toBe(false);
    expect(await verifyWebhook({ payload, signatureHeader: 'garbage', secret, now })).toBe(false);
    expect(await verifyWebhook({ payload, signatureHeader: 't=abc,v1=xx', secret, now })).toBe(false);
  });
});
