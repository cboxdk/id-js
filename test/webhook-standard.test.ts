import { describe, expect, it } from 'vitest';
import { verifyStandardWebhook } from '../src/index.js';

// The Standard Webhooks specification's own test vector.
const secret = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
const id = 'msg_p5jXN8AQM9LWM0D4loKWxJek';
const timestamp = 1614265330;
const payload = '{"test": 2432232314}';
const signature = 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=';

function headers(sig = signature, ts = String(timestamp)): Headers {
  return new Headers({ 'webhook-id': id, 'webhook-timestamp': ts, 'webhook-signature': sig });
}

async function sign(key: Uint8Array<ArrayBuffer>, content: string): Promise<string> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return `v1,${Buffer.from(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(content))).toString('base64')}`;
}

describe('verifyStandardWebhook', () => {
  it('accepts the specification vector', async () => {
    expect(await verifyStandardWebhook({ payload, headers: headers(), secret, now: timestamp })).toBe(true);
  });

  it('reads a plain header record, and any valid signature among several', async () => {
    const record = { 'Webhook-Id': id, 'Webhook-Timestamp': String(timestamp), 'Webhook-Signature': `v1,bm9wZQ== ${signature}` };
    expect(await verifyStandardWebhook({ payload, headers: record, secret, now: timestamp })).toBe(true);
  });

  it('rejects a tampered body, a wrong secret, a stale timestamp and a missing header', async () => {
    expect(await verifyStandardWebhook({ payload: '{"test": 2432232315}', headers: headers(), secret, now: timestamp })).toBe(false);
    expect(await verifyStandardWebhook({ payload, headers: headers(), secret: 'whsec_AAAAAAAAAAAAAAAAAAAAAAAA', now: timestamp })).toBe(false);
    expect(await verifyStandardWebhook({ payload, headers: headers(), secret, now: timestamp + 301 })).toBe(false);
    expect(await verifyStandardWebhook({ payload, headers: new Headers({ 'webhook-id': id }), secret, now: timestamp })).toBe(false);
    expect(await verifyStandardWebhook({ payload, headers: headers('v2,' + signature.slice(3)), secret, now: timestamp })).toBe(false);
  });

  it('takes the 64-hex secret of an endpoint moved from the cbox scheme', async () => {
    const hex = 'a1'.repeat(32);
    // Cbox ID signs with `whsec_` + base64 of the hex string: the same bytes as the hex itself.
    const sig = await sign(new TextEncoder().encode(hex), `${id}.${timestamp}.${payload}`);
    const whsec = `whsec_${Buffer.from(hex).toString('base64')}`;

    expect(await verifyStandardWebhook({ payload, headers: headers(sig), secret: hex, now: timestamp })).toBe(true);
    expect(await verifyStandardWebhook({ payload, headers: headers(sig), secret: whsec, now: timestamp })).toBe(true);
  });
});
