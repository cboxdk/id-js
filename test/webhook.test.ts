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

/**
 * A signature is accepted only in full, and only at its exact length.
 *
 * The comparison here is hand-rolled — `crypto.timingSafeEqual` is a Node API and this
 * package runs in browsers and workers too — so its two properties are ours to hold, and
 * neither had a test. Both survived mutation: replacing the comparison with an 8-character
 * prefix match, and deleting the length check, each left the whole suite green.
 *
 * The length check is not cosmetic. Without it the loop runs over the EXPECTED digest's
 * length and simply never reads the extra characters, so a valid signature with anything
 * appended verifies — measured directly: `tse(good, good + 'JUNK')` is true.
 */
describe('signature comparison', () => {
  const now = 1_700_000_000;

  it('rejects a valid signature with anything appended', async () => {
    const header = await sign(now, payload);

    // The digest is intact and complete; there is simply more after it. A comparison that
    // walks only the expected length cannot see the difference.
    expect(
      await verifyWebhook({ payload, signatureHeader: `${header}00`, secret, now }),
    ).toBe(false);
  });

  it('rejects a signature truncated to a valid prefix', async () => {
    const header = await sign(now, payload);
    const [stamp, v1] = header.split(',');
    const digest = (v1 ?? '').slice('v1='.length);

    // Every character present is correct — there are just fewer of them. This is what a
    // prefix comparison accepts, and the only test that can tell one apart from a full one.
    expect(
      await verifyWebhook({
        payload,
        signatureHeader: `${stamp},v1=${digest.slice(0, 32)}`,
        secret,
        now,
      }),
    ).toBe(false);
  });

  it('rejects a signature that differs only in its last character', async () => {
    const header = await sign(now, payload);
    const flipped = header.slice(0, -1) + (header.endsWith('0') ? '1' : '0');

    // The far end of the digest, where a comparison that stops early never looks.
    expect(
      await verifyWebhook({ payload, signatureHeader: flipped, secret, now }),
    ).toBe(false);
  });
});

/*
 * A NON-NUMERIC TIMESTAMP HAS TO BE REFUSED BY SHAPE, not left to arithmetic.
 *
 * Found by mutation: deleting the shape check left every test green. The reason it is not
 * a hole is that the HMAC below still refuses — an attacker cannot produce a matching
 * signature without the secret. The reason it is not redundant either is what happens on
 * the way there: `Number('abc')` is NaN, and `Math.abs(NaN) > tolerance` is FALSE, so a
 * malformed timestamp sails straight through the freshness window that exists to stop
 * replays. The shape check is the only thing standing between a garbage `t=` and the
 * replay defence being silently skipped.
 */
it('rejects a timestamp that is not a number, rather than letting NaN pass the freshness window', async () => {
  const body = '{"event":"user.created"}';
  const now = Math.floor(Date.now() / 1000);
  // A real signature over the malformed header value, so the only thing that can refuse
  // this is the shape check — not the HMAC.
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`abc.${body}`));
  const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');

  expect(await verifyWebhook({ payload: body, signatureHeader: `t=abc,v1=${hex}`, secret, now })).toBe(false);
});

it('rejects an empty timestamp for the same reason', async () => {
  const body = '{"event":"user.created"}';
  expect(
    await verifyWebhook({
      payload: body,
      signatureHeader: 't=,v1=deadbeef',
      secret,
      now: Math.floor(Date.now() / 1000),
    }),
  ).toBe(false);
});
