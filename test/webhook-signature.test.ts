import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyWebhook } from '../src/webhook.js';

/**
 * Golden webhook-signature vectors, shared byte-for-byte with laravel-id (the
 * sender) and with id-python, id-go and laravel-id-client.
 *
 * webhook.test.ts signs with its own copy of the formula and then verifies it, so
 * it passes even if this SDK and the server disagree — flipping the signed string
 * from `${timestamp}.${body}` to `${body}.${timestamp}` on either side leaves that
 * suite green while every delivery fails in the field. These signatures are fixed
 * bytes produced by the server's implementation and independently reproduced with
 * OpenSSL and Python.
 */
interface SignatureCase {
  name: string;
  secret: string;
  timestamp: number;
  body: string;
  signed_payload: string;
  signature: string;
  header: string;
  reversed_order_signature: string;
  reversed_order_header: string;
}

const fixture: { signed_payload_template: string; header_template: string; cases: SignatureCase[] } = JSON.parse(
  readFileSync(fileURLToPath(new URL('./fixtures/webhook-signature.json', import.meta.url)), 'utf8'),
);

describe('verifyWebhook against the shared cross-SDK vectors', () => {
  it.each(fixture.cases.map((c) => [c.name, c] as const))(
    'accepts the golden signature for %s',
    async (_name, testCase) => {
      expect(
        await verifyWebhook({
          payload: testCase.body,
          signatureHeader: testCase.header,
          secret: testCase.secret,
          now: testCase.timestamp,
        }),
      ).toBe(true);
    },
  );

  it.each(fixture.cases.map((c) => [c.name, c] as const))(
    'rejects the reversed-concatenation signature for %s',
    async (_name, testCase) => {
      // The exact same secret, timestamp and body, signed as `body.timestamp`
      // instead of `timestamp.body`. A verifier that concatenates the other way
      // round accepts this — and rejects everything the server actually sends.
      expect(
        await verifyWebhook({
          payload: testCase.body,
          signatureHeader: testCase.reversed_order_header,
          secret: testCase.secret,
          now: testCase.timestamp,
        }),
      ).toBe(false);
    },
  );

  it('rejects a golden signature replayed against a tampered body', async () => {
    const testCase = fixture.cases[0]!;

    expect(
      await verifyWebhook({
        payload: `${testCase.body} `,
        signatureHeader: testCase.header,
        secret: testCase.secret,
        now: testCase.timestamp,
      }),
    ).toBe(false);
  });

  it('verifies the raw bytes, not a re-serialized copy of the parsed body', async () => {
    // The unicode case ships escaped slashes and \uXXXX escapes. Re-encoding the
    // parsed object (JSON.stringify) produces equivalent JSON with different bytes,
    // which must NOT verify — this is the single most common integration bug.
    const testCase = fixture.cases.find((c) => c.name === 'unicode_and_escaped_slashes')!;
    const reSerialized = JSON.stringify(JSON.parse(testCase.body));

    expect(reSerialized).not.toBe(testCase.body);
    expect(
      await verifyWebhook({
        payload: reSerialized,
        signatureHeader: testCase.header,
        secret: testCase.secret,
        now: testCase.timestamp,
      }),
    ).toBe(false);
  });
});

/**
 * The wire format, stated once as a constant.
 *
 * This package verifies against its OWN copy of the fixture, as every SDK does, so a copy
 * that drifts is silent: this suite stays green against the drifted bytes while every
 * delivery from the server 401s in the field. The templates were the one field no test
 * read — flipping `signed_payload_template` to `{body}.{timestamp}` here changed nothing,
 * because each case also carries its signed payload as a literal.
 *
 * Deliberately NOT derived from the file it guards: `{timestamp}.{body}` is the contract
 * with the sender, and a copy that says otherwise is wrong rather than authoritative.
 */
describe('the shared fixture', () => {
  it('pins the signed-payload order this package must agree with the server on', () => {
    expect(fixture.signed_payload_template).toBe('{timestamp}.{body}');
    expect(fixture.header_template).toBe('t={timestamp},v1={signature}');
  });

  it.each(fixture.cases.map((c) => [c.name, c] as const))(
    'builds %s from the templates it publishes',
    (_name, testCase) => {
      const signedPayload = fixture.signed_payload_template
        .replace('{timestamp}', String(testCase.timestamp))
        .replace('{body}', testCase.body);

      // The template and the literal are the same fact stated twice; either one edited
      // alone is now a failure, which is what makes carrying both worthwhile.
      expect(signedPayload).toBe(testCase.signed_payload);
    },
  );
});
