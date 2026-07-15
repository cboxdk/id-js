import { describe, expect, it } from 'vitest';
import { challenge, createVerifier, randomToken } from '../src/pkce.js';

describe('pkce', () => {
  it('creates URL-safe verifiers with no padding', () => {
    const verifier = createVerifier();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(verifier.length).toBeGreaterThanOrEqual(43); // 32 bytes base64url
  });

  it('produces distinct random tokens', () => {
    expect(randomToken()).not.toBe(randomToken());
  });

  it('computes the S256 challenge from a known RFC 7636 vector', async () => {
    // RFC 7636 Appendix B.
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(await challenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
});
