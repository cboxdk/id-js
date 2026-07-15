/**
 * PKCE (RFC 7636) and the random values the login flow needs, built on Web Crypto
 * (`globalThis.crypto`) so the same code runs on Node, edge runtimes and browsers.
 */

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A URL-safe random token of `bytes` bytes (default 32), for state and nonce. */
export function randomToken(bytes = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** A high-entropy PKCE code verifier. */
export function createVerifier(): string {
  return randomToken(32);
}

/** The S256 code challenge for a verifier. */
export async function challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}
