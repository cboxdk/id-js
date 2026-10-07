/**
 * DPoP (RFC 9449) proofs for a sender-constrained access token, on WebCrypto alone — no
 * dependency, so it runs on Node, edge runtimes and the browser alike.
 *
 * A DPoP-bound token (its `cnf.jkt` names a key) is presented as `Authorization: DPoP <token>`
 * with a fresh proof per request, signed by that key: `htm` and `htu` pin the request, `ath`
 * pins the token, `jti` and `iat` make it single-use. A stolen token without the private key
 * is useless.
 */

/** Produces the `DPoP` header value for one request. */
export interface DPoPSigner {
  /** The RFC 7638 thumbprint of the public key — the `jkt` a bound token's `cnf` names. */
  readonly jkt: string;
  proof(input: { method: string; url: string; accessToken: string; nonce?: string }): Promise<string>;
}

const encoder = new TextEncoder();

function base64url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (const byte of view) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256(input: string): Promise<string> {
  return base64url(await crypto.subtle.digest('SHA-256', encoder.encode(input)));
}

/** A fresh, non-extractable P-256 key pair for {@link createDPoPSigner}. */
export async function generateDPoPKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
}

/**
 * A signer for ES256 proofs with `keyPair` — the key the access token was bound to when it
 * was issued (the same one the token request's own DPoP proof used).
 */
export async function createDPoPSigner(keyPair: CryptoKeyPair): Promise<DPoPSigner> {
  const exported = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const { crv, x, y } = exported;

  if (exported.kty !== 'EC' || crv !== 'P-256' || typeof x !== 'string' || typeof y !== 'string') {
    throw new TypeError('A DPoP key must be an ECDSA P-256 key pair.');
  }

  const jwk = { crv, kty: 'EC', x, y };
  // RFC 7638: the required members, lexicographic order, no whitespace.
  const jkt = await sha256(JSON.stringify(jwk));

  return {
    jkt,
    async proof({ method, url, accessToken, nonce }) {
      const target = new URL(url);
      const header = { typ: 'dpop+jwt', alg: 'ES256', jwk };
      const payload: Record<string, unknown> = {
        jti: crypto.randomUUID(),
        htm: method.toUpperCase(),
        // RFC 9449 §4.2: the URI without query and fragment.
        htu: `${target.origin}${target.pathname}`,
        iat: Math.floor(Date.now() / 1000),
        ath: await sha256(accessToken),
      };

      if (nonce !== undefined) {
        payload.nonce = nonce;
      }

      const signingInput = `${base64url(encoder.encode(JSON.stringify(header)))}.${base64url(encoder.encode(JSON.stringify(payload)))}`;
      // WebCrypto's ECDSA signature is already IEEE P1363 (r || s) — exactly JWS's ES256 form.
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        keyPair.privateKey,
        encoder.encode(signingInput),
      );

      return `${signingInput}.${base64url(signature)}`;
    },
  };
}
