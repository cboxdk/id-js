import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, SignJWT, type JWK } from 'jose';
import { ConfigurationError } from '../errors.js';
import { randomToken } from '../pkce.js';

/** The client-assertion algorithms this module signs with. Cbox ID accepts both. */
export type ClientKeyAlgorithm = 'ES256' | 'RS256';

/** A signing key pair for `private_key_jwt`, from {@link generateClientKeyPair}. */
export interface ClientKeyPair {
  alg: ClientKeyAlgorithm;
  /** The RFC 7638 thumbprint of the public key, used as `kid`. */
  kid: string;
  /** The public JWK (with `kid`, `alg`, `use: 'sig'`) — what registration sends in `jwks`. */
  publicJwk: JWK;
  /**
   * The private JWK. PERSIST THIS, and only this, somewhere the user alone can read
   * (mode 0600, the OS keychain). It is the client's credential: whoever holds it is the
   * client. Never log it, never commit it.
   */
  privateJwk: JWK;
  /** The private key as a WebCrypto `CryptoKey`, ready to sign with. */
  privateKey: CryptoKey;
}

/**
 * How the client authenticates at the backchannel, device and token endpoints.
 *
 * - `private_key_jwt` (RFC 7523): a short-lived assertion signed with your private key.
 *   The right choice for a self-registered agent or CLI: nothing secret ever crosses the
 *   wire, and the server stores only the public key.
 * - `client_secret_basic` / `client_secret_post`: a console-issued secret.
 * - `none`: a public client names itself by `client_id`. Fine for the device grant;
 *   the backchannel endpoint refuses it (`invalid_client`) because CIBA has no front
 *   channel to bind the flow to.
 */
export type ClientAuth =
  | {
      method: 'private_key_jwt';
      clientId: string;
      /** A `CryptoKey`, or the private JWK you persisted from {@link generateClientKeyPair}. */
      privateKey: CryptoKey | JWK;
      /** Inferred from the key when omitted. */
      alg?: ClientKeyAlgorithm;
      /** Sent as the assertion's `kid`. Taken from a JWK's own `kid` when omitted. */
      kid?: string;
    }
  | { method: 'client_secret_basic' | 'client_secret_post'; clientId: string; clientSecret: string }
  | { method: 'none'; clientId: string };

/**
 * A fresh signing key pair for `private_key_jwt`, generated with WebCrypto (via `jose`), so
 * it runs on Node, Deno, Bun and edge runtimes. ES256 by default — small keys, small
 * signatures. The private key is extractable on purpose: the caller must persist it.
 */
export async function generateClientKeyPair(alg: ClientKeyAlgorithm = 'ES256'): Promise<ClientKeyPair> {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const publicBare = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicBare, 'sha256');

  const publicJwk: JWK = { ...publicBare, kid, alg, use: 'sig' };
  const privateJwk: JWK = { ...(await exportJWK(privateKey)), kid, alg, use: 'sig' };

  return { alg, kid, publicJwk, privateJwk, privateKey };
}

/**
 * A signed RFC 7523 client assertion: `iss` = `sub` = client id, `aud` = the token
 * endpoint, a random `jti` (the server remembers it, so each assertion is single-use),
 * `iat` now and `exp` at most 60 seconds later.
 */
export async function createClientAssertion(
  auth: Extract<ClientAuth, { method: 'private_key_jwt' }>,
  audience: string,
  options: { now?: () => number; lifetimeSeconds?: number } = {},
): Promise<string> {
  const lifetime = Math.min(Math.max(options.lifetimeSeconds ?? 60, 1), 60);
  const nowSeconds = Math.floor((options.now ?? Date.now)() / 1000);
  const { key, alg, kid } = await signingKey(auth);

  const header: { alg: string; kid?: string } = { alg };
  if (kid !== undefined) {
    header.kid = kid;
  }

  return new SignJWT({})
    .setProtectedHeader(header)
    .setIssuer(auth.clientId)
    .setSubject(auth.clientId)
    .setAudience(audience)
    .setJti(randomToken(16))
    .setIssuedAt(nowSeconds)
    .setExpirationTime(nowSeconds + lifetime)
    .sign(key);
}

/**
 * Put client authentication on a request: fields in the form body, and/or an
 * `Authorization` header. `audience` is the token endpoint, the one value Cbox ID accepts
 * on assertions to all of its endpoints.
 */
export async function applyClientAuth(
  auth: ClientAuth,
  body: URLSearchParams,
  headers: Record<string, string>,
  audience: string,
): Promise<void> {
  if (!auth.clientId) {
    throw new ConfigurationError('A `clientId` is required.');
  }

  switch (auth.method) {
    case 'private_key_jwt':
      body.set('client_id', auth.clientId);
      body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      body.set('client_assertion', await createClientAssertion(auth, audience));
      return;
    case 'client_secret_basic':
      if (!auth.clientSecret) {
        throw new ConfigurationError('`client_secret_basic` needs a `clientSecret`.');
      }
      // RFC 6749 §2.3.1: both halves are form-encoded before they are joined.
      headers['authorization'] = `Basic ${btoa(`${formEncode(auth.clientId)}:${formEncode(auth.clientSecret)}`)}`;
      return;
    case 'client_secret_post':
      if (!auth.clientSecret) {
        throw new ConfigurationError('`client_secret_post` needs a `clientSecret`.');
      }
      body.set('client_id', auth.clientId);
      body.set('client_secret', auth.clientSecret);
      return;
    case 'none':
      body.set('client_id', auth.clientId);
      return;
  }
}

async function signingKey(
  auth: Extract<ClientAuth, { method: 'private_key_jwt' }>,
): Promise<{ key: CryptoKey | Uint8Array; alg: ClientKeyAlgorithm; kid: string | undefined }> {
  const source = auth.privateKey;

  if (isCryptoKey(source)) {
    const alg = auth.alg ?? algFromCryptoKey(source);
    return { key: source, alg, kid: auth.kid };
  }

  if (typeof source !== 'object' || source === null || typeof source.d !== 'string') {
    throw new ConfigurationError('`privateKey` must be a CryptoKey or a private JWK (with `d`).');
  }

  const alg = auth.alg ?? algFromJwk(source);
  const key = await importJWK(source, alg);

  return { key, alg, kid: auth.kid ?? (typeof source.kid === 'string' ? source.kid : undefined) };
}

function isCryptoKey(value: unknown): value is CryptoKey {
  return typeof CryptoKey !== 'undefined' && value instanceof CryptoKey;
}

function algFromCryptoKey(key: CryptoKey): ClientKeyAlgorithm {
  if (key.algorithm.name === 'ECDSA') {
    return 'ES256';
  }
  if (key.algorithm.name === 'RSASSA-PKCS1-v1_5') {
    return 'RS256';
  }
  throw new ConfigurationError(`Unsupported client key algorithm ${key.algorithm.name}; use ES256 or RS256.`);
}

function algFromJwk(jwk: JWK): ClientKeyAlgorithm {
  if (jwk.alg === 'ES256' || jwk.alg === 'RS256') {
    return jwk.alg as ClientKeyAlgorithm;
  }
  if (jwk.alg === undefined && jwk.kty === 'EC' && jwk.crv === 'P-256') {
    return 'ES256';
  }
  if (jwk.alg === undefined && jwk.kty === 'RSA') {
    return 'RS256';
  }
  throw new ConfigurationError('The private JWK is not an ES256 (P-256) or RS256 key.');
}

function formEncode(value: string): string {
  return encodeURIComponent(value).replace(/%20/g, '+');
}
