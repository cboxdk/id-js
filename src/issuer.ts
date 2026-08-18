import { ConfigurationError } from './errors.js';

/**
 * An issuer must be HTTPS.
 *
 * Everything this SDK does with it carries a credential: the authorization code, the PKCE
 * verifier, the client secret, the refresh token. Over `http://` a network attacker reads
 * all of them — and, worse, replaces the discovery document and JWKS, at which point a
 * forged id_token verifies cleanly and the whole verification chain proves nothing.
 *
 * Loopback is allowed because a native app's own callback listener is loopback by
 * definition (RFC 8252) and a dev instance runs there.
 */
export function assertSecureIssuer(issuer: string): void {
  let url: URL;

  try {
    url = new URL(issuer);
  } catch {
    throw new ConfigurationError('Cbox ID config `issuer` is not a valid URL.');
  }

  if (url.protocol === 'https:') {
    return;
  }

  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]' || url.hostname === '::1';

  if (url.protocol === 'http:' && loopback) {
    return;
  }

  throw new ConfigurationError(
    `Cbox ID config \`issuer\` must be https (got ${url.protocol}//${url.hostname}).`,
  );
}
