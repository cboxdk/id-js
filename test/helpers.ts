import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { vi } from 'vitest';

export const ISSUER = 'https://id.test';

export const discovery = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/oauth/authorize`,
  token_endpoint: `${ISSUER}/oauth/token`,
  jwks_uri: `${ISSUER}/oauth/jwks`,
  userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
  introspection_endpoint: `${ISSUER}/oauth/introspect`,
  revocation_endpoint: `${ISSUER}/oauth/revoke`,
  end_session_endpoint: `${ISSUER}/oauth/logout`,
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

export const NONCE = 'test-nonce';

/** Optional overrides for the timestamps a signed id_token carries. */
export interface SignOptions {
  /** `exp` — an epoch-seconds number or a jose duration string (default `'5m'`). */
  expiresAt?: number | string;
  /** `iat` — epoch seconds (default: now). */
  issuedAt?: number;
}

/** A form POST the fake instance recorded, so tests can assert what was sent. */
export interface RecordedRequest {
  url: string;
  authorization: string | null;
  body: URLSearchParams;
}

export interface FakeInstance {
  jwk: JWK;
  /** The last request the revocation endpoint received, or null. */
  revocation(): RecordedRequest | null;
  signIdToken(claims: Record<string, unknown>, opts?: SignOptions): Promise<string>;
  /** Sign an id_token with a DIFFERENT key than the JWKS advertises (kid still `test-key`). */
  foreignIdToken(claims: Record<string, unknown>): Promise<string>;
  /** Replace what the token endpoint returns for an authorization_code exchange. */
  setTokenResponse(response: Record<string, unknown>): void;
  /**
   * Make the NEXT token-endpoint call fail, once. An object is served as JSON — an RFC
   * 6749 §5.2 error body; a string is served verbatim, which is how a proxy or a captive
   * portal answers, and is the case where the SDK must NOT invent an error code.
   */
  failNextToken(body: unknown, status: number, headers?: Record<string, string>): void;
  fetchMock: ReturnType<typeof vi.fn>;
}

/**
 * A fake Cbox ID instance backed by a REAL RS256 keypair: it serves a discovery
 * document and JWKS, signs genuine id_tokens, and answers the token / userinfo /
 * introspection endpoints. Tests run against real crypto, not stubbed success.
 */
export async function fakeInstance(
  overrides: {
    tokenResponse?: Record<string, unknown>;
    userinfo?: Record<string, unknown>;
    introspection?: Record<string, unknown>;
  } = {},
): Promise<FakeInstance> {
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  jwk.kid = 'test-key';
  jwk.alg = 'RS256';
  jwk.use = 'sig';

  const signIdToken = (claims: Record<string, unknown>, opts: SignOptions = {}): Promise<string> =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuedAt(opts.issuedAt)
      .setExpirationTime(opts.expiresAt ?? '5m')
      .sign(privateKey);

  // A token signed by a foreign keypair but presenting the advertised kid, so the
  // verifier picks the real JWKS key and the signature check must fail.
  const foreignIdToken = async (claims: Record<string, unknown>): Promise<string> => {
    const foreign = await generateKeyPair('RS256', { extractable: true });
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(foreign.privateKey);
  };

  const defaultIdToken = await signIdToken({
    iss: ISSUER,
    aud: 'client-abc',
    sub: 'user-1',
    nonce: NONCE,
    email: 'ada@acme.com',
    name: 'Ada',
    org: 'org-1',
  });

  let tokenResponse: Record<string, unknown> = overrides.tokenResponse ?? {
    access_token: 'access-abc',
    id_token: defaultIdToken,
    refresh_token: 'refresh-abc',
    expires_in: 3600,
    token_type: 'Bearer',
  };

  let revocation: RecordedRequest | null = null;
  // A one-shot failure for the token endpoint, so a test can assert what the SDK makes of
  // an RFC 6749 §5.2 error body without permanently breaking the fake for the next call.
  let nextTokenFailure: { body: unknown; status: number; headers?: Record<string, string> } | null = null;

  const fetchMock = vi.fn(async (input: unknown, init?: RequestInit): Promise<Response> => {
    const url = String(input instanceof Request ? input.url : input);

    if (url.endsWith('/.well-known/openid-configuration')) {
      return json(discovery);
    }
    if (url === discovery.jwks_uri) {
      return json({ keys: [jwk] });
    }
    if (url === discovery.token_endpoint) {
      if (nextTokenFailure !== null) {
        const failure = nextTokenFailure;
        nextTokenFailure = null;

        const headers = { ...(failure.headers ?? {}) };

        return typeof failure.body === 'string'
          ? new Response(failure.body, { status: failure.status, headers })
          : new Response(JSON.stringify(failure.body), {
              status: failure.status,
              headers: { 'content-type': 'application/json', ...headers },
            });
      }

      const body = new URLSearchParams(String(init?.body ?? ''));
      if (body.get('grant_type') === 'client_credentials') {
        return json({ access_token: 'machine-token', token_type: 'Bearer' });
      }
      return json(tokenResponse);
    }
    if (url === discovery.userinfo_endpoint) {
      return json(
        overrides.userinfo ?? { sub: 'user-1', email: 'ada@acme.com', name: 'Ada', org: 'org-1' },
      );
    }
    if (url === discovery.introspection_endpoint) {
      return json(overrides.introspection ?? { active: true, sub: 'user-1', scope: 'openid' });
    }
    if (url === discovery.revocation_endpoint) {
      const headers = new Headers(init?.headers as HeadersInit | undefined);
      revocation = {
        url,
        authorization: headers.get('authorization'),
        body: new URLSearchParams(String(init?.body ?? '')),
      };
      // RFC 7009: a successful revocation carries an empty 200 body.
      return new Response(null, { status: 200 });
    }
    return new Response('not found', { status: 404 });
  });

  const setTokenResponse = (response: Record<string, unknown>): void => {
    tokenResponse = response;
  };

  const failNextToken = (body: unknown, status: number, headers?: Record<string, string>): void => {
    nextTokenFailure = { body, status, ...(headers ? { headers } : {}) };
  };

  return {
    jwk,
    revocation: () => revocation,
    signIdToken,
    foreignIdToken,
    setTokenResponse,
    failNextToken,
    fetchMock,
  };
}
