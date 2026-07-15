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
  end_session_endpoint: `${ISSUER}/oauth/logout`,
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

export const NONCE = 'test-nonce';

export interface FakeInstance {
  jwk: JWK;
  signIdToken(claims: Record<string, unknown>): Promise<string>;
  /** Replace what the token endpoint returns for an authorization_code exchange. */
  setTokenResponse(response: Record<string, unknown>): void;
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

  const signIdToken = (claims: Record<string, unknown>): Promise<string> =>
    new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

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

  const fetchMock = vi.fn(async (input: unknown, init?: RequestInit): Promise<Response> => {
    const url = String(input instanceof Request ? input.url : input);

    if (url.endsWith('/.well-known/openid-configuration')) {
      return json(discovery);
    }
    if (url === discovery.jwks_uri) {
      return json({ keys: [jwk] });
    }
    if (url === discovery.token_endpoint) {
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
    return new Response('not found', { status: 404 });
  });

  const setTokenResponse = (response: Record<string, unknown>): void => {
    tokenResponse = response;
  };

  return { jwk, signIdToken, setTokenResponse, fetchMock };
}
