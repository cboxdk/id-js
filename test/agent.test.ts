import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import {
  AccessDeniedError,
  AgentGrantError,
  AuthenticationError,
  BINDING_CODE_ALPHABET,
  CIBA_GRANT_TYPE,
  ConfigurationError,
  DEVICE_CODE_GRANT_TYPE,
  ExpiredTokenError,
  GrantCancelledError,
  InvalidBindingMessageError,
  InvalidClientError,
  InvalidGrantError,
  InvalidTargetError,
  SlowDownError,
  UnknownUserIdError,
  createBindingCode,
  createClientAssertion,
  discoverAuthorizationServer,
  generateClientKeyPair,
  pollBackchannel,
  refreshAgentTokens,
  registerAgentClient,
  startBackchannel,
  startDeviceAuthorization,
  waitForBackchannelToken,
  waitForDeviceToken,
  type AuthorizationServerMetadata,
  type ClientAuth,
} from '../src/agent/index.js';

const ISSUER = 'https://id.test';

const metadata: AuthorizationServerMetadata = {
  issuer: ISSUER,
  token_endpoint: `${ISSUER}/oauth/token`,
  registration_endpoint: `${ISSUER}/oauth/register`,
  backchannel_authentication_endpoint: `${ISSUER}/oauth/backchannel_authentication`,
  device_authorization_endpoint: `${ISSUER}/oauth/device_authorization`,
  backchannel_token_delivery_modes_supported: ['poll'],
  backchannel_user_code_parameter_supported: false,
};

interface Recorded {
  url: string;
  method: string;
  headers: Headers;
  body: string;
}

type Reply = { status?: number; body?: unknown; headers?: Record<string, string> };

/** A scripted fake server: each endpoint answers from its own queue, and every request is recorded. */
function fakeServer(script: Record<string, Reply[] | Reply>) {
  const requests: Recorded[] = [];
  const queues = new Map<string, Reply[]>();
  for (const [path, replies] of Object.entries(script)) {
    queues.set(path, Array.isArray(replies) ? [...replies] : [replies]);
  }

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const path = new URL(url).pathname;
    requests.push({
      url,
      method: init?.method ?? 'GET',
      headers: new Headers(init?.headers),
      body: init?.body === undefined || init.body === null ? '' : String(init.body),
    });

    if (path === '/.well-known/oauth-authorization-server' && !queues.has(path)) {
      return json(metadata);
    }

    const queue = queues.get(path);
    const reply = queue && queue.length > 1 ? queue.shift() : queue?.[0];
    if (reply === undefined) {
      throw new Error(`unexpected fetch ${url}`);
    }
    return json(reply.body ?? {}, reply.status ?? 200, reply.headers);
  });

  return {
    fetch: fetchMock as unknown as typeof fetch,
    requests,
    to: (path: string) => requests.filter((r) => new URL(r.url).pathname === path),
    form: (path: string, index = 0) => new URLSearchParams(requests.filter((r) => new URL(r.url).pathname === path)[index]?.body ?? ''),
  };
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

const tokens = { access_token: 'at-1', token_type: 'Bearer', expires_in: 3600, refresh_token: 'rt-1', scope: 'brain.read' };

const backchannel = { auth_req_id: 'req-1', expires_in: 120, interval: 5 };

function recordingSleep() {
  const waits: number[] = [];
  const sleep = async (ms: number): Promise<void> => {
    waits.push(ms);
  };
  return { waits, sleep };
}

describe('discoverAuthorizationServer', () => {
  it('reads RFC 8414 metadata from the issuer', async () => {
    const server = fakeServer({});
    const doc = await discoverAuthorizationServer(`${ISSUER}/`, { fetch: server.fetch });

    expect(doc.backchannel_authentication_endpoint).toBe(`${ISSUER}/oauth/backchannel_authentication`);
    expect(server.requests[0]?.url).toBe(`${ISSUER}/.well-known/oauth-authorization-server`);
  });

  it('refuses metadata for a different issuer', async () => {
    const server = fakeServer({ '/.well-known/oauth-authorization-server': { body: { ...metadata, issuer: 'https://evil.test' } } });

    await expect(discoverAuthorizationServer(ISSUER, { fetch: server.fetch })).rejects.toThrow(/different issuer/);
  });

  it('refuses a plain-http issuer', async () => {
    await expect(discoverAuthorizationServer('http://id.example.com')).rejects.toThrow(ConfigurationError);
  });
});

describe('generateClientKeyPair / createClientAssertion', () => {
  it.each(['ES256', 'RS256'] as const)('signs an RFC 7523 assertion with %s that verifies against the public JWK', async (alg) => {
    const keys = await generateClientKeyPair(alg);

    expect(keys.publicJwk).toMatchObject({ alg, kid: keys.kid, use: 'sig' });
    expect(keys.publicJwk).not.toHaveProperty('d');
    expect(keys.privateJwk).toHaveProperty('d');

    const assertion = await createClientAssertion(
      { method: 'private_key_jwt', clientId: 'agent-1', privateKey: keys.privateJwk },
      metadata.token_endpoint,
    );

    const { payload, protectedHeader } = await jwtVerify(assertion, await importJWK(keys.publicJwk, alg), {
      issuer: 'agent-1',
      subject: 'agent-1',
      audience: metadata.token_endpoint,
    });

    expect(protectedHeader).toMatchObject({ alg, kid: keys.kid });
    expect(typeof payload.jti).toBe('string');
    expect(payload.exp! - payload.iat!).toBeLessThanOrEqual(60);
  });

  it('uses a fresh jti every time, because the server remembers them', async () => {
    const keys = await generateClientKeyPair();
    const auth = { method: 'private_key_jwt', clientId: 'agent-1', privateKey: keys.privateKey } as const;
    const a = await createClientAssertion(auth, metadata.token_endpoint);
    const b = await createClientAssertion(auth, metadata.token_endpoint);

    const jti = async (jwt: string) => (await jwtVerify(jwt, await importJWK(keys.publicJwk, 'ES256'))).payload.jti;
    expect(await jti(a)).not.toBe(await jti(b));
    // Algorithm inferred from the CryptoKey.
    expect(decodeProtectedHeader(a).alg).toBe('ES256');
  });

  it('caps the lifetime at 60 seconds', async () => {
    const keys = await generateClientKeyPair();
    const jwt = await createClientAssertion(
      { method: 'private_key_jwt', clientId: 'c', privateKey: keys.privateKey },
      metadata.token_endpoint,
      { lifetimeSeconds: 3600 },
    );
    const { payload } = await jwtVerify(jwt, await importJWK(keys.publicJwk, 'ES256'));
    expect(payload.exp! - payload.iat!).toBe(60);
  });
});

describe('registerAgentClient', () => {
  it('registers a private_key_jwt client with an inline jwks and returns a usable auth', async () => {
    const server = fakeServer({
      '/oauth/register': {
        status: 201,
        body: {
          client_id: 'agent-1',
          token_endpoint_auth_method: 'private_key_jwt',
          grant_types: [CIBA_GRANT_TYPE, 'refresh_token'],
          scope: 'brain.read',
        },
      },
    });

    const registered = await registerAgentClient({
      issuer: ISSUER,
      fetch: server.fetch,
      clientName: 'Cbox Brain CLI',
      grantTypes: [CIBA_GRANT_TYPE, 'refresh_token'],
      scope: ['brain.read'],
    });

    const sent = JSON.parse(server.to('/oauth/register')[0]!.body) as Record<string, unknown>;
    expect(sent).toMatchObject({
      client_name: 'Cbox Brain CLI',
      grant_types: [CIBA_GRANT_TYPE, 'refresh_token'],
      token_endpoint_auth_method: 'private_key_jwt',
      scope: 'brain.read',
    });
    const jwks = sent['jwks'] as { keys: Array<Record<string, unknown>> };
    expect(jwks.keys).toHaveLength(1);
    // Only the public half leaves the machine.
    expect(jwks.keys[0]).not.toHaveProperty('d');
    expect(jwks.keys[0]?.['kid']).toBe(registered.keyPair?.kid);

    expect(registered.clientId).toBe('agent-1');
    expect(registered.clientSecret).toBeNull();
    expect(registered.auth).toMatchObject({ method: 'private_key_jwt', clientId: 'agent-1' });
    expect(registered.keyPair?.privateJwk).toHaveProperty('d');
  });

  it('registers a public device client without keys', async () => {
    const server = fakeServer({ '/oauth/register': { status: 201, body: { client_id: 'cli-1', token_endpoint_auth_method: 'none' } } });

    const registered = await registerAgentClient({
      issuer: ISSUER,
      metadata,
      fetch: server.fetch,
      clientName: 'cli',
      grantTypes: [DEVICE_CODE_GRANT_TYPE],
      tokenEndpointAuthMethod: 'none',
      initialAccessToken: 'iat-1',
    });

    const sent = JSON.parse(server.to('/oauth/register')[0]!.body) as Record<string, unknown>;
    expect(sent).not.toHaveProperty('jwks');
    expect(server.to('/oauth/register')[0]?.headers.get('authorization')).toBe('Bearer iat-1');
    // `metadata` passed: no discovery round trip.
    expect(server.to('/.well-known/oauth-authorization-server')).toHaveLength(0);
    expect(registered.keyPair).toBeNull();
    expect(registered.auth).toEqual({ method: 'none', clientId: 'cli-1' });
  });

  it('says so when registration is switched off', async () => {
    const { registration_endpoint: _omit, ...withoutRegistration } = metadata;
    await expect(
      registerAgentClient({ issuer: ISSUER, metadata: withoutRegistration, clientName: 'x', grantTypes: [CIBA_GRANT_TYPE] }),
    ).rejects.toThrow(ConfigurationError);
  });

  it('throws SlowDownError with Retry-After on a 429', async () => {
    const server = fakeServer({ '/oauth/register': { status: 429, body: { error: 'slow_down' }, headers: { 'retry-after': '30' } } });

    const error = await registerAgentClient({
      issuer: ISSUER,
      metadata,
      fetch: server.fetch,
      clientName: 'x',
      grantTypes: [CIBA_GRANT_TYPE],
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(SlowDownError);
    expect((error as SlowDownError).retryAfter).toBe(30);
    expect((error as SlowDownError).isRateLimited).toBe(true);
  });
});

describe('startBackchannel', () => {
  it('sends login_hint, scope, binding_message, resource, requested_expiry, nonce and a client assertion — and no user_code', async () => {
    const keys = await generateClientKeyPair();
    const server = fakeServer({ '/oauth/backchannel_authentication': { body: backchannel } });

    const auth = await startBackchannel({
      issuer: ISSUER,
      fetch: server.fetch,
      client: { method: 'private_key_jwt', clientId: 'agent-1', privateKey: keys.privateJwk },
      loginHint: 'ada@acme.com',
      scope: ['openid', 'brain.read'],
      bindingMessage: 'Brain CLI K7QM',
      resource: 'https://brain.test/api',
      requestedExpiry: 300,
      nonce: 'n-1',
    });

    const form = server.form('/oauth/backchannel_authentication');
    expect(form.get('login_hint')).toBe('ada@acme.com');
    expect(form.get('scope')).toBe('openid brain.read');
    expect(form.get('binding_message')).toBe('Brain CLI K7QM');
    expect(form.getAll('resource')).toEqual(['https://brain.test/api']);
    expect(form.get('requested_expiry')).toBe('300');
    expect(form.get('nonce')).toBe('n-1');
    expect(form.has('user_code')).toBe(false);
    expect(form.get('client_id')).toBe('agent-1');
    expect(form.get('client_assertion_type')).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');

    // aud = token endpoint, iss = sub = client id.
    await jwtVerify(form.get('client_assertion')!, await importJWK(keys.publicJwk, 'ES256'), {
      issuer: 'agent-1',
      subject: 'agent-1',
      audience: metadata.token_endpoint,
    });

    expect(auth).toMatchObject({ authReqId: 'req-1', expiresIn: 120, interval: 5, resource: ['https://brain.test/api'] });
  });

  it('authenticates with a client secret over Basic', async () => {
    const server = fakeServer({ '/oauth/backchannel_authentication': { body: backchannel } });

    await startBackchannel({
      issuer: ISSUER,
      metadata,
      fetch: server.fetch,
      client: { method: 'client_secret_basic', clientId: 'app 1', clientSecret: 's3cr:t' },
      loginHint: 'user-1',
      scope: 'openid',
      bindingMessage: 'K7QM',
    });

    const request = server.to('/oauth/backchannel_authentication')[0]!;
    expect(request.headers.get('authorization')).toBe(`Basic ${btoa('app+1:s3cr%3At')}`);
    expect(new URLSearchParams(request.body).has('client_secret')).toBe(false);
  });

  it.each([
    ['unknown_user_id', UnknownUserIdError],
    ['invalid_binding_message', InvalidBindingMessageError],
    ['invalid_target', InvalidTargetError],
    ['invalid_client', InvalidClientError],
  ] as const)('throws a typed error for %s', async (code, Klass) => {
    const server = fakeServer({
      '/oauth/backchannel_authentication': { status: code === 'invalid_client' ? 401 : 400, body: { error: code, error_description: 'nope' } },
    });

    const error = await startBackchannel({
      issuer: ISSUER,
      metadata,
      fetch: server.fetch,
      client: { method: 'none', clientId: 'c' },
      loginHint: 'x',
      scope: 'openid',
      bindingMessage: 'K7QM',
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(Klass);
    expect(error).toBeInstanceOf(AgentGrantError);
    expect(error).toBeInstanceOf(AuthenticationError);
    expect((error as AgentGrantError).error).toBe(code);
    expect((error as AgentGrantError).errorDescription).toBe('nope');
  });

  it('refuses a resource that is not an absolute URI before sending anything', async () => {
    const server = fakeServer({});
    await expect(
      startBackchannel({
        issuer: ISSUER,
        metadata,
        fetch: server.fetch,
        client: { method: 'none', clientId: 'c' },
        loginHint: 'x',
        scope: 'openid',
        bindingMessage: 'K7QM',
        resource: 'brain',
      }),
    ).rejects.toThrow(ConfigurationError);
    expect(server.requests).toHaveLength(0);
  });
});

describe('pollBackchannel / waitForBackchannelToken', () => {
  const client: ClientAuth = { method: 'client_secret_post', clientId: 'agent-1', clientSecret: 'secret' };
  const authorization = () => ({ authReqId: 'req-1', expiresIn: 120, interval: 5, expiresAt: Date.now() + 120_000, resource: ['https://brain.test/api'] });

  it('polls once with the CIBA grant, auth_req_id and the same resource', async () => {
    const server = fakeServer({ '/oauth/token': { status: 400, body: { error: 'authorization_pending' } } });

    const result = await pollBackchannel({ issuer: ISSUER, metadata, fetch: server.fetch, client, authorization: authorization() });

    expect(result).toEqual({ status: 'pending' });
    const form = server.form('/oauth/token');
    expect(form.get('grant_type')).toBe(CIBA_GRANT_TYPE);
    expect(form.get('auth_req_id')).toBe('req-1');
    expect(form.getAll('resource')).toEqual(['https://brain.test/api']);
    expect(form.get('client_secret')).toBe('secret');
  });

  it('waits the interval, keeps going on pending, and returns the tokens', async () => {
    const server = fakeServer({
      '/oauth/token': [
        { status: 400, body: { error: 'authorization_pending' } },
        { status: 400, body: { error: 'authorization_pending' } },
        { body: tokens },
      ],
    });
    const { waits, sleep } = recordingSleep();

    const result = await waitForBackchannelToken({ issuer: ISSUER, fetch: server.fetch, client, authorization: authorization(), sleep });

    expect(result).toMatchObject({ accessToken: 'at-1', refreshToken: 'rt-1', expiresIn: 3600, idToken: null, scope: 'brain.read' });
    expect(waits).toEqual([5000, 5000, 5000]);
    expect(server.to('/oauth/token')).toHaveLength(3);
    // Discovered once for the whole wait, not per poll.
    expect(server.to('/.well-known/oauth-authorization-server')).toHaveLength(1);
  });

  it('adds five seconds on slow_down and keeps the slower rate', async () => {
    const server = fakeServer({
      '/oauth/token': [
        { status: 400, body: { error: 'slow_down' } },
        { status: 400, body: { error: 'authorization_pending' } },
        { body: tokens },
      ],
    });
    const { waits, sleep } = recordingSleep();

    await waitForBackchannelToken({ issuer: ISSUER, metadata, fetch: server.fetch, client, authorization: authorization(), sleep });

    expect(waits).toEqual([5000, 10_000, 10_000]);
  });

  it('honours Retry-After on a 429', async () => {
    const server = fakeServer({
      '/oauth/token': [
        { status: 429, body: { error: 'slow_down' }, headers: { 'retry-after': '42' } },
        { status: 429, body: 'Too Many Requests', headers: { 'retry-after': '1' } },
        { body: tokens },
      ],
    });
    const { waits, sleep } = recordingSleep();

    await waitForBackchannelToken({ issuer: ISSUER, metadata, fetch: server.fetch, client, authorization: authorization(), sleep });

    // 42 s (Retry-After beats 10 s), then 15 s (+5 again beats the 1 s Retry-After).
    expect(waits).toEqual([5000, 42_000, 15_000]);
  });

  it.each([
    ['access_denied', AccessDeniedError],
    ['expired_token', ExpiredTokenError],
    ['invalid_grant', InvalidGrantError],
    ['invalid_target', InvalidTargetError],
    ['invalid_client', InvalidClientError],
  ] as const)('stops on %s', async (code, Klass) => {
    const server = fakeServer({ '/oauth/token': { status: 400, body: { error: code } } });
    const { sleep } = recordingSleep();

    await expect(
      waitForBackchannelToken({ issuer: ISSUER, metadata, fetch: server.fetch, client, authorization: authorization(), sleep }),
    ).rejects.toBeInstanceOf(Klass);
    expect(server.to('/oauth/token')).toHaveLength(1);
  });

  it('gives up locally once the request has expired', async () => {
    const server = fakeServer({ '/oauth/token': { status: 400, body: { error: 'authorization_pending' } } });
    let clock = 0;
    const sleep = async (ms: number): Promise<void> => {
      clock += ms;
    };

    await expect(
      waitForBackchannelToken({
        issuer: ISSUER,
        metadata,
        fetch: server.fetch,
        client,
        authorization: { ...authorization(), expiresAt: 12_000 },
        sleep,
        now: () => clock,
      }),
    ).rejects.toBeInstanceOf(ExpiredTokenError);
    // Polls at 5 s and 10 s; at 15 s the request is over and nothing more is sent.
    expect(server.to('/oauth/token')).toHaveLength(2);
  });

  it('can be cancelled with an AbortSignal', async () => {
    const server = fakeServer({ '/oauth/token': { status: 400, body: { error: 'authorization_pending' } } });
    const controller = new AbortController();
    let polls = 0;
    const sleep = async (): Promise<void> => {
      polls++;
      if (polls === 2) {
        controller.abort();
      }
    };

    await expect(
      waitForBackchannelToken({ issuer: ISSUER, metadata, fetch: server.fetch, client, authorization: authorization(), sleep, signal: controller.signal }),
    ).rejects.toBeInstanceOf(GrantCancelledError);
    expect(server.to('/oauth/token')).toHaveLength(1);
  });

  it('interrupts the real timer immediately on abort', async () => {
    const server = fakeServer({});
    const controller = new AbortController();
    const pending = waitForBackchannelToken({
      issuer: ISSUER,
      metadata,
      fetch: server.fetch,
      client,
      authorization: { ...authorization(), interval: 30 },
      signal: controller.signal,
    });
    controller.abort();

    await expect(pending).rejects.toBeInstanceOf(GrantCancelledError);
    expect(server.requests).toHaveLength(0);
  });
});

describe('device grant', () => {
  const client: ClientAuth = { method: 'none', clientId: 'cli-1' };

  it('starts, shows the code, polls with the device grant and returns tokens', async () => {
    const server = fakeServer({
      '/oauth/device_authorization': {
        body: {
          device_code: 'dc-1',
          user_code: 'WDJB-MJHT',
          verification_uri: `${ISSUER}/device`,
          verification_uri_complete: `${ISSUER}/device?user_code=WDJB-MJHT`,
          expires_in: 600,
        },
      },
      '/oauth/token': [{ status: 400, body: { error: 'authorization_pending' } }, { body: tokens }],
    });
    const { waits, sleep } = recordingSleep();

    const auth = await startDeviceAuthorization({ issuer: ISSUER, metadata, fetch: server.fetch, client, scope: 'brain.read offline_access', resource: ['https://brain.test/api'] });

    expect(auth).toMatchObject({ userCode: 'WDJB-MJHT', interval: 5, verificationUriComplete: `${ISSUER}/device?user_code=WDJB-MJHT` });
    expect(server.form('/oauth/device_authorization').get('client_id')).toBe('cli-1');
    expect(server.form('/oauth/device_authorization').get('scope')).toBe('brain.read offline_access');

    const result = await waitForDeviceToken({ issuer: ISSUER, metadata, fetch: server.fetch, client, authorization: auth, sleep });

    expect(result.accessToken).toBe('at-1');
    expect(waits).toEqual([5000, 5000]);
    const form = server.form('/oauth/token', 1);
    expect(form.get('grant_type')).toBe(DEVICE_CODE_GRANT_TYPE);
    expect(form.get('device_code')).toBe('dc-1');
    expect(form.getAll('resource')).toEqual(['https://brain.test/api']);
  });

  it('stops when the person declines', async () => {
    const server = fakeServer({ '/oauth/token': { status: 400, body: { error: 'access_denied' } } });
    const { sleep } = recordingSleep();

    await expect(
      waitForDeviceToken({
        issuer: ISSUER,
        metadata,
        fetch: server.fetch,
        client,
        authorization: {
          deviceCode: 'dc-1',
          userCode: 'X',
          verificationUri: `${ISSUER}/device`,
          verificationUriComplete: null,
          expiresIn: 600,
          interval: 5,
          expiresAt: Date.now() + 600_000,
          resource: [],
        },
        sleep,
      }),
    ).rejects.toBeInstanceOf(AccessDeniedError);
  });

  it('never echoes a non-JSON error body', async () => {
    const server = fakeServer({ '/oauth/device_authorization': { status: 502, body: '<html>client_secret=leaked</html>' } });

    const error = await startDeviceAuthorization({ issuer: ISSUER, metadata, fetch: server.fetch, client }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(AgentGrantError);
    expect((error as Error).message).not.toContain('leaked');
    expect((error as AgentGrantError).error).toBeUndefined();
    expect((error as AgentGrantError).status).toBe(502);
  });
});

describe('refreshAgentTokens', () => {
  it('refreshes with the same client assertion auth', async () => {
    const keys = await generateClientKeyPair();
    const server = fakeServer({ '/oauth/token': { body: { ...tokens, refresh_token: 'rt-2' } } });

    const result = await refreshAgentTokens({
      issuer: ISSUER,
      metadata,
      fetch: server.fetch,
      client: { method: 'private_key_jwt', clientId: 'agent-1', privateKey: keys.privateJwk },
      refreshToken: 'rt-1',
      resource: 'https://brain.test/api',
    });

    expect(result.refreshToken).toBe('rt-2');
    const form = server.form('/oauth/token');
    expect(form.get('grant_type')).toBe('refresh_token');
    expect(form.get('refresh_token')).toBe('rt-1');
    expect(form.getAll('resource')).toEqual(['https://brain.test/api']);
    expect(form.has('client_assertion')).toBe(true);
  });

  it('throws on a 429 instead of treating it as a poll answer', async () => {
    const server = fakeServer({ '/oauth/token': { status: 429, body: {}, headers: { 'retry-after': '7' } } });

    const error = await refreshAgentTokens({ issuer: ISSUER, metadata, fetch: server.fetch, client: { method: 'none', clientId: 'c' }, refreshToken: 'rt' }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(SlowDownError);
    expect((error as SlowDownError).retryAfter).toBe(7);
  });

  it('throws InvalidGrantError for a dead refresh token', async () => {
    const server = fakeServer({ '/oauth/token': { status: 400, body: { error: 'invalid_grant' } } });

    await expect(
      refreshAgentTokens({ issuer: ISSUER, metadata, fetch: server.fetch, client: { method: 'none', clientId: 'c' }, refreshToken: 'rt' }),
    ).rejects.toBeInstanceOf(InvalidGrantError);
  });
});

describe('createBindingCode', () => {
  it('makes short codes from the unambiguous alphabet', () => {
    for (let i = 0; i < 200; i++) {
      const code = createBindingCode();
      expect(code).toHaveLength(4);
      for (const ch of code) {
        expect(BINDING_CODE_ALPHABET).toContain(ch);
      }
    }
    expect(createBindingCode(6)).toHaveLength(6);
    expect(BINDING_CODE_ALPHABET).not.toMatch(/[0O1IL5S2Z8B]/);
  });

  it('refuses a silly length', () => {
    expect(() => createBindingCode(0)).toThrow(ConfigurationError);
  });
});
