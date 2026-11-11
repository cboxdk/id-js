import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CboxIdApiError,
  ConfigurationError,
  EnvironmentClient,
  OrganizationClient,
  PlatformClient,
  WorkspaceClient,
  organizationOperations,
  v1Routes,
  v1Unmapped,
  workspaceOperations,
} from '../src/management/index.js';
import {
  CboxIdClient,
  VaultClient,
  currentWebhookEventType,
  isPrefixedId,
  isWebhookEventType,
  legacyWebhookEventType,
  publishManifest,
  rawId,
  sameId,
  webhookEventTypeAliases,
} from '../src/index.js';
import { fakeInstance, ISSUER, NONCE } from './helpers.js';

const API = 'https://api.cboxid.test';
const HOST = 'https://acme.test';
const KEY = 'cbid_env_test_key';
const ULID = '01J9ZK3M4N5P6Q7R8S9T0V1W2X';

interface Call {
  url: string;
  method: string;
  headers: Headers;
  body: unknown;
}

function fakeFetch(...replies: (Response | ((call: Call) => Response))[]) {
  const calls: Call[] = [];
  const fn = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const call: Call = {
      url: String(input),
      method: init?.method ?? 'GET',
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    const next = replies.shift();
    if (next === undefined) throw new Error(`unexpected request ${call.method} ${call.url}`);
    return typeof next === 'function' ? next(call) : next;
  });

  return { fetch: fn as unknown as typeof fetch, calls };
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

function v1Env(fetchImpl: typeof fetch, extra: Partial<ConstructorParameters<typeof EnvironmentClient>[0]> = {}) {
  return new EnvironmentClient({ apiUrl: API, apiKey: KEY, fetch: fetchImpl, retry: { baseDelayMs: 0 }, approvalPollIntervalMs: 0, ...extra });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('management client without apiUrl', () => {
  it('calls {baseUrl}/api/v1 with today’s paths, exactly as before', async () => {
    const { fetch, calls } = fakeFetch(json({ data: [{ id: 'usr_1' }], meta: { has_more: false } }));
    const client = new EnvironmentClient({ baseUrl: HOST, apiKey: KEY, fetch });

    const page = await client.users.list({ limit: 5 });

    expect(calls[0]!.url).toBe(`${HOST}/api/v1/users?limit=5`);
    expect(page.data).toEqual([{ id: 'usr_1' }]);
    expect(client.transport.v1).toBe(false);
  });

  it('still needs a baseUrl for the environment plane', () => {
    expect(() => new EnvironmentClient({ apiKey: KEY } as never)).toThrow(/baseUrl/);
  });
});

describe('management client with apiUrl (Cbox ID v3)', () => {
  it('sends an operation to its /v1 route and reads the list envelope', async () => {
    const { fetch, calls } = fakeFetch(
      json({ object: 'list', data: [{ object: 'user', id: `usr_${ULID}` }], has_more: true, next_cursor: 'c2' }),
    );

    const page = await v1Env(fetch).users.list({ limit: 5 });

    expect(calls[0]!.url).toBe(`${API}/v1/users?limit=5`);
    expect(calls[0]!.headers.get('authorization')).toBe(`Bearer ${KEY}`);
    expect(page.data).toEqual([{ object: 'user', id: `usr_${ULID}` }]);
    expect(page.meta).toEqual({ has_more: true, next_cursor: 'c2' });
  });

  it('accepts apiUrl with or without /v1', async () => {
    for (const apiUrl of [API, `${API}/`, `${API}/v1`, `${API}/v1/`]) {
      expect(new EnvironmentClient({ apiUrl, apiKey: KEY }).transport.baseUrl).toBe(`${API}/v1`);
    }
    expect(() => new EnvironmentClient({ apiUrl: 'http://api.cboxid.test', apiKey: KEY })).toThrow(/https/);
    expect(() => new EnvironmentClient({ apiUrl: ' ', apiKey: KEY })).toThrow(ConfigurationError);
  });

  it('pages every list by cursor', async () => {
    const { fetch, calls } = fakeFetch(
      json({ object: 'list', data: [{ id: 'a' }], has_more: true, next_cursor: 'c2' }),
      json({ object: 'list', data: [{ id: 'b' }], has_more: false, next_cursor: null }),
    );

    const ids: string[] = [];
    for await (const user of v1Env(fetch).users.listAll()) ids.push((user as { id: string }).id);

    expect(ids).toEqual(['a', 'b']);
    expect(new URL(calls[1]!.url).searchParams.get('after')).toBe('c2');
  });

  it('reads a /v1 resource as the object itself, even one with a field called data', async () => {
    const app = { object: 'app', id: 'app_1', data: { anything: true } };
    const { fetch } = fakeFetch(json(app));

    const result = await v1Env(fetch).apps.get('app_1');

    expect(result.data).toEqual(app);
    expect(result.meta).toBeUndefined();
  });

  it('addresses a child by its own id, the parent in the query', async () => {
    const { fetch, calls } = fakeFetch(new Response(null, { status: 204 }));

    await v1Env(fetch).apps.secrets.revoke('app_1', 'sec_9');

    expect(calls[0]!.method).toBe('DELETE');
    expect(calls[0]!.url).toBe(`${API}/v1/app-secrets/sec_9?app_id=app_1`);
  });

  it('moves a parent id into the body where /v1 takes it there', async () => {
    const { fetch, calls } = fakeFetch(json({ object: 'organization_domain', id: 'dom_1' }, 201));

    await v1Env(fetch).organizations.domains.add('org_1', { domain: 'acme.com' });

    expect(calls[0]!.method).toBe('POST');
    expect(calls[0]!.url).toBe(`${API}/v1/organization-domains`);
    expect(calls[0]!.body).toEqual({ domain: 'acme.com', organization_id: 'org_1' });
  });

  it('accepts prefixed and raw ids alike as arguments', async () => {
    const { fetch, calls } = fakeFetch(json({ object: 'app', id: `app_${ULID}` }), json({ object: 'app', id: `app_${ULID}` }));
    const client = v1Env(fetch);

    await client.apps.get(`app_${ULID}`);
    await client.apps.get(ULID.toLowerCase());

    expect(calls.map((c) => c.url)).toEqual([`${API}/v1/apps/app_${ULID}`, `${API}/v1/apps/${ULID.toLowerCase()}`]);
  });

  it('keeps calling /api/v1 on baseUrl for an operation with no /v1 route', async () => {
    expect(v1Unmapped).toContain('environment PUT /organizations/{organization_id}/domains/{domain_id}/capture');
    const { fetch, calls } = fakeFetch(json({ data: { id: 'dom_1' } }));

    const client = v1Env(fetch, { baseUrl: HOST });
    await client.organizations.domains.capture('org_1', 'dom_1', { enabled: true });

    expect(calls[0]!.url).toBe(`${HOST}/api/v1/organizations/org_1/domains/dom_1/capture`);
    expect(calls[0]!.method).toBe('PUT');
  });

  it('says so when such an operation has no baseUrl to fall back to', async () => {
    const { fetch } = fakeFetch();

    await expect(v1Env(fetch).organizations.domains.capture('org_1', 'dom_1', { enabled: true })).rejects.toThrow(/no \/v1 route/);
  });

  it('reads an RFC 9457 problem into CboxIdApiError', async () => {
    const { fetch } = fakeFetch(
      json(
        {
          type: 'https://api.cboxid.com/problems/validation_failed',
          title: 'Unprocessable',
          status: 422,
          detail: 'The name is required.',
          error: 'validation_failed',
          errors: { name: ['The name is required.'] },
        },
        422,
        { 'content-type': 'application/problem+json' },
      ),
    );

    const error = await v1Env(fetch)
      .users.list()
      .catch((e: unknown) => e);

    expect(error).toBeInstanceOf(CboxIdApiError);
    expect(error).toMatchObject({ status: 422, error: 'validation_failed', message: 'The name is required.', errors: { name: ['The name is required.'] } });
  });

  it('waits for a /v1 approval and repeats the request with it', async () => {
    const approval = { object: 'approval', id: 'apr_1', status: 'pending', binding_code: 'K7-4Q', expires_at: '2999-01-01T00:00:00Z' };
    const { fetch, calls } = fakeFetch(
      json(approval, 202, { 'retry-after': '0' }),
      json({ ...approval, status: 'approved' }, 200, { 'retry-after': '0' }),
      new Response(null, { status: 204 }),
    );
    const seen: string[] = [];

    await v1Env(fetch, { onApprovalRequired: (a) => void seen.push(a.binding_code) }).apps.secrets.revoke('app_1', 'sec_9');

    expect(seen).toEqual(['K7-4Q']);
    expect(calls[1]!.url).toBe(`${API}/v1/approvals/apr_1`);
    expect(calls[2]!.headers.get('cbox-approval')).toBe('apr_1');
    expect(calls[2]!.headers.get('idempotency-key')).toBe(calls[0]!.headers.get('idempotency-key'));
  });

  it('takes request() paths relative to /v1, untranslated', async () => {
    const { fetch, calls } = fakeFetch(json({ object: 'list', data: [], has_more: false, next_cursor: null }));

    await v1Env(fetch).transport.request('GET', '/users', { query: { q: 'ada' } });

    expect(calls[0]!.url).toBe(`${API}/v1/users?q=ada`);
  });

  it('routes the platform plane to /v1/admin', async () => {
    const { fetch, calls } = fakeFetch(json({ object: 'operator', id: 'op_1' }));
    const client = new PlatformClient({ apiUrl: API, accessToken: 'at', fetch });

    await client.operators.setStatus('op_1', { status: 'suspended' });

    expect(calls[0]!.method).toBe('PATCH');
    expect(calls[0]!.url).toBe(`${API}/v1/admin/operators/op_1`);
    expect(calls[0]!.body).toEqual({ status: 'suspended' });
  });

  it('has a /v1 route for every generated operation but the listed few', () => {
    expect(Object.keys(v1Routes).length).toBeGreaterThan(300);
    expect(v1Unmapped.length).toBeLessThan(15);
  });
});

describe('OrganizationClient', () => {
  it('is the workspace client under its new name', async () => {
    const { fetch, calls } = fakeFetch(json({ object: 'organization', id: `org_${ULID}`, name: 'Acme' }));
    const client = new OrganizationClient({ apiUrl: API, apiKey: 'cbid_org_key', fetch });

    const result = await client.workspace.get();

    expect(client).toBeInstanceOf(WorkspaceClient);
    expect(organizationOperations).toBe(workspaceOperations);
    expect(calls[0]!.url).toBe(`${API}/v1/organization`);
    expect(calls[0]!.headers.get('authorization')).toBe('Bearer cbid_org_key');
    expect(result.data).toMatchObject({ name: 'Acme' });
  });

  it('revokes an environment key at /v1/environment-keys', async () => {
    const { fetch, calls } = fakeFetch(new Response(null, { status: 204 }));

    await new OrganizationClient({ apiUrl: API, apiKey: 'cbid_org_key', fetch }).keys.environment.revoke('env_1', 'key_1');

    expect(calls[0]!.url).toBe(`${API}/v1/environment-keys/key_1?environment_id=env_1`);
  });

  it('still works without apiUrl, on the workspace paths', async () => {
    const { fetch, calls } = fakeFetch(json({ data: { id: 'ws_1' } }));

    await new OrganizationClient({ baseUrl: HOST, apiKey: 'cbid_ws_key', fetch }).workspace.get();

    expect(calls[0]!.url).toBe(`${HOST}/api/v1/workspace`);
  });
});

describe('ids', () => {
  it('unwraps a prefixed ULID and leaves anything else alone', () => {
    expect(rawId(`org_${ULID}`)).toBe(ULID.toLowerCase());
    expect(rawId(ULID)).toBe(ULID);
    expect(rawId('org_1')).toBe('org_1');
    expect(rawId('cid_abc')).toBe('cid_abc');
    expect(isPrefixedId(`usr_${ULID}`)).toBe(true);
    expect(isPrefixedId(ULID)).toBe(false);
  });

  it('matches the two spellings of one id, and nothing else', () => {
    expect(sameId(`org_${ULID}`, ULID.toLowerCase())).toBe(true);
    expect(sameId(ULID, `org_${ULID.toLowerCase()}`)).toBe(true);
    expect(sameId('org_1', 'org_1')).toBe(true);
    expect(sameId('org_1', '1')).toBe(false);
    expect(sameId('ABC', 'abc')).toBe(false);
    expect(sameId(`org_${ULID}`, `usr_${ULID.replace('X', 'Y')}`)).toBe(false);
    expect(sameId(null, null)).toBe(false);
    expect(sameId('', '')).toBe(false);
  });

  it('holds a sign-in bound with a prefixed id to the raw org claim', async () => {
    const raw = ULID.toLowerCase();
    const inst = await fakeInstance({ userinfo: { sub: 'user-1', org: raw } });
    inst.setTokenResponse({
      access_token: 'access-abc',
      id_token: await inst.signIdToken({ iss: ISSUER, aud: 'client-abc', sub: 'user-1', nonce: NONCE, org: raw }),
      token_type: 'Bearer',
    });
    vi.stubGlobal('fetch', inst.fetchMock);
    const client = new CboxIdClient({ issuer: ISSUER, clientId: 'client-abc', clientSecret: 's', redirectUri: 'https://app.test/cb' });

    const user = await client.authenticate({
      params: { code: 'c', state: 'state-1' },
      stored: { state: 'state-1', codeVerifier: 'v', nonce: NONCE, organization: `org_${ULID}` },
    });

    expect(user.organizationId).toBe(raw);
  });
});

describe('webhook event types', () => {
  it('maps the old names and the id.* names onto each other', () => {
    expect(currentWebhookEventType('organization.member_added')).toBe('id.organization.member_added');
    expect(currentWebhookEventType('user.login')).toBe('id.user.signed_in');
    expect(currentWebhookEventType('id.user.created')).toBe('id.user.created');
    expect(currentWebhookEventType('*')).toBe('*');
    expect(legacyWebhookEventType('id.user.signed_in')).toBe('user.login');
    expect(legacyWebhookEventType('id.organization.member_added')).toBe('organization.member_added');
    expect(legacyWebhookEventType('user.created')).toBe('user.created');
    expect(webhookEventTypeAliases('user.login')).toEqual(['user.login', 'id.user.signed_in']);
  });

  it.each([
    ['organization.member_added', 'organization.member_added', true],
    ['id.organization.member_added', 'organization.member_added', true],
    ['organization.member_added', 'id.organization.member_added', true],
    ['id.user.signed_in', 'user.login', true],
    ['user.login', 'id.user.signed_in', true],
    ['id.user.login', 'user.login', true],
    ['user.created', 'user.deleted', false],
    ['id.user.created', 'user.deleted', false],
    ['', 'user.created', false],
  ] as const)('isWebhookEventType(%s, %s) is %s', (actual, expected, result) => {
    expect(isWebhookEventType(actual, expected)).toBe(result);
  });
});

describe('apiUrl outside the management clients', () => {
  it('leases a pipe token from /v1/pipe-leases', async () => {
    const mock = vi.fn(async (_input: unknown, _init?: RequestInit) => json({ access_token: 'gho', provider: 'github', user_id: 'u', connection_id: 'c', scopes: [], lease_expires_at: 'x', metadata: {} }));
    vi.stubGlobal('fetch', mock);

    await new VaultClient(ISSUER, 't', 10_000, { apiUrl: API }).leasePipeToken('github', { purpose: 'p', userId: 'u' });

    expect(mock.mock.calls[0]![0]).toBe(`${API}/v1/pipe-leases?provider=github`);
  });

  it('refuses a plain-http apiUrl on the vault client', () => {
    expect(() => new VaultClient(ISSUER, 't', 10_000, { apiUrl: 'http://api.example.com' })).toThrow(ConfigurationError);
  });

  it('leases a vault secret from /v1, and keeps provisioning on the issuer', async () => {
    const mock = vi.fn(async (_input: unknown, _init?: RequestInit) => json({ secret_id: 's', provider: 'stripe', secret: 'x', expires_at: 'y' }));
    vi.stubGlobal('fetch', mock);
    const vault = new VaultClient(ISSUER, 't', 10_000, { apiUrl: `${API}/v1` });

    await vault.lease('sec_1', 'charge');
    await vault.rotate('sec_1', 'new');

    expect(mock.mock.calls.map((c) => c[0])).toEqual([`${API}/v1/vault-secrets/sec_1/lease`, `${ISSUER}/api/v1/vault/secrets/sec_1/rotate`]);
  });

  it('pushes the manifest to /v1/app-manifests, minting the token at the issuer', async () => {
    const urls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL) => {
        const url = String(input);
        urls.push(url);
        if (url.endsWith('/.well-known/openid-configuration')) return json({ issuer: ISSUER, token_endpoint: `${ISSUER}/oauth/token` });
        if (url === `${ISSUER}/oauth/token`) return json({ access_token: 'tok', token_type: 'Bearer' });
        return new Response('nope', { status: 500 });
      }),
    );

    await publishManifest({ issuer: ISSUER, clientId: 'cid', clientSecret: 's', apiUrl: API }, { permissions: [], roles: [] }).catch(() => undefined);

    expect(urls).toContain(`${ISSUER}/oauth/token`);
    expect(urls).toContain(`${API}/v1/app-manifests`);
  });
});
