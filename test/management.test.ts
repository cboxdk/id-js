import { readFile } from 'node:fs/promises';
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { describe, expect, expectTypeOf, it, vi } from 'vitest';
import { generateAll } from '../scripts/generate-management.js';
import {
  AccountClient,
  ApprovalDeniedError,
  ApprovalExpiredError,
  CboxIdApiError,
  ConfigurationError,
  EnvironmentClient,
  ManagementNetworkError,
  PlatformClient,
  WorkspaceClient,
  createDPoPSigner,
  environmentOperations,
  generateDPoPKeyPair,
  workspaceOperations,
  type ApiResponse,
  type EnvironmentApi,
  type PendingApprovalResult,
} from '../src/management/index.js';

const HOST = 'https://acme.test';
const API = `${HOST}/api/v1`;
const KEY = 'cbid_env_test_key';

interface Call {
  url: string;
  method: string;
  headers: Headers;
  body: unknown;
}

type Reply = Response | Error | ((call: Call) => Response | Error);

/** A fetch that answers from a queue and records every request it saw. */
function fakeFetch(...replies: Reply[]) {
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
    const reply = typeof next === 'function' ? next(call) : next;
    if (reply instanceof Error) throw reply;
    return reply;
  });

  return { fetch: fn as unknown as typeof fetch, calls };
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

function env(fetchImpl: typeof fetch, extra: Partial<ConstructorParameters<typeof EnvironmentClient>[0]> = {}) {
  return new EnvironmentClient({
    baseUrl: HOST,
    apiKey: KEY,
    fetch: fetchImpl,
    retry: { baseDelayMs: 0 },
    approvalPollIntervalMs: 0,
    ...extra,
  });
}

const app = { id: 'app_1', client_id: 'cid', name: 'Billing' };
const held = (id = 'apr_1', pollUrl = `${API}/action-approvals/${id}`) =>
  json(
    {
      error: 'approval_required',
      message: 'This action needs approval.',
      approval: { id, status: 'pending', binding_code: 'K7-4Q', expires_at: '2999-01-01T00:00:00Z', poll_url: pollUrl },
    },
    202,
    { 'retry-after': '0' },
  );
const approvalStatus = (status: string, id = 'apr_1') => json({ data: { id, status } }, 200, { 'retry-after': '0' });

describe('management client — requests', () => {
  it('sends the key as a bearer token against {host}/api/v1 and unwraps the envelope', async () => {
    const { fetch, calls } = fakeFetch(json({ data: app }, 201));
    const result = await env(fetch).apps.create({ name: 'Billing', type: 'web' });

    expect(calls[0]!.url).toBe(`${API}/apps`);
    expect(calls[0]!.method).toBe('POST');
    expect(calls[0]!.headers.get('authorization')).toBe(`Bearer ${KEY}`);
    expect(calls[0]!.headers.get('content-type')).toBe('application/json');
    expect(calls[0]!.body).toEqual({ name: 'Billing', type: 'web' });
    expect(result.status).toBe(201);
    expect(result.data).toEqual(app);
    expectTypeOf(result.data).toEqualTypeOf<EnvironmentApi.App>();
    expect(result.replayed).toBe(false);
  });

  it('puts path parameters in order, encoded, and GET input in the query string', async () => {
    const { fetch, calls } = fakeFetch(json({ data: [], meta: { has_more: false } }), json({ data: [] }));
    const client = env(fetch);

    await client.members.list('org/1', { limit: 5 });
    await client.roles.list({ client_id: 'cid', organization_id: 'org_1' });

    expect(calls[0]!.url).toBe(`${API}/organizations/org%2F1/members?limit=5`);
    expect(calls[0]!.headers.get('idempotency-key')).toBeNull();
    expect(calls[1]!.url).toBe(`${API}/roles?client_id=cid&organization_id=org_1`);
  });

  it('answers a 204 with no data', async () => {
    const { fetch } = fakeFetch(new Response(null, { status: 204 }));
    const result = await env(fetch).apps.delete('app_1');

    expect(result.status).toBe(204);
    expect(result.data).toBeUndefined();
  });
});

describe('management client — idempotency and retries', () => {
  it('sends a generated Idempotency-Key on a write and reuses it on every retry', async () => {
    const { fetch, calls } = fakeFetch(
      json({ error: 'server_error', message: 'Boom.' }, 503),
      new TypeError('fetch failed'),
      json({ error: 'rate_limited', message: 'Slow down.' }, 429, { 'retry-after': '0' }),
      json({ data: app }, 201, { 'idempotent-replayed': 'true' }),
    );
    const result = await env(fetch).apps.create({ name: 'Billing' });

    expect(calls).toHaveLength(4);
    const keys = calls.map((c) => c.headers.get('idempotency-key'));
    expect(keys[0]).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(new Set(keys).size).toBe(1);
    expect(calls.every((c) => JSON.stringify(c.body) === JSON.stringify({ name: 'Billing' }))).toBe(true);
    expect(result.replayed).toBe(true);
    expect(result.idempotencyKey).toBe(keys[0]);
  });

  it('uses the caller’s own Idempotency-Key, and a fresh one per call otherwise', async () => {
    const { fetch, calls } = fakeFetch(json({ data: app }, 201), json({ data: app }, 201), json({ data: app }, 201));
    const client = env(fetch);

    await client.apps.create({ name: 'A' }, { idempotencyKey: 'mine-1' });
    await client.apps.create({ name: 'A' });
    await client.apps.create({ name: 'A' });

    expect(calls[0]!.headers.get('idempotency-key')).toBe('mine-1');
    expect(calls[1]!.headers.get('idempotency-key')).not.toBe(calls[2]!.headers.get('idempotency-key'));
  });

  it('waits out 409 idempotency_in_progress with the same key', async () => {
    const { fetch, calls } = fakeFetch(
      json({ error: 'idempotency_in_progress', message: 'Still running.' }, 409, { 'retry-after': '0' }),
      json({ data: app }, 201, { 'idempotent-replayed': 'true' }),
    );
    const result = await env(fetch).apps.create({ name: 'A' });

    expect(calls[0]!.headers.get('idempotency-key')).toBe(calls[1]!.headers.get('idempotency-key'));
    expect(result.replayed).toBe(true);
  });

  it('does not retry a 4xx, and gives up after maxRetries with a typed error', async () => {
    const conflict = fakeFetch(json({ error: 'slug_taken', message: 'Taken.' }, 409));
    await expect(env(conflict.fetch).organizations.create({ name: 'Acme', slug: 'acme' })).rejects.toMatchObject({
      status: 409,
      error: 'slug_taken',
    });
    expect(conflict.calls).toHaveLength(1);

    const down = fakeFetch(new TypeError('a'), new TypeError('b'), new TypeError('c'));
    const error = await env(down.fetch, { retry: { maxRetries: 2, baseDelayMs: 0 } })
      .apps.create({ name: 'A' }, { idempotencyKey: 'k-1' })
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ManagementNetworkError);
    expect((error as ManagementNetworkError).idempotencyKey).toBe('k-1');
    expect(down.calls).toHaveLength(3);
  });

  it('throws a 429 at once when Retry-After is longer than it may wait', async () => {
    const { fetch, calls } = fakeFetch(json({ error: 'rate_limited', message: 'Slow down.' }, 429, { 'retry-after': '120' }));
    const error = (await env(fetch).apps.list().catch((e: unknown) => e)) as CboxIdApiError;

    expect(error).toBeInstanceOf(CboxIdApiError);
    expect(error.status).toBe(429);
    expect(error.retryAfter).toBe(120);
    expect(calls).toHaveLength(1);
  });
});

describe('management client — errors', () => {
  it('types a validation failure, with its field errors and request id, and never echoes the body', async () => {
    const { fetch } = fakeFetch(
      json(
        {
          error: 'validation_failed',
          message: 'The given data was invalid.',
          errors: { name: ['The name field is required.'] },
          request_id: 'req_42',
        },
        422,
        { 'x-request-id': 'req_from_header' },
      ),
    );
    const error = (await env(fetch)
      .users.create({ email: 'a@b.test', password: 'hunter2-secret' })
      .catch((e: unknown) => e)) as CboxIdApiError;

    expect(error).toBeInstanceOf(CboxIdApiError);
    expect(error.status).toBe(422);
    expect(error.error).toBe('validation_failed');
    expect(error.isValidationError).toBe(true);
    expect(error.message).toBe('The given data was invalid.');
    expect(error.errors).toEqual({ name: ['The name field is required.'] });
    expect(error.requestId).toBe('req_42');
    expect(JSON.stringify(error)).not.toContain('hunter2');
    expect(error.message).not.toContain('hunter2');
  });

  it('falls back to the X-Request-Id header when the body has no request_id', async () => {
    const { fetch } = fakeFetch(new Response('<html>Bad gateway</html>', { status: 404, headers: { 'x-request-id': 'req_7' } }));
    await expect(env(fetch).apps.get('app_1')).rejects.toMatchObject({ status: 404, requestId: 'req_7' });
  });

  it('reads an RFC 6750 bearer challenge, and a non-JSON body', async () => {
    const challenge = fakeFetch(json({ error: 'invalid_token', error_description: 'Expired.' }, 401));
    await expect(env(challenge.fetch).apps.list()).rejects.toMatchObject({ error: 'invalid_token', message: 'Expired.', status: 401 });

    const html = fakeFetch(new Response('<html>Forbidden</html>', { status: 403 }));
    await expect(env(html.fetch).apps.list()).rejects.toMatchObject({ error: 'http_403', message: 'HTTP 403' });
  });
});

describe('management client — approvals', () => {
  it('shows the binding code, polls, then repeats with Cbox-Approval and the same Idempotency-Key', async () => {
    const secret = { id: 'sec_2', secret: 'cbid_secret_shown_once', ends_with: 'once' };
    const { fetch, calls } = fakeFetch(
      held(),
      approvalStatus('pending'),
      approvalStatus('approved'),
      json({ data: secret }, 201),
    );
    const onApprovalRequired = vi.fn();
    const result = await env(fetch, { onApprovalRequired }).apps.secrets.rotate('app_1', { grace_seconds: 3600 });

    expect(onApprovalRequired).toHaveBeenCalledTimes(1);
    expect(onApprovalRequired.mock.calls[0]![0]).toMatchObject({ id: 'apr_1', binding_code: 'K7-4Q' });
    expect(onApprovalRequired.mock.calls[0]![1]).toMatchObject({ action: 'apps.secrets.rotate', danger: 'critical' });

    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      `POST ${API}/apps/app_1/secrets`,
      `GET ${API}/action-approvals/apr_1`,
      `GET ${API}/action-approvals/apr_1`,
      `POST ${API}/apps/app_1/secrets`,
    ]);
    expect(calls[0]!.headers.get('cbox-approval')).toBeNull();
    expect(calls[1]!.headers.get('authorization')).toBe(`Bearer ${KEY}`);
    expect(calls[3]!.headers.get('cbox-approval')).toBe('apr_1');
    expect(calls[3]!.headers.get('idempotency-key')).toBe(calls[0]!.headers.get('idempotency-key'));
    expect(calls[3]!.body).toEqual({ grace_seconds: 3600 });
    expect(result.data).toEqual(secret);
  });

  it('throws a typed error when the person denies it, or nobody answers', async () => {
    const denied = fakeFetch(held(), approvalStatus('denied'));
    await expect(env(denied.fetch).apps.secrets.rotate('app_1', { grace_seconds: 0 })).rejects.toBeInstanceOf(ApprovalDeniedError);
    expect(denied.calls).toHaveLength(2);

    const expired = fakeFetch(held(), approvalStatus('expired'));
    const error = await env(expired.fetch).apps.secrets.rotate('app_1', { grace_seconds: 0 }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApprovalExpiredError);
    expect((error as ApprovalExpiredError).approval.id).toBe('apr_1');
  });

  it('hands the pending approval back with approval: "return", and resume() finishes the job', async () => {
    const { fetch, calls } = fakeFetch(held(), approvalStatus('approved'), json({ data: { id: 'sec_3' } }, 201));
    const onApprovalRequired = vi.fn();
    const outcome = await env(fetch, { onApprovalRequired }).apps.secrets.rotate('app_1', { grace_seconds: 0 }, { approval: 'return' });

    expectTypeOf(outcome).toEqualTypeOf<
      ApiResponse<EnvironmentApi.AppsSecretsRotateResponse> | PendingApprovalResult<EnvironmentApi.AppsSecretsRotateResponse>
    >();
    expect(outcome.pending).toBe(true);
    if (!outcome.pending) throw new Error('expected a pending approval');
    expect(outcome.approval.binding_code).toBe('K7-4Q');
    expect(outcome.action).toBe('apps.secrets.rotate');
    expect(calls).toHaveLength(1);
    expect(onApprovalRequired).not.toHaveBeenCalled();

    const done = await outcome.resume();
    expect(done.data).toEqual({ id: 'sec_3' });
    expect(calls[2]!.headers.get('cbox-approval')).toBe('apr_1');
    expect(calls[2]!.headers.get('idempotency-key')).toBe(outcome.idempotencyKey);
  });

  it('never sends the credential to a poll_url on another origin', async () => {
    const { fetch, calls } = fakeFetch(held('apr_1', 'https://evil.test/api/v1/action-approvals/apr_1'));
    await expect(env(fetch).apps.secrets.rotate('app_1', { grace_seconds: 0 })).rejects.toThrow(/another origin/);
    expect(calls).toHaveLength(1);
  });

  it('polls the workspace plane’s own approval route', async () => {
    const { fetch, calls } = fakeFetch(
      held('apr_9', 'https://api.cboxid.test/api/v1/workspace/action-approvals/apr_9'),
      approvalStatus('approved', 'apr_9'),
      new Response(null, { status: 204 }),
    );
    const ws = new WorkspaceClient({ baseUrl: 'https://api.cboxid.test', apiKey: 'cbid_ws_k', fetch, retry: { baseDelayMs: 0 } });
    await ws.keys.workspace.revoke('wk_1');

    expect(calls[1]!.url).toBe('https://api.cboxid.test/api/v1/workspace/action-approvals/apr_9');
    expect(calls[2]!.headers.get('cbox-approval')).toBe('apr_9');
  });
});

describe('management client — pagination', () => {
  it('follows meta.next_cursor on a cursor-paged list', async () => {
    const { fetch, calls } = fakeFetch(
      json({ data: [{ id: 'o1' }, { id: 'o2' }], meta: { limit: 2, has_more: true, next_cursor: 'c2' } }),
      json({ data: [{ id: 'o3' }], meta: { limit: 2, has_more: false, next_cursor: null } }),
    );
    const ids: string[] = [];
    for await (const org of env(fetch).organizations.listAll({ limit: 2 })) {
      ids.push(org.id ?? '');
    }

    expect(ids).toEqual(['o1', 'o2', 'o3']);
    expect(calls[0]!.url).toBe(`${API}/organizations?limit=2`);
    expect(calls[1]!.url).toBe(`${API}/organizations?limit=2&after=c2`);
  });

  it('follows meta.next_page on a numbered list, and stops when has_more is false', async () => {
    const { fetch, calls } = fakeFetch(
      json({ data: [{ id: 'm1' }], meta: { page: 1, has_more: true, next_page: 2 } }),
      json({ data: [{ id: 'm2' }], meta: { page: 2, has_more: false, next_page: null } }),
    );
    const ws = new WorkspaceClient({ apiKey: 'cbid_ws_k', fetch });
    const ids: string[] = [];
    for await (const member of ws.team.listAll()) {
      ids.push(member.id ?? '');
    }

    expect(ids).toEqual(['m1', 'm2']);
    expect(calls[0]!.url).toBe('https://api.cboxid.com/api/v1/workspace/members');
    expect(calls[1]!.url).toBe('https://api.cboxid.com/api/v1/workspace/members?page=2');
  });

  it('stops reading pages when the caller breaks out', async () => {
    const { fetch, calls } = fakeFetch(json({ data: [{ id: 'u1' }, { id: 'u2' }], meta: { has_more: true, next_cursor: 'x' } }));
    for await (const user of env(fetch).users.listAll()) {
      expect(user.id).toBe('u1');
      break;
    }
    expect(calls).toHaveLength(1);
  });
});

describe('management client — credentials', () => {
  it('refuses a key from the wrong plane, a key where none is accepted, and plain http', () => {
    expect(() => new EnvironmentClient({ baseUrl: HOST, apiKey: 'cbid_ws_x' })).toThrow(ConfigurationError);
    expect(() => new WorkspaceClient({ apiKey: 'cbid_env_x' })).toThrow(ConfigurationError);
    expect(() => new PlatformClient({ apiKey: 'cbid_ws_x' })).toThrow(/accepts no management key/);
    expect(() => new AccountClient({ baseUrl: HOST, apiKey: 'cbid_env_x' })).toThrow(ConfigurationError);
    expect(() => new EnvironmentClient({ baseUrl: 'http://acme.test', apiKey: KEY })).toThrow(/https/);
    expect(() => new EnvironmentClient({ baseUrl: HOST })).toThrow(/exactly one/);
    expect(() => new EnvironmentClient({ baseUrl: 'http://localhost:8000', apiKey: KEY })).not.toThrow();
  });

  it('drives any environment from the platform root with one token and Cbox-Environment', async () => {
    const { fetch, calls } = fakeFetch(
      json({ data: [] }),
      held('apr_1', 'https://api.cboxid.test/api/v1/action-approvals/apr_1'),
      approvalStatus('approved'),
      json({ data: app }, 201),
    );
    const root = new EnvironmentClient({
      baseUrl: 'https://api.cboxid.test',
      accessToken: 'root_token',
      environment: 'acme-staging',
      fetch,
      approvalPollIntervalMs: 0,
    });

    await root.apps.list();
    await root.apps.create({ name: 'A' });

    expect(calls[0]!.url).toBe('https://api.cboxid.test/api/v1/apps');
    expect(calls).toHaveLength(4);
    expect(calls[3]!.headers.get('cbox-approval')).toBe('apr_1');
    expect(calls.every((c) => c.headers.get('cbox-environment') === 'acme-staging')).toBe(true);
    expect(calls.every((c) => c.headers.get('authorization') === 'Bearer root_token')).toBe(true);
  });

  it('refuses `environment` with a key, or on another plane', () => {
    expect(() => new EnvironmentClient({ baseUrl: HOST, apiKey: KEY, environment: 'acme' })).toThrow(ConfigurationError);
    expect(() => new WorkspaceClient({ accessToken: 't', environment: 'acme' })).toThrow(/environment plane/);
  });

  it('calls a token provider before every request', async () => {
    const { fetch, calls } = fakeFetch(json({ data: [] }), json({ data: [] }));
    let n = 0;
    const client = new AccountClient({ baseUrl: `${HOST}/api/v1/`, accessToken: async () => `tok_${++n}`, fetch });

    await client.request('GET', '/me/profile');
    await client.request('GET', '/me/profile');

    expect(calls[0]!.url).toBe(`${API}/me/profile`);
    expect(calls.map((c) => c.headers.get('authorization'))).toEqual(['Bearer tok_1', 'Bearer tok_2']);
  });

  it('presents a DPoP-bound token with a proof that pins method, URL and token', async () => {
    const keyPair = await generateDPoPKeyPair();
    const dpop = await createDPoPSigner(keyPair);
    const { fetch, calls } = fakeFetch(json({ data: app }, 201));
    const client = new EnvironmentClient({ baseUrl: HOST, accessToken: 'at_123', dpop, fetch });

    await client.apps.create({ name: 'A' });

    expect(calls[0]!.headers.get('authorization')).toBe('DPoP at_123');
    const proof = calls[0]!.headers.get('dpop')!;
    const header = decodeProtectedHeader(proof);
    expect(header.typ).toBe('dpop+jwt');
    const { payload } = await jwtVerify(proof, await importJWK(header.jwk!, 'ES256'));
    expect(payload.htm).toBe('POST');
    expect(payload.htu).toBe(`${API}/apps`);
    const ath = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('at_123'))).toString('base64url');
    expect(payload.ath).toBe(ath);
    expect(typeof decodeJwt(proof).jti).toBe('string');
  });

  it('answers a DPoP nonce challenge once, with the nonce in the next proof', async () => {
    const dpop = await createDPoPSigner(await generateDPoPKeyPair());
    const { fetch, calls } = fakeFetch(
      json({ error: 'use_dpop_nonce', error_description: 'Nonce required.' }, 401, { 'dpop-nonce': 'n-1' }),
      json({ data: [] }),
    );
    await new EnvironmentClient({ baseUrl: HOST, accessToken: 'at', dpop, fetch }).apps.list();

    expect(decodeJwt(calls[0]!.headers.get('dpop')!).nonce).toBeUndefined();
    expect(decodeJwt(calls[1]!.headers.get('dpop')!).nonce).toBe('n-1');
  });
});

describe('generated surface', () => {
  it('names methods after x-action, with the spec’s method, path, scope and danger', () => {
    const client = env(fakeFetch().fetch);

    expect(typeof client.apps.create).toBe('function');
    expect(typeof client.apps.secrets.rotate).toBe('function');
    expect(typeof client.sso.connections.requireSso).toBe('function');
    expect(typeof client.organizations.listAll).toBe('function');
    expect(typeof new WorkspaceClient({ apiKey: 'cbid_ws_k' }).environments.create).toBe('function');
    // The account and platform planes prefix every action with the plane; the client drops it.
    expect(typeof new AccountClient({ baseUrl: HOST, accessToken: 't' }).sessions.revokeOthers).toBe('function');
    expect(typeof new PlatformClient({ accessToken: 't' }).workspaces.create).toBe('function');

    expect(environmentOperations['apps.create']).toMatchObject({ method: 'POST', path: '/apps', scope: 'apps:write', danger: 'critical' });
    expect(environmentOperations['apps.secrets.rotate']).toMatchObject({
      action: 'apps.secrets.rotate',
      operationId: 'apps_secrets_rotate',
      method: 'POST',
      path: '/apps/{id}/secrets',
      pathParams: ['id'],
      approval: true,
    });
    expect(environmentOperations['organizations.list']).toMatchObject({ method: 'GET', path: '/organizations', pagination: 'cursor' });
    expect(environmentOperations['members.roles.grant']).toMatchObject({
      method: 'PUT',
      path: '/organizations/{organization_id}/members/{user_id}/roles/{role_id}',
      pathParams: ['organization_id', 'user_id', 'role_id'],
    });
    expect(workspaceOperations['environments.create']).toMatchObject({
      method: 'POST',
      path: '/workspace/environments',
      scope: 'environments:write',
      danger: 'critical',
    });
    expect(workspaceOperations['team.list']).toMatchObject({ pagination: 'page' });
    // Scope and danger come from x-scope / x-danger.
    expect(environmentOperations['audit_logs.events.create']).toMatchObject({
      method: 'POST',
      path: '/audit-logs/events',
      scope: 'audit_logs:write',
      danger: 'write',
    });
    // Wave 7: typed key answers, signature schemes, log-stream tests, portal-link lifecycle.
    expectTypeOf<EnvironmentApi.KeysCreateResponse['data']>().toEqualTypeOf<EnvironmentApi.ManagementKey>();
    expectTypeOf<EnvironmentApi.LogStreamsTestResponse['data']>().toEqualTypeOf<EnvironmentApi.LogStreamTest>();
    expect(environmentOperations['webhooks.signature_scheme.change']).toMatchObject({ method: 'POST', path: '/webhooks/{id}/signature-scheme' });
    expect(typeof client.webhooks.signatureScheme.change).toBe('function');
    expect(typeof client.logStreams.test).toBe('function');
    expect(typeof client.organizations.portalLinks.list).toBe('function');
    expect(typeof client.organizations.portalLinks.revoke).toBe('function');
    expect(environmentOperations['audit_logs.verify']).toMatchObject({ method: 'GET', path: '/audit-logs/verify', scope: 'audit_logs:read' });
    expectTypeOf<EnvironmentApi.OrganizationsPortalLinksCreateBody['intents']>().toEqualTypeOf<
      Array<'sso' | 'dsync' | 'domain_verification' | 'log_streams' | 'certificate_renewal' | 'audit_logs'>
    >();
  });

  it('is exactly what the generator makes of the vendored specs (regenerate with `npm run generate`)', async () => {
    for (const [path, result] of await generateAll()) {
      expect(await readFile(path, 'utf8'), path).toBe(result.code);
    }
  });
});
