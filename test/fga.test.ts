import { describe, expect, expectTypeOf, it, vi } from 'vitest';
import { EnvironmentClient, fgaTuple, type EnvironmentApi } from '../src/management/index.js';

const HOST = 'https://acme.test';
const API = `${HOST}/api/v1`;

function fakeFetch(...bodies: unknown[]) {
  const calls: { url: string; method: string; body: unknown; headers: Headers }[] = [];
  const fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method ?? 'GET',
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
      headers: new Headers(init?.headers),
    });
    return new Response(JSON.stringify(bodies.shift()), { status: 200, headers: { 'content-type': 'application/json' } });
  });

  return { fetch: fetch as unknown as typeof globalThis.fetch, calls };
}

function env(fetch: typeof globalThis.fetch) {
  return new EnvironmentClient({ baseUrl: HOST, apiKey: 'cbid_env_test', fetch, retry: { baseDelayMs: 0 } });
}

const check = {
  allowed: true,
  resource_type: 'document',
  resource_id: 'leave',
  relation: 'viewer',
  subject: { type: 'user', id: 'alice', relation: null },
  consistency_token: '7.9f3c1a7be2d0',
};

describe('feature flag evaluation', () => {
  it('evaluates every flag for a user in an organization', async () => {
    const data = {
      user_id: 'usr_1',
      organization_id: 'org_1',
      feature_flags: ['acme-beta'],
      evaluations: [
        { key: 'acme-beta', enabled: true, reason: 'organization_target' },
        { key: 'old-reports', enabled: false, reason: 'disabled' },
      ],
    };
    const { fetch, calls } = fakeFetch({ data });

    const result = await env(fetch).featureFlags.evaluate({ user_id: 'usr_1', organization_id: 'org_1' });

    expect(calls[0]!.url).toBe(`${API}/feature-flags/evaluate?user_id=usr_1&organization_id=org_1`);
    expect(result.data.feature_flags).toEqual(['acme-beta']);
    expect(result.data.evaluations[1]!.reason).toBe('disabled');
  });
});

describe('fine-grained authorization', () => {
  it('writes tuples, then checks at least as fresh as the write', async () => {
    const { fetch, calls } = fakeFetch({ data: { written: 1, deleted: 0, consistency_token: '7.9f3c1a7be2d0' } }, { data: check });
    const client = env(fetch);

    const written = await client.fga.tuples.write({
      tuples: [{ resource_type: 'group', resource_id: 'eng', relation: 'member', subject: { type: 'user', id: 'alice' } }],
    });
    const answer = await client.fga.check({
      resource_type: 'document',
      resource_id: 'leave',
      relation: 'viewer',
      subject_type: 'user',
      subject_id: 'alice',
      consistency_token: written.data.consistency_token,
    });

    expect(calls[0]!.url).toBe(`${API}/fga/tuples`);
    expect(calls[0]!.method).toBe('POST');
    expect(calls[0]!.headers.get('idempotency-key')).not.toBeNull();
    expect(calls[1]!.url).toBe(
      `${API}/fga/check?resource_type=document&resource_id=leave&relation=viewer&subject_type=user&subject_id=alice&consistency_token=7.9f3c1a7be2d0`,
    );
    expect(answer.data.allowed).toBe(true);
    expectTypeOf(answer.data.allowed).toEqualTypeOf<boolean>();
  });

  it('sends a batch as checks[] in the tuple notation', async () => {
    const { fetch, calls } = fakeFetch({ data: { results: [check, { ...check, allowed: false }], consistency_token: '7.a' } });

    const result = await env(fetch).fga.checkBatch({
      checks: [
        fgaTuple({ resource_type: 'document', resource_id: 'leave', relation: 'viewer', subject: { type: 'user', id: 'alice' } }),
        'document:readme#editor@user:alice',
      ],
    });

    const url = new URL(calls[0]!.url);
    expect(url.pathname).toBe('/api/v1/fga/check/batch');
    expect(url.searchParams.getAll('checks[]')).toEqual(['document:leave#viewer@user:alice', 'document:readme#editor@user:alice']);
    expect(result.data.results.map((r) => r.allowed)).toEqual([true, false]);
  });

  it('deletes tuples, lists resources and subjects, and reads and replaces the schema', async () => {
    const schema = { defined: true, schema: 'type user', version: 2, types: [], updated_at: null, consistency_token: '8.b' };
    const { fetch, calls } = fakeFetch(
      { data: { written: 0, deleted: 1, consistency_token: '8.a' } },
      { data: [{ type: 'document', id: 'leave' }], meta: { has_more: false, next_cursor: null } },
      { data: [{ type: 'user', id: 'alice' }], meta: { has_more: false, next_cursor: null } },
      { data: schema },
      { data: schema },
    );
    const client = env(fetch);
    const tuple = { resource_type: 'group', resource_id: 'eng', relation: 'member', subject: { type: 'user', id: 'alice' } };

    expect((await client.fga.tuples.delete({ tuples: [tuple] })).data.deleted).toBe(1);
    const resources = await client.fga.resources.list({ resource_type: 'document', relation: 'viewer', subject_type: 'user', subject_id: 'alice' });
    const subjects = await client.fga.subjects.list({ resource_type: 'document', resource_id: 'leave', relation: 'viewer', subject_type: 'user', consistency_token: '8.a' });
    await client.fga.schema.get();
    await client.fga.schema.update({ schema: 'type user' });

    expect(calls.map((c) => `${c.method} ${new URL(c.url).pathname}`)).toEqual([
      'POST /api/v1/fga/tuples/delete',
      'GET /api/v1/fga/resources',
      'GET /api/v1/fga/subjects',
      'GET /api/v1/fga/schema',
      'PUT /api/v1/fga/schema',
    ]);
    expect(new URL(calls[2]!.url).searchParams.get('consistency_token')).toBe('8.a');
    expect(calls[4]!.body).toEqual({ schema: 'type user' });
    expect(resources.data).toEqual([{ type: 'document', id: 'leave' }]);
    expect(subjects.data[0]!.id).toBe('alice');
    expectTypeOf(resources.data).toEqualTypeOf<EnvironmentApi.FgaObject[]>();
  });
});

describe('fgaTuple', () => {
  it('writes one subject and a userset', () => {
    expect(fgaTuple({ resource_type: 'document', resource_id: 'readme', relation: 'viewer', subject: { type: 'user', id: 'alice' } })).toBe(
      'document:readme#viewer@user:alice',
    );
    expect(
      fgaTuple({ resource_type: 'folder', resource_id: 'policies', relation: 'viewer', subject: { type: 'group', id: 'eng', relation: 'member' } }),
    ).toBe('folder:policies#viewer@group:eng#member');
    // Ids are the app's own and may carry a colon.
    expect(fgaTuple({ resource_type: 'doc', resource_id: 'a:b', relation: 'viewer', subject: { type: 'user', id: 'u:1' } })).toBe(
      'doc:a:b#viewer@user:u:1',
    );
  });

  it('refuses a part the notation cannot carry', () => {
    expect(() => fgaTuple({ resource_type: 'doc', resource_id: 'a#b', relation: 'viewer', subject: { type: 'user', id: 'x' } })).toThrow(TypeError);
    expect(() => fgaTuple({ resource_type: 'doc', resource_id: 'a', relation: 'viewer', subject: { type: 'user', id: 'x@y' } })).toThrow(TypeError);
    expect(() => fgaTuple({ resource_type: 'doc:x', resource_id: 'a', relation: 'viewer', subject: { type: 'user', id: 'x' } })).toThrow(TypeError);
    expect(() => fgaTuple({ resource_type: 'doc', resource_id: '', relation: 'viewer', subject: { type: 'user', id: 'x' } })).toThrow(TypeError);
  });
});

describe('an action that answers 202 Accepted', () => {
  it('reads its own 202 body as the result, not as an approval', async () => {
    const directory = { id: 'dir_1', name: 'Workday' };
    const fetch = vi.fn(async () =>
      new Response(JSON.stringify({ data: directory }), { status: 202, headers: { 'content-type': 'application/json' } }),
    );

    const result = await env(fetch as unknown as typeof globalThis.fetch).directories.sync('dir_1', { full: true });

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(result.status).toBe(202);
    expect(result.data).toEqual(directory);
  });
});
