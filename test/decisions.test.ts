import { afterEach, expect, it, vi } from 'vitest';
import { checkPermissions } from '../src/decisions.js';
import { AuthenticationError } from '../src/errors.js';

const config = { issuer: 'https://id.example.test', clientId: 'app-a' };
const body = () => ({
  mode: 'rbac', subject: { type: 'user', id: 'person-a' }, organization: 'org-a',
  client_id: 'app-a', org_role: 'admin', organization_active: true, allowed: true,
  results: [{ permission: 'documents:read', allowed: true }],
});
const check = () => checkPermissions(config, 'secret-token', 'person-a', 'org-a', ['documents:read']);
afterEach(() => vi.unstubAllGlobals());

it('binds the request and rechecks revocation without treating shared Admin as an app grant', async () => {
  const current = body();
  const fetch = vi.fn(async (_url: unknown, init?: RequestInit) => {
    expect(init?.redirect).toBe('error');
    expect(JSON.parse(String(init?.body))).toEqual({ subject: 'person-a', org: 'org-a', permission: ['documents:read'] });
    return Response.json(current);
  });
  vi.stubGlobal('fetch', fetch);
  expect((await check()).allows('documents:read')).toBe(true);
  current.allowed = false;
  current.results[0]!.allowed = false;
  const revoked = await check();
  expect(revoked.organizationRole).toBe('admin');
  expect(revoked.allowed()).toBe(false);
  expect(revoked.allows('documents:write')).toBe(false);
  expect(fetch).toHaveBeenCalledTimes(2);
});

it.each([
  { subject: { type: 'user', id: 'person-b' } }, { subject: { type: 'client', id: 'person-a' } },
  { organization: 'org-b' }, { client_id: 'app-b' }, { mode: 'fga' }, { org_role: 'superadmin' },
  { org_role: undefined }, { organization_active: 'true' }, { organization_active: false },
  { allowed: false }, { results: [] }, { results: [{ permission: 'documents:write', allowed: true }] },
  { results: [{ permission: 'documents:read', allowed: 'true' }] },
])('fails closed on a mismatched or malformed response: %j', async override => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ ...body(), ...override })));
  await expect(check()).rejects.toBeInstanceOf(AuthenticationError);
});

it.each([302, 401, 403, 429, 500, 503])('fails closed on HTTP %s without returning server secrets', async status => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response('secret-token', { status })));
  await expect(check()).rejects.toThrow('Permission decision could not be verified.');
});

it('bounds the response and sanitizes transport failures', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response('x'.repeat(65537))));
  await expect(check()).rejects.toThrow(/exceeded its limit/);
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('secret-token'); }));
  await expect(check()).rejects.toThrow('Permission decision could not be verified.');
});

it('accepts an exact inactive denial and denies unknown permissions', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ ...body(), organization_active: false, allowed: false })));
  expect((await check()).allows('documents:read')).toBe(false);
});
