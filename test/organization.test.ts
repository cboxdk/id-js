import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  actor,
  AuthenticationError,
  CboxIdClient,
  ConfigurationError,
  hasPermission,
  hasRole,
  isSupportSession,
  organization,
  permissions,
  roles,
  sessionId,
} from '../src/index.js';
import { NextRequest } from 'next/server';
import { createCboxId } from '../src/nextjs.js';
import { fakeInstance, ISSUER, NONCE } from './helpers.js';

const baseConfig = {
  issuer: ISSUER,
  clientId: 'client-abc',
  clientSecret: 'secret-xyz',
  redirectUri: 'https://app.test/auth/callback',
};

const stored = { state: 'state-1', codeVerifier: 'verifier-1', nonce: NONCE };

afterEach(() => {
  vi.unstubAllGlobals();
});

async function clientFor(overrides: Parameters<typeof fakeInstance>[0] = {}) {
  const inst = await fakeInstance(overrides);
  vi.stubGlobal('fetch', inst.fetchMock);
  return { inst, client: new CboxIdClient(baseConfig) };
}

describe('organization parameters on the authorize URL', () => {
  it('sends organization and organization_hint under the names the server reads', async () => {
    const { client } = await clientFor();

    const url = new URL(
      (await client.createAuthorizationRequest({ organization: 'org-2', organizationHint: 'org-3' })).url,
    );

    expect(url.searchParams.get('organization')).toBe('org-2');
    expect(url.searchParams.get('organization_hint')).toBe('org-3');
  });

  it('sends neither when not asked, so an ordinary sign-in is not bound to anything', async () => {
    const { client } = await clientFor();

    const url = new URL((await client.createAuthorizationRequest()).url);

    expect(url.searchParams.has('organization')).toBe(false);
    expect(url.searchParams.has('organization_hint')).toBe(false);
    expect(url.searchParams.has('prompt')).toBe(false);
  });

  it.each(['select_organization', 'create_organization'] as const)('sends prompt=%s', async (prompt) => {
    const { client } = await clientFor();

    const url = new URL((await client.createAuthorizationRequest({ prompt })).url);

    expect(url.searchParams.get('prompt')).toBe(prompt);
  });

  it('joins several prompts with a space and drops duplicates', async () => {
    const { client } = await clientFor();

    const url = new URL(
      (await client.createAuthorizationRequest({
        prompt: ['login', 'select_organization', 'login'],
        organizationHint: 'org-3',
      })).url,
    );

    expect(url.searchParams.get('prompt')).toBe('login select_organization');
    expect(url.searchParams.get('organization_hint')).toBe('org-3');
  });

  it("refuses prompt 'none' combined with another value (OIDC Core 3.1.2.1)", async () => {
    const { client } = await clientFor();

    await expect(client.createAuthorizationRequest({ prompt: ['none', 'login'] })).rejects.toThrowError(
      new ConfigurationError("`prompt: 'none'` cannot be combined with another prompt value."),
    );
  });

  it('refuses organization with the picker, and points at organizationHint', async () => {
    const { client } = await clientFor();

    const attempt = client.createAuthorizationRequest({ organization: 'org-2', prompt: 'select_organization' });

    await expect(attempt).rejects.toBeInstanceOf(ConfigurationError);
    await expect(attempt).rejects.toThrowError(/Use `organizationHint` to preselect/);
  });

  it('refuses organization with create_organization', async () => {
    const { client } = await clientFor();

    await expect(
      client.createAuthorizationRequest({ organization: 'org-2', prompt: ['login', 'create_organization'] }),
    ).rejects.toThrowError(/binds the sign-in to an existing organization/);
  });

  it('refuses an empty organization rather than sending a parameter that names nothing', async () => {
    const { client } = await clientFor();

    await expect(client.createAuthorizationRequest({ organization: '' })).rejects.toThrowError(
      /`organization` is empty/,
    );
    await expect(client.createAuthorizationRequest({ organizationHint: '' })).rejects.toThrowError(
      /`organizationHint` is empty/,
    );
  });
});

describe('switchOrganization', () => {
  it('is a full PKCE authorization bound to the chosen organization', async () => {
    const { client } = await clientFor();

    const request = await client.switchOrganization('org-2', { scopes: ['openid', 'organizations'] });
    const url = new URL(request.url);

    expect(url.origin + url.pathname).toBe(`${ISSUER}/oauth/authorize`);
    expect(url.searchParams.get('organization')).toBe('org-2');
    expect(url.searchParams.get('scope')).toBe('openid organizations');
    expect(url.searchParams.get('state')).toBe(request.state);
    expect(url.searchParams.get('nonce')).toBe(request.nonce);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(request.codeVerifier).not.toBe('');
  });

  it('echoes the organization so the callback can hold the tokens to it', async () => {
    const { client } = await clientFor();

    expect((await client.switchOrganization('org-2')).organization).toBe('org-2');
    expect((await client.createAuthorizationRequest()).organization).toBeUndefined();
  });

  it('accepts tokens bound to the organization that was asked for', async () => {
    const { client } = await clientFor();

    // The fake instance binds every token to org-1.
    const user = await client.authenticate({
      params: { code: 'c', state: 'state-1' },
      stored: { ...stored, organization: 'org-1' },
    });

    expect(user.organizationId).toBe('org-1');
  });

  it('refuses tokens bound to a different organization than the switch asked for', async () => {
    // An instance that predates the parameter ignores it and answers for the session's
    // current organization — which the app would otherwise present as the new one.
    const { client } = await clientFor();

    await expect(
      client.authenticate({
        params: { code: 'c', state: 'state-1' },
        stored: { ...stored, organization: 'org-2' },
      }),
    ).rejects.toThrowError(
      new AuthenticationError(
        'The sign-in was bound to organization org-2, but the tokens are for org-1. The instance may not support organization selection.',
      ),
    );
  });

  it('refuses tokens bound to no organization at all when one was asked for', async () => {
    const { inst, client } = await clientFor({ userinfo: { sub: 'user-1' } });
    inst.setTokenResponse({
      access_token: 'access-unbound',
      id_token: await inst.signIdToken({ iss: ISSUER, aud: 'client-abc', sub: 'user-1', nonce: NONCE }),
    });

    await expect(
      client.authenticate({
        params: { code: 'c', state: 'state-1' },
        stored: { ...stored, organization: 'org-2' },
      }),
    ).rejects.toThrowError(/but the tokens are for no organization/);
  });

  it('cannot be told to open the picker instead', async () => {
    const { client } = await clientFor();

    await expect(client.switchOrganization('org-2', { prompt: 'select_organization' })).rejects.toThrowError(
      /has nothing to choose/,
    );
  });

  it('surfaces a refused switch as access_denied on the error, not only in the message', async () => {
    const { client } = await clientFor();

    const attempt = client.authenticate({
      params: { state: 'state-1', error: 'access_denied', error_description: 'Not a member of that organization.' },
      stored,
    });

    await expect(attempt).rejects.toBeInstanceOf(AuthenticationError);
    await expect(attempt).rejects.toMatchObject({
      error: 'access_denied',
      errorDescription: 'Not a member of that organization.',
    });
  });
});

describe('typed tenancy claims on the signed-in user', () => {
  it('maps org, org_name, org_role, roles and permissions', async () => {
    const { client } = await clientFor({
      userinfo: {
        sub: 'user-1',
        org: 'org-1',
        org_name: 'Acme',
        org_role: 'admin',
        roles: ['billing-admin'],
        permissions: ['invoices:create', 'invoices:read'],
      },
    });

    const user = await client.authenticate({ params: { code: 'c', state: 'state-1' }, stored });

    expect(user.organization).toEqual({ id: 'org-1', name: 'Acme', role: 'admin' });
    expect(user.organizationId).toBe('org-1');
    expect(user.roles).toEqual(['billing-admin']);
    expect(user.permissions).toEqual(['invoices:create', 'invoices:read']);
    expect(user.actor).toBeNull();
    expect(isSupportSession(user)).toBe(false);
    expect(user.sessionId).toBeNull();
  });

  it('carries the id_token sid, which a back-channel logout names the session by', async () => {
    const { inst, client } = await clientFor();
    inst.setTokenResponse({
      access_token: 'access-1',
      id_token: await inst.signIdToken({ iss: ISSUER, aud: 'client-abc', sub: 'user-1', nonce: NONCE, sid: 'sess-42' }),
      expires_in: 3600,
    });

    const user = await client.authenticate({ params: { code: 'c', state: 'state-1' }, stored });

    expect(user.sessionId).toBe('sess-42');
    expect(sessionId(user)).toBe('sess-42');
  });

  it('marks a support session from the signed act claim', async () => {
    const { inst, client } = await clientFor();
    inst.setTokenResponse({
      access_token: 'access-acted',
      id_token: await inst.signIdToken({
        iss: ISSUER,
        aud: 'client-abc',
        sub: 'user-1',
        nonce: NONCE,
        org: 'org-1',
        act: { sub: 'staff-9' },
      }),
      expires_in: 3600,
    });

    const user = await client.authenticate({ params: { code: 'c', state: 'state-1' }, stored });

    expect(user.actor).toEqual({ sub: 'staff-9', actor: null });
    expect(isSupportSession(user)).toBe(true);
    // Acted grants get no refresh token; the SDK reports what came back, not a default.
    expect(user.refreshToken).toBeNull();
  });

  it('does not let UserInfo erase the act the id_token signature covers', async () => {
    const { inst, client } = await clientFor({ userinfo: { sub: 'user-1', act: null } });
    inst.setTokenResponse({
      access_token: 'access-acted',
      id_token: await inst.signIdToken({
        iss: ISSUER,
        aud: 'client-abc',
        sub: 'user-1',
        nonce: NONCE,
        act: { sub: 'staff-9' },
      }),
    });

    const user = await client.authenticate({ params: { code: 'c', state: 'state-1' }, stored });

    expect(isSupportSession(user)).toBe(true);
  });

  it('gives empty lists, not undefined, when the session holds no roles', async () => {
    const { client } = await clientFor();

    const user = await client.authenticate({ params: { code: 'c', state: 'state-1' }, stored });

    expect(user.roles).toEqual([]);
    expect(user.permissions).toEqual([]);
    // The default fake instance sends `org` but no name or tier.
    expect(user.organization).toEqual({ id: 'org-1', name: null, role: null });
  });
});

describe('claim helpers on a raw claim set', () => {
  it('reads an access-token payload a resource server verified itself', () => {
    const payload = {
      sub: 'user-1',
      org: 'org-1',
      org_role: 'owner',
      roles: ['billing-admin', 7, ''],
      permissions: ['invoices:read'],
    };

    expect(organization(payload)).toEqual({ id: 'org-1', name: null, role: 'owner' });
    expect(roles(payload)).toEqual(['billing-admin']);
    expect(hasRole(payload, 'billing-admin')).toBe(true);
    expect(hasPermission(payload, 'invoices:read')).toBe(true);
    expect(isSupportSession(payload)).toBe(false);
    expect(sessionId(payload)).toBeNull();
    expect(sessionId({ sid: '' })).toBeNull();
    expect(sessionId({ sid: 42 })).toBeNull();
  });

  it('matches permissions exactly, with no wildcard expansion', () => {
    const payload = { permissions: ['invoices:*'] };

    expect(hasPermission(payload, 'invoices:delete')).toBe(false);
    expect(permissions(payload)).toEqual(['invoices:*']);
  });

  it('never guesses an unknown org_role into a known tier', () => {
    expect(organization({ org: 'org-1', org_role: 'superowner' })?.role).toBeNull();
    expect(organization({ org: '', org_role: 'owner' })).toBeNull();
    expect(organization({})).toBeNull();
  });

  it('counts a malformed act as a support session (fail-closed)', () => {
    expect(isSupportSession({ act: 'staff-9' })).toBe(true);
    expect(actor({ act: 'staff-9' })).toEqual({ sub: null, actor: null });
    expect(isSupportSession({ act: {} })).toBe(true);
    expect(isSupportSession({ act: [] })).toBe(true);
    expect(isSupportSession({ act: null })).toBe(false);
  });

  it('follows a chained act (RFC 8693 4.1), bounded in depth', () => {
    expect(actor({ act: { sub: 'staff-9', act: { sub: 'svc-1' } } })).toEqual({
      sub: 'staff-9',
      actor: { sub: 'svc-1', actor: null },
    });

    let deep: Record<string, unknown> = { sub: 'last' };
    for (let i = 0; i < 1000; i++) {
      deep = { sub: `a${i}`, act: deep };
    }

    let depth = 0;
    for (let a = actor({ act: deep }); a !== null; a = a.actor) {
      depth += 1;
    }
    expect(depth).toBe(8);
  });

  it('reads a claim set that happens to have a `claims` key as claims, not as a user', () => {
    const payload = { claims: { org: 'org-other' }, org: 'org-1' };

    expect(organization(payload)?.id).toBe('org-1');
  });
});

describe('Next.js adapter', () => {
  it('switchOrganization redirects with organization= and stores the PKCE state', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const cboxId = createCboxId(baseConfig);

    const response = await cboxId.switchOrganization('org-2');
    const location = new URL(response.headers.get('location') ?? '');

    expect(location.searchParams.get('organization')).toBe('org-2');
    expect(response.cookies.get('cbox_id_state')?.value).toBe(location.searchParams.get('state'));
    expect(response.cookies.get('cbox_id_nonce')?.value).toBe(location.searchParams.get('nonce'));
    expect(response.cookies.get('cbox_id_verifier')?.value).toBeTruthy();
  });

  it('stores the switched-to organization and verifies it on the callback', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const cboxId = createCboxId(baseConfig);

    const response = await cboxId.switchOrganization('org-2');
    expect(response.cookies.get('cbox_id_organization')?.value).toBe('org-2');

    const state = response.cookies.get('cbox_id_state')?.value ?? '';
    const callback = new NextRequest(`https://app.test/auth/callback?code=c&state=${state}`, {
      headers: {
        cookie: [
          `cbox_id_state=${state}`,
          `cbox_id_verifier=${response.cookies.get('cbox_id_verifier')?.value ?? ''}`,
          `cbox_id_nonce=${NONCE}`,
          'cbox_id_organization=org-2',
        ].join('; '),
      },
    });

    // The fake instance answers for org-1, so the binding is not honoured.
    await expect(cboxId.callback(callback)).rejects.toThrowError(/bound to organization org-2/);
  });

  it('a plain sign-in clears a binding left by an abandoned switch', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const cboxId = createCboxId(baseConfig);

    const response = await cboxId.signIn();

    expect(response.headers.get('set-cookie')).toMatch(/cbox_id_organization=;[^,]*(Expires=Thu, 01 Jan 1970|Max-Age=0)/i);
  });

  it('signIn passes the organization prompt and hint through', async () => {
    const inst = await fakeInstance();
    vi.stubGlobal('fetch', inst.fetchMock);
    const cboxId = createCboxId(baseConfig);

    const response = await cboxId.signIn({ prompt: 'select_organization', organizationHint: 'org-3' });
    const location = new URL(response.headers.get('location') ?? '');

    expect(location.searchParams.get('prompt')).toBe('select_organization');
    expect(location.searchParams.get('organization_hint')).toBe('org-3');
  });
});
