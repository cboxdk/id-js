import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildManifest,
  ConfigurationError,
  defineAuthz,
  publishManifest,
} from '../src/index.js';
import { discovery, ISSUER } from './helpers.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

const config = {
  issuer: ISSUER,
  clientId: 'client-abc',
  clientSecret: 'secret-xyz',
};

const declaration = {
  permissions: [
    { key: 'invoices:create', description: 'Create invoices' },
    { key: 'invoices:read', description: 'View invoices' },
  ],
  roles: [
    {
      key: 'billing-admin',
      name: 'Billing Admin',
      description: 'Full billing access',
      permissions: ['invoices:create', 'invoices:read'],
    },
  ],
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('buildManifest', () => {
  it('stamps a stable 16-hex version that ignores declaration order', async () => {
    const a = await buildManifest(declaration);
    const b = await buildManifest({
      permissions: [...declaration.permissions].reverse(),
      roles: declaration.roles,
    });

    expect(a.version).toMatch(/^[0-9a-f]{16}$/);
    expect(a.version).toBe(b.version);
    // Sorted into a canonical order regardless of how it was declared.
    expect(a.permissions.map((p) => p.key)).toEqual(['invoices:create', 'invoices:read']);
  });

  it('changes the version when the catalog changes', async () => {
    const a = await buildManifest(declaration);
    const b = await buildManifest({
      permissions: [...declaration.permissions, { key: 'invoices:void' }],
      roles: declaration.roles,
    });
    expect(a.version).not.toBe(b.version);
  });
});

describe('defineAuthz', () => {
  it('rejects a role that grants an undeclared permission', () => {
    expect(() =>
      defineAuthz({
        permissions: [{ key: 'invoices:read' }],
        roles: [{ key: 'admin', name: 'Admin', permissions: ['invoices:delete'] }],
      }),
    ).toThrowError(ConfigurationError);
  });

  it('rejects duplicate permission keys', () => {
    expect(() =>
      defineAuthz({ permissions: [{ key: 'a:b' }, { key: 'a:b' }] }),
    ).toThrowError(ConfigurationError);
  });
});

describe('publishManifest', () => {
  it('mints an apps.manifest token and pushes the manifest with the bearer', async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const mock = vi.fn(async (input: unknown, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      calls.push({ url, init: init ?? {} });

      if (url.endsWith('/.well-known/openid-configuration')) {
        return json(discovery);
      }
      if (url === discovery.token_endpoint) {
        return json({ access_token: 'manifest-token', token_type: 'Bearer' });
      }
      if (url === `${ISSUER}/api/v1/apps/manifest`) {
        return json({ unchanged: false, roles_declared: 1, permissions_declared: 2 });
      }
      return new Response('not found', { status: 404 });
    });
    vi.stubGlobal('fetch', mock);

    const summary = await publishManifest(config, declaration);
    expect(summary).toEqual({ unchanged: false, roles_declared: 1, permissions_declared: 2 });

    // The token request used the client-credentials grant scoped to apps.manifest.
    const tokenCall = calls.find((c) => c.url === discovery.token_endpoint);
    expect(tokenCall).toBeDefined();
    const tokenBody = new URLSearchParams(String(tokenCall!.init.body));
    expect(tokenBody.get('grant_type')).toBe('client_credentials');
    expect(tokenBody.get('client_id')).toBe('client-abc');
    expect(tokenBody.get('client_secret')).toBe('secret-xyz');
    expect(tokenBody.get('scope')).toBe('apps.manifest');

    // The manifest POST carried the bearer + a version + the declared catalog.
    const pushCall = calls.find((c) => c.url === `${ISSUER}/api/v1/apps/manifest`);
    expect(pushCall).toBeDefined();
    expect(pushCall!.init.method).toBe('POST');
    const headers = pushCall!.init.headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer manifest-token');
    expect(headers.accept).toBe('application/json');
    const sent = JSON.parse(String(pushCall!.init.body)) as {
      version: string;
      permissions: { key: string }[];
      roles: { key: string }[];
    };
    expect(sent.version).toMatch(/^[0-9a-f]{16}$/);
    expect(sent.permissions.map((p) => p.key)).toContain('invoices:create');
    expect(sent.roles.map((r) => r.key)).toEqual(['billing-admin']);
  });

  it('throws when the server rejects the push', async () => {
    const mock = vi.fn(async (input: unknown): Promise<Response> => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return json(discovery);
      }
      if (url === discovery.token_endpoint) {
        return json({ access_token: 'manifest-token' });
      }
      return json({ error: 'invalid_manifest' }, 422);
    });
    vi.stubGlobal('fetch', mock);

    await expect(publishManifest(config, declaration)).rejects.toThrowError(/422/);
  });

  it('throws when no apps.manifest token can be minted', async () => {
    const mock = vi.fn(async (input: unknown): Promise<Response> => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return json(discovery);
      }
      return json({ error: 'invalid_scope' }, 400);
    });
    vi.stubGlobal('fetch', mock);

    await expect(publishManifest(config, declaration)).rejects.toThrowError(/apps\.manifest/);
  });
});
