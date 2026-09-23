import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildManifest,
  ConfigurationError,
  defineAuthz,
  publishManifest,
  type AuthzDeclaration,
  type PermissionDefinition,
  type RoleDefinition,
} from '../src/index.js';
import { canonicalManifestJson } from '../src/authz.js';
import { discovery, ISSUER } from './helpers.js';

interface FixtureCase {
  name: string;
  permissions: { key: string; description: string | null; tenant_assignable?: boolean }[];
  roles: {
    key: string;
    name: string;
    description: string | null;
    permissions: string[];
    tenant_assignable?: boolean;
  }[];
  canonical_json: string;
  sha256: string;
  version: string;
}

// The shared cross-SDK fixture: manifests + their canonical JSON and hash, generated
// from the PHP reference (Cbox\Id\AccessControl\Manifest\Manifest::checksum). id-js,
// id-python, id-go and laravel-id all assert against this same file so the four stay
// byte-for-byte locked together.
const fixture = JSON.parse(
  readFileSync(fileURLToPath(new URL('./fixtures/manifest-hash.json', import.meta.url)), 'utf8'),
) as { cases: FixtureCase[] };

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

describe('cross-SDK manifest hash fixture', () => {
  it('carries every case the PHP reference asserts, staff roles and self-serve permissions included', () => {
    // A stale copy of the fixture passes every case it has; this is what notices the copy.
    expect(fixture.cases.map((c) => c.name)).toEqual([
      'empty',
      'basic',
      'edge_cases',
      'staff_role',
      'self_serve_permission',
    ]);
  });

  for (const testCase of fixture.cases) {
    it(`matches the PHP reference canonical hash: ${testCase.name}`, async () => {
      // A null description in the fixture means "not declared" — omit the field. The
      // flags are carried exactly as the fixture states them, absent included: absent and
      // the default must hash the same.
      const permissions: PermissionDefinition[] = testCase.permissions.map((p) => ({
        key: p.key,
        ...(p.description === null ? {} : { description: p.description }),
        ...(p.tenant_assignable === undefined ? {} : { tenantAssignable: p.tenant_assignable }),
      }));
      const roles: RoleDefinition[] = testCase.roles.map((r) => ({
        key: r.key,
        name: r.name,
        ...(r.description === null ? {} : { description: r.description }),
        permissions: r.permissions,
        ...(r.tenant_assignable === undefined ? {} : { tenantAssignable: r.tenant_assignable }),
      }));

      // Byte-for-byte identical canonical serialization to PHP's json_encode.
      const canonical = canonicalManifestJson(permissions, roles);
      expect(canonical).toBe(testCase.canonical_json);
      expect(createHash('sha256').update(canonical, 'utf8').digest('hex')).toBe(testCase.sha256);
      // The SDK's own sha256 of those bytes, truncated to 16 hex, matches the fixture.
      const manifest = await buildManifest({ permissions, roles });
      expect(manifest.version).toBe(testCase.version);
      expect(testCase.version).toBe(testCase.sha256.slice(0, 16));
    });
  }
});

describe('staff roles and self-serve permissions', () => {
  const catalog = {
    permissions: [
      { key: 'support:impersonate', description: 'Act as a customer' },
      { key: 'parcels:read', description: 'View parcels', tenantAssignable: true },
    ],
    roles: [
      {
        key: 'support',
        name: 'Support',
        permissions: ['support:impersonate', 'parcels:read'],
        tenantAssignable: false,
      },
      { key: 'viewer', name: 'Viewer', permissions: ['parcels:read'] },
    ],
  } satisfies AuthzDeclaration;

  it('sends a staff role as tenant_assignable: false, the only key the server reads', async () => {
    const manifest = await buildManifest(catalog);
    const support = manifest.roles.find((r) => r.key === 'support') as unknown as Record<string, unknown>;

    expect(support['tenant_assignable']).toBe(false);
    // Sent camelCase, the server would ignore it and default the role to assignable.
    expect(support).not.toHaveProperty('tenantAssignable');
  });

  it('sends a self-serve permission as tenant_assignable: true', async () => {
    const manifest = await buildManifest(catalog);
    const read = manifest.permissions.find((p) => p.key === 'parcels:read') as unknown as Record<string, unknown>;

    expect(read['tenant_assignable']).toBe(true);
    expect(read).not.toHaveProperty('tenantAssignable');
  });

  it('leaves both flags off the wire in their default state', async () => {
    const manifest = await buildManifest({
      permissions: [{ key: 'parcels:read', tenantAssignable: false }],
      roles: [{ key: 'viewer', name: 'Viewer', permissions: ['parcels:read'], tenantAssignable: true }],
    });

    expect(manifest.permissions[0]).toEqual({ key: 'parcels:read' });
    expect(manifest.roles[0]).toEqual({ key: 'viewer', name: 'Viewer', permissions: ['parcels:read'] });
  });

  it('changes the version when a role becomes staff-only, so the server does not skip the sync', async () => {
    const before = await buildManifest({
      permissions: catalog.permissions,
      roles: catalog.roles.map(({ tenantAssignable: _, ...role }) => role),
    });
    const after = await buildManifest(catalog);

    expect(after.version).not.toBe(before.version);
  });

  it('changes the version when a permission becomes self-serve', async () => {
    const before = await buildManifest({
      permissions: catalog.permissions.map(({ tenantAssignable: _, ...permission }) => permission),
      roles: catalog.roles,
    });
    const after = await buildManifest(catalog);

    expect(after.version).not.toBe(before.version);
  });

  it('hashes a repeated permission ref as the server does, once', async () => {
    const once = await buildManifest({
      permissions: [{ key: 'parcels:read' }],
      roles: [{ key: 'viewer', name: 'Viewer', permissions: ['parcels:read'] }],
    });
    const twice = await buildManifest({
      permissions: [{ key: 'parcels:read' }],
      roles: [{ key: 'viewer', name: 'Viewer', permissions: ['parcels:read', 'parcels:read'] }],
    });

    expect(twice.version).toBe(once.version);
    expect(twice.roles[0]!.permissions).toEqual(['parcels:read']);
  });

  it('refuses a role flag that is not a boolean, which a YAML-loaded "false" would be', () => {
    const untyped = { key: 'support', name: 'Support', permissions: [], tenantAssignable: 'false' };

    expect(() => defineAuthz({ roles: [untyped as unknown as RoleDefinition] })).toThrowError(
      'Role "support" `tenantAssignable` must be true or false.',
    );
  });

  it('refuses a permission flag that is not a boolean', () => {
    const untyped = { key: 'parcels:read', tenantAssignable: 1 };

    expect(() => defineAuthz({ permissions: [untyped as unknown as PermissionDefinition] })).toThrowError(
      'Permission "parcels:read" `tenantAssignable` must be true or false.',
    );
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

  it('rejects a key the server would refuse, where it was written', () => {
    expect(() => defineAuthz({ permissions: [{ key: 'Invoices:Read' }] })).toThrowError(
      'Permission key "Invoices:Read" is not a lowercase `feature:action` slug (e.g. `invoices:create`).',
    );
    expect(() => defineAuthz({ roles: [{ key: 'billing admin', name: 'Billing', permissions: [] }] })).toThrowError(
      'Role key "billing admin" is not a lowercase `feature:action` slug (e.g. `invoices:create`).',
    );
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

  it('pushes a staff role over the wire as tenant_assignable: false', async () => {
    let pushed: unknown;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: unknown, init?: RequestInit): Promise<Response> => {
        const url = String(input);
        if (url.endsWith('/.well-known/openid-configuration')) {
          return json(discovery);
        }
        if (url === discovery.token_endpoint) {
          return json({ access_token: 'manifest-token', token_type: 'Bearer' });
        }
        pushed = JSON.parse(String(init?.body));
        return json({ unchanged: false });
      }),
    );

    await publishManifest(config, {
      permissions: [{ key: 'support:impersonate' }],
      roles: [{ key: 'support', name: 'Support', permissions: ['support:impersonate'], tenantAssignable: false }],
    });

    expect((pushed as { roles: unknown[] }).roles).toEqual([
      { key: 'support', name: 'Support', permissions: ['support:impersonate'], tenant_assignable: false },
    ]);
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
