import { Discovery } from './discovery.js';
import { AuthenticationError, ConfigurationError } from './errors.js';

/**
 * A permission your app declares. `key` is a `feature:action` slug (e.g.
 * `invoices:create`); `description` is human-facing copy for the Cbox ID console.
 */
export interface PermissionDefinition {
  key: string;
  description?: string;
}

/**
 * A role your app declares. `permissions` lists the permission keys the role
 * grants — each must reference a declared {@link PermissionDefinition}.
 */
export interface RoleDefinition {
  key: string;
  name: string;
  description?: string;
  permissions: string[];
}

/**
 * The roles + permissions an app declares in code. Either list may be omitted.
 * Pass this to {@link defineAuthz} (to validate up front) or straight to
 * {@link buildManifest} / {@link publishManifest}.
 */
export interface AuthzDeclaration {
  permissions?: PermissionDefinition[];
  roles?: RoleDefinition[];
}

/**
 * The manifest as it is sent to Cbox ID: the declared permissions + roles plus a
 * content-derived `version`, so republishing an unchanged catalog is a no-op.
 */
export interface AuthzManifest {
  version: string;
  permissions: PermissionDefinition[];
  roles: RoleDefinition[];
}

/** What {@link publishManifest} needs to authenticate the push. */
export interface ManifestPublisherConfig {
  /** Base URL (issuer) of the Cbox ID instance — the `token_endpoint` is discovered from it. */
  issuer: string;
  /** Your OAuth client id. The client must hold the `apps.manifest` scope. */
  clientId: string;
  /** Your OAuth client secret. The push uses the client-credentials grant. */
  clientSecret: string;
  /** Timeout (ms) for back-channel HTTP calls. Defaults to `10000`. */
  timeoutMs?: number;
}

/**
 * The server's sync summary. The named fields are the ones the SDK/CLI reads;
 * the index signature keeps any extra fields the server returns.
 */
export interface ManifestSyncSummary {
  unchanged?: boolean;
  roles_declared?: number;
  permissions_declared?: number;
  version?: string;
  [key: string]: unknown;
}

/**
 * Validate a roles/permissions declaration and return it normalized (both lists
 * always present). Call this where you declare your catalog so mistakes — a role
 * that grants an undeclared permission, a duplicate key — surface immediately
 * rather than on deploy.
 *
 * @throws ConfigurationError on a missing key/name, a duplicate, or a role that
 *   references a permission that was never declared.
 */
export function defineAuthz(declaration: AuthzDeclaration): Required<AuthzDeclaration> {
  const permissions = declaration.permissions ?? [];
  const roles = declaration.roles ?? [];
  assertDeclaration(permissions, roles);
  return { permissions, roles };
}

/**
 * Build the manifest — the declared catalog plus a stable content hash `version`
 * (first 16 hex chars of the sha256 of the canonicalized catalog). The catalog is
 * sorted by key first, so declaration order never changes the version.
 */
export async function buildManifest(declaration: AuthzDeclaration): Promise<AuthzManifest> {
  const permissions = (declaration.permissions ?? []).map(canonicalPermission);
  const roles = (declaration.roles ?? []).map(canonicalRole);
  assertDeclaration(permissions, roles);

  permissions.sort((a, b) => a.key.localeCompare(b.key));
  roles.sort((a, b) => a.key.localeCompare(b.key));

  const version = (await sha256Hex(JSON.stringify({ permissions, roles }))).slice(0, 16);
  return { version, permissions, roles };
}

/**
 * Publish this app's authorization manifest (its declared roles + permissions) to
 * Cbox ID. The app owns what a role means; Cbox ID owns identity and who holds it.
 *
 * It mints a client-credentials token with the `apps.manifest` scope (token
 * endpoint discovered from the issuer's OIDC configuration), then POSTs the
 * manifest to `{issuer}/api/v1/apps/manifest`. Run it on deploy or from a script;
 * an unchanged catalog is a server-side no-op.
 *
 * @returns the server's sync summary (`unchanged`, `roles_declared`, …).
 * @throws ConfigurationError when config or the declaration is invalid.
 * @throws AuthenticationError when the token cannot be minted or the push fails.
 */
export async function publishManifest(
  config: ManifestPublisherConfig,
  declaration: AuthzDeclaration,
): Promise<ManifestSyncSummary> {
  if (!config.issuer || !config.clientId || !config.clientSecret) {
    throw new ConfigurationError('Publishing a manifest needs issuer, clientId and clientSecret.');
  }

  const timeoutMs = config.timeoutMs ?? 10_000;
  const manifest = await buildManifest(declaration);
  const discovery = new Discovery(config.issuer, timeoutMs, 3_600_000);

  const token = await mintToken(config, discovery, timeoutMs);

  const response = await fetchWithTimeout(
    `${config.issuer.replace(/\/$/, '')}/api/v1/apps/manifest`,
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/json',
        'content-type': 'application/json',
      },
      body: JSON.stringify(manifest),
    },
    timeoutMs,
  );

  if (!response.ok) {
    throw new AuthenticationError(`Manifest push failed: HTTP ${response.status} ${await response.text()}`);
  }

  const json = (await response.json()) as unknown;
  return json !== null && typeof json === 'object' ? (json as ManifestSyncSummary) : {};
}

async function mintToken(
  config: ManifestPublisherConfig,
  discovery: Discovery,
  timeoutMs: number,
): Promise<string> {
  const response = await fetchWithTimeout(
    await discovery.endpoint('token_endpoint'),
    {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: config.clientId,
        client_secret: config.clientSecret,
        scope: 'apps.manifest',
      }),
    },
    timeoutMs,
  );

  const json = (await response.json().catch(() => ({}))) as { access_token?: unknown };
  if (typeof json.access_token !== 'string' || json.access_token === '') {
    throw new AuthenticationError(
      'Could not obtain an apps.manifest access token — check the client credentials and that the client holds the apps.manifest scope.',
    );
  }
  return json.access_token;
}

function assertDeclaration(permissions: PermissionDefinition[], roles: RoleDefinition[]): void {
  const permissionKeys = new Set<string>();
  for (const permission of permissions) {
    if (!permission.key) {
      throw new ConfigurationError('Every permission needs a non-empty `key`.');
    }
    if (permissionKeys.has(permission.key)) {
      throw new ConfigurationError(`Permission "${permission.key}" is declared more than once.`);
    }
    permissionKeys.add(permission.key);
  }

  const roleKeys = new Set<string>();
  for (const role of roles) {
    if (!role.key) {
      throw new ConfigurationError('Every role needs a non-empty `key`.');
    }
    if (!role.name) {
      throw new ConfigurationError(`Role "${role.key}" needs a non-empty \`name\`.`);
    }
    if (roleKeys.has(role.key)) {
      throw new ConfigurationError(`Role "${role.key}" is declared more than once.`);
    }
    roleKeys.add(role.key);
    for (const reference of role.permissions) {
      if (!permissionKeys.has(reference)) {
        throw new ConfigurationError(
          `Role "${role.key}" references permission "${reference}", which is not declared.`,
        );
      }
    }
  }
}

/** A permission with keys in a fixed order and no `undefined` fields (stable to hash). */
function canonicalPermission(permission: PermissionDefinition): PermissionDefinition {
  return permission.description === undefined
    ? { key: permission.key }
    : { key: permission.key, description: permission.description };
}

/** A role with keys in a fixed order, sorted permission refs, and no `undefined` fields. */
function canonicalRole(role: RoleDefinition): RoleDefinition {
  const permissions = [...role.permissions].sort((a, b) => a.localeCompare(b));
  return role.description === undefined
    ? { key: role.key, name: role.name, permissions }
    : { key: role.key, name: role.name, description: role.description, permissions };
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
