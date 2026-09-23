import { Discovery } from './discovery.js';
import { AuthenticationError, ConfigurationError } from './errors.js';

/**
 * A permission your app declares. `key` is a `feature:action` slug (e.g.
 * `invoices:create`); `description` is human-facing copy for the Cbox ID console.
 */
export interface PermissionDefinition {
  key: string;
  description?: string;
  /**
   * Whether an organization's own administrators may hand this permission out in a custom
   * role they build themselves (self-serve). Defaults to `false`: a permission is internal
   * unless you opt it in, so a key added in a hurry never becomes something every customer
   * can grant. Sent as `tenant_assignable: true`.
   */
  tenantAssignable?: boolean;
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
  /**
   * Whether an organization's administrators may assign this role to their members.
   * Defaults to `true`.
   *
   * Set `false` for a STAFF role — your own support or operations people, held
   * environment-wide across every customer (typically the role that grants
   * `support:impersonate`). Cbox ID never lists or accepts a staff role on the
   * organization plane; only an environment administrator can grant it. Sent as
   * `tenant_assignable: false`.
   */
  tenantAssignable?: boolean;
}

/** A permission as it is sent to Cbox ID (snake_case, the manifest's wire format). */
export interface ManifestPermission {
  key: string;
  description?: string;
  /** Present only for a self-serve permission. See {@link PermissionDefinition.tenantAssignable}. */
  tenant_assignable?: true;
}

/** A role as it is sent to Cbox ID (snake_case, the manifest's wire format). */
export interface ManifestRole {
  key: string;
  name: string;
  description?: string;
  permissions: string[];
  /** Present only for a staff role. See {@link RoleDefinition.tenantAssignable}. */
  tenant_assignable?: false;
}

/**
 * The roles + permissions an app declares in code. Either list may be omitted.
 * Pass this to {@link defineAuthz} (to validate up front) or straight to
 * {@link buildManifest} / {@link publishManifest}.
 */
export interface AuthzDeclaration {
  permissions?: PermissionDefinition[];
  roles?: RoleDefinition[];
  /**
   * Where this app's OLD login lives, while you are migrating off it.
   *
   * Declared here for the same reason roles are: it is a fact about the app, it belongs
   * with the deploy, and the alternative is a URL pasted into a console and a secret
   * pasted into an env file that quietly disagree six weeks later.
   *
   * IT DOES NOT TAKE EFFECT ON ITS OWN. Unlike a role — which affects only the app that
   * declared it — this names a URL that every unknown email and the password typed with
   * it will be offered to, on the environment's whole sign-in path. So it arrives as a
   * proposal and an operator has to approve it in the console. Changing the url later
   * drops that approval, on purpose.
   */
  legacyLogin?: LegacyLoginDeclaration;
}

/** Where an app's old login lives. See {@link AuthzDeclaration.legacyLogin}. */
export interface LegacyLoginDeclaration {
  /** Must be https — a password in the clear is readable by everything on the path. */
  url: string;
  /** At least 32 characters. It is the only thing proving a request came from Cbox ID. */
  secret: string;
}

/**
 * The manifest as it is sent to Cbox ID: the declared permissions + roles plus a
 * content-derived `version`, so republishing an unchanged catalog is a no-op.
 */
export interface AuthzManifest {
  version: string;
  permissions: ManifestPermission[];
  roles: ManifestRole[];
  legacy_login?: LegacyLoginDeclaration;
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
export function defineAuthz(
  declaration: AuthzDeclaration,
): AuthzDeclaration & { permissions: PermissionDefinition[]; roles: RoleDefinition[] } {
  const permissions = declaration.permissions ?? [];
  const roles = declaration.roles ?? [];
  assertDeclaration(permissions, roles);

  // The legacy login is validated here too, so a bad one fails in the deploy that
  // introduced it rather than as a 4xx from a manifest push somebody has to go and read.
  if (declaration.legacyLogin) {
    assertLegacyLogin(declaration.legacyLogin);
  }

  // `Required<>` no longer fits: the catalog is always present after this, and the legacy
  // login legitimately is not. Returning the declaration's own optionality keeps a caller
  // from having to invent an empty one.
  return { ...declaration, permissions, roles };
}

/**
 * Build the manifest — the declared catalog plus a stable content hash `version`
 * (first 16 hex chars of the sha256 of the canonicalized catalog). The catalog is
 * sorted by key first, so declaration order never changes the version.
 */
export async function buildManifest(declaration: AuthzDeclaration): Promise<AuthzManifest> {
  const permissions = declaration.permissions ?? [];
  const roles = declaration.roles ?? [];
  assertDeclaration(permissions, roles);

  // The version hashes the CATALOG only, and the legacy login is deliberately outside it:
  // this canonicalization is a cross-SDK contract — id-js, id-python, id-go and the PHP
  // reference all produce the same bytes, and a shared fixture exists to keep them from
  // drifting. The server compares a declared url separately for the same reason.
  const version = (await sha256Hex(canonicalManifestJson(permissions, roles))).slice(0, 16);

  const manifest: AuthzManifest = {
    version,
    permissions: [...permissions].sort((a, b) => byteCompare(a.key, b.key)).map(wirePermission),
    roles: [...roles].sort((a, b) => byteCompare(a.key, b.key)).map(wireRole),
  };

  if (declaration.legacyLogin) {
    assertLegacyLogin(declaration.legacyLogin);
    manifest.legacy_login = declaration.legacyLogin;
  }

  return manifest;
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

/**
 * A `feature:action` (or bare `feature`) key: lowercase, with dot/colon-separated segments.
 * The server's own pattern, restated so a bad key fails where it was written rather than
 * as a 4xx from a manifest push on deploy.
 */
const KEY_PATTERN = /^[a-z][a-z0-9_-]*(?:[.:][a-z0-9_-]+)*$/;

function assertDeclaration(permissions: PermissionDefinition[], roles: RoleDefinition[]): void {
  const permissionKeys = new Set<string>();
  for (const permission of permissions) {
    if (!permission.key) {
      throw new ConfigurationError('Every permission needs a non-empty `key`.');
    }
    assertKey(permission.key, 'Permission');
    if (permissionKeys.has(permission.key)) {
      throw new ConfigurationError(`Permission "${permission.key}" is declared more than once.`);
    }
    assertFlag(permission.tenantAssignable, `Permission "${permission.key}"`);
    permissionKeys.add(permission.key);
  }

  const roleKeys = new Set<string>();
  for (const role of roles) {
    if (!role.key) {
      throw new ConfigurationError('Every role needs a non-empty `key`.');
    }
    assertKey(role.key, 'Role');
    if (!role.name) {
      throw new ConfigurationError(`Role "${role.key}" needs a non-empty \`name\`.`);
    }
    if (roleKeys.has(role.key)) {
      throw new ConfigurationError(`Role "${role.key}" is declared more than once.`);
    }
    assertFlag(role.tenantAssignable, `Role "${role.key}"`);
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

function assertKey(key: string, what: 'Permission' | 'Role'): void {
  if (!KEY_PATTERN.test(key)) {
    throw new ConfigurationError(
      `${what} key "${key}" is not a lowercase \`feature:action\` slug (e.g. \`invoices:create\`).`,
    );
  }
}

/**
 * `tenantAssignable`, when given, must be a real boolean.
 *
 * The type says so, but a catalog loaded from YAML or JSON arrives untyped, and the
 * string `"false"` is truthy: the one value that has to mean "staff only" would read as
 * "every customer may grant this". The server refuses a non-boolean role flag for the
 * same reason; refusing it here puts the failure in the deploy that introduced it.
 */
function assertFlag(value: unknown, owner: string): void {
  if (value !== undefined && typeof value !== 'boolean') {
    throw new ConfigurationError(`${owner} \`tenantAssignable\` must be true or false.`);
  }
}

/**
 * A permission in the manifest's wire format: fixed key order, no `undefined` fields.
 *
 * `tenant_assignable` is written only when it is `true`, the non-default. The server reads
 * the snake_case key and nothing else, so this mapping is the whole difference between a
 * self-serve permission and an internal one — `tenantAssignable` sent as-is would be
 * ignored.
 */
function wirePermission(permission: PermissionDefinition): ManifestPermission {
  return {
    key: permission.key,
    ...(permission.description === undefined ? {} : { description: permission.description }),
    ...(permission.tenantAssignable === true ? { tenant_assignable: true as const } : {}),
  };
}

/**
 * A role in the manifest's wire format: fixed key order, de-duplicated and sorted
 * permission refs, no `undefined` fields.
 *
 * `tenant_assignable: false` is written only for a staff role. THIS IS THE LINE THAT
 * KEEPS A STAFF ROLE STAFF-ONLY: the server defaults an absent key to assignable, so a
 * camelCase `tenantAssignable: false` passed straight through would publish your support
 * role as one every customer's administrator can hand out.
 */
function wireRole(role: RoleDefinition): ManifestRole {
  return {
    key: role.key,
    name: role.name,
    ...(role.description === undefined ? {} : { description: role.description }),
    permissions: uniqueSorted(role.permissions),
    ...(role.tenantAssignable === false ? { tenant_assignable: false as const } : {}),
  };
}

/**
 * Serialize {permissions, roles} to the exact canonical JSON the PHP reference hashes,
 * so the `version` is byte-for-byte identical across every Cbox ID SDK. Matches PHP
 * `json_encode` defaults: object keys in insertion order, permissions and roles sorted
 * by key, each role's permission refs de-duplicated and sorted, an absent-or-empty
 * description emitted as `null`, forward slashes escaped as `\/`, and every non-ASCII
 * code unit as `\uXXXX`.
 *
 * Each `tenant_assignable` flag appears ONLY in its non-default state — `true` on a
 * permission, `false` on a role — exactly as the reference writes it. That keeps every
 * catalog that never mentions the flag hashing to the bytes it always has, while a
 * change to it still changes the version (an unchanged version is a skipped sync).
 */
export function canonicalManifestJson(
  permissions: PermissionDefinition[],
  roles: RoleDefinition[],
): string {
  const canonical = {
    permissions: [...permissions]
      .sort((a, b) => byteCompare(a.key, b.key))
      .map((p) => ({
        key: p.key,
        description: emptyToNull(p.description),
        ...(p.tenantAssignable === true ? { tenant_assignable: true } : {}),
      })),
    roles: [...roles]
      .sort((a, b) => byteCompare(a.key, b.key))
      .map((r) => ({
        key: r.key,
        name: r.name,
        description: emptyToNull(r.description),
        permissions: uniqueSorted(r.permissions),
        ...(r.tenantAssignable === false ? { tenant_assignable: false } : {}),
      })),
  };
  return escapeLikePhp(JSON.stringify(canonical));
}

/**
 * Permission refs as the server stores them: each once, sorted. The server drops a
 * repeated ref before it hashes, so hashing the repeat here would give a `version` that
 * no server ever computes.
 */
function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort(byteCompare);
}

/** PHP treats an absent or empty description as `null` in the hashed catalog. */
function emptyToNull(value: string | undefined): string | null {
  return value === undefined || value === '' ? null : value;
}

/** Byte-wise (code-unit) comparison — matches PHP `strcmp` on the ASCII-only keys. */
function byteCompare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Apply PHP `json_encode`'s default `\/` slash and `\uXXXX` non-ASCII escaping. */
function escapeLikePhp(json: string): string {
  let out = '';
  for (let i = 0; i < json.length; i++) {
    const char = json.charAt(i);
    const code = json.charCodeAt(i);
    if (char === '/') {
      out += '\\/';
    } else if (code > 0x7f) {
      out += '\\u' + code.toString(16).padStart(4, '0');
    } else {
      out += char;
    }
  }
  return out;
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

/**
 * Refuse a legacy login declaration the server would refuse anyway.
 *
 * Checked in the SDK so it fails at build time, in the deploy that introduced it, rather
 * than as a 4xx from a manifest push somebody has to go and read. Both rules are the
 * server's and are restated here rather than inferred: https because a password in the
 * clear is readable by everything on the path, and a real secret because it is the only
 * thing proving a request came from Cbox ID.
 */
function assertLegacyLogin(legacy: LegacyLoginDeclaration): void {
  if (!legacy.url.startsWith('https://')) {
    throw new ConfigurationError('legacyLogin.url must be https — a password must never cross the network in the clear.');
  }

  if (!legacy.secret || legacy.secret.length < 32) {
    throw new ConfigurationError('legacyLogin.secret must be at least 32 characters; it is what proves a request came from Cbox ID.');
  }
}
