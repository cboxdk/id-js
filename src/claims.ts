import type { CboxUser } from './types.js';

/**
 * The membership tier a person holds in the organization a token is bound to — the
 * `org_role` claim. Coarse on purpose: it says who may administer the organization
 * itself (invite, bill, delete). What they may do inside YOUR app is `roles` /
 * `permissions`, which your app declares and Cbox ID assigns.
 */
export type OrganizationRole = 'owner' | 'admin' | 'developer' | 'member' | 'viewer';

const ORGANIZATION_ROLES: ReadonlySet<string> = new Set<OrganizationRole>([
  'owner',
  'admin',
  'developer',
  'member',
  'viewer',
]);

/** The organization a token is bound to: the `org`, `org_name` and `org_role` claims. */
export interface CboxActiveOrganization {
  /** The stable organization id (`org`). */
  id: string;
  /** Its display name (`org_name`), when the instance sent one. */
  name: string | null;
  /**
   * The person's membership tier in it (`org_role`). Null when the claim is absent, or
   * carries a tier this SDK version does not know — an unrecognised tier is never
   * guessed upward into one that grants something.
   */
  role: OrganizationRole | null;
}

/**
 * Who is actually driving a delegated session — the RFC 8693 §4.1 `act` claim. Cbox ID
 * sets it on the tokens of a SUPPORT SESSION: a staff member acting as one of your users,
 * with a stated reason, for at most an hour, with no refresh token.
 *
 * `sub` is the actor's subject id. It is null when an `act` claim is present but not in
 * the shape RFC 8693 describes — the token is still acted, and saying so matters more
 * than knowing by whom (see {@link isSupportSession}).
 */
export interface CboxActor {
  sub: string | null;
  /** The prior actor, when delegation was chained (RFC 8693 §4.1 nested `act`). */
  actor: CboxActor | null;
}

/**
 * Anything the helpers below can read claims from: a {@link CboxUser} from sign-in, or a
 * claim set you verified yourself — an access token's payload on a resource server, say.
 */
export type ClaimSource = CboxUser | Readonly<Record<string, unknown>>;

/**
 * The organization this session is bound to, or null when it is bound to none.
 *
 * ```ts
 * const org = organization(user);
 * if (org?.role === 'owner') showBilling();
 * ```
 */
export function organization(source: ClaimSource): CboxActiveOrganization | null {
  const claims = claimsOf(source);
  const id = claims['org'];

  if (typeof id !== 'string' || id === '') {
    return null;
  }

  const name = claims['org_name'];
  const role = claims['org_role'];

  return {
    id,
    name: typeof name === 'string' && name !== '' ? name : null,
    role: typeof role === 'string' && ORGANIZATION_ROLES.has(role) ? (role as OrganizationRole) : null,
  };
}

/**
 * The actor behind a support session (`act`), or null for an ordinary session in which
 * the person is acting as themselves.
 */
export function actor(source: ClaimSource): CboxActor | null {
  return parseActor(claimsOf(source)['act'], 0);
}

/**
 * Whether somebody other than the signed-in person is driving this session — a staff
 * member in a support session (the token carries `act`).
 *
 * FAIL-CLOSED. Any `act` claim at all counts, including one whose shape this SDK cannot
 * read: the check exists so an app can show a banner and refuse the things a helper
 * should never do on somebody's behalf (change their password, move their money), and a
 * malformed claim is not evidence that nobody else is at the keyboard.
 */
export function isSupportSession(source: ClaimSource): boolean {
  return actor(source) !== null;
}

/** The app roles this session holds — the `roles` claim; empty when there are none. */
export function roles(source: ClaimSource): string[] {
  return stringList(claimsOf(source)['roles']);
}

/**
 * The permissions this session holds — the `permissions` claim, already expanded from
 * `roles` by Cbox ID; empty when there are none.
 */
export function permissions(source: ClaimSource): string[] {
  return stringList(claimsOf(source)['permissions']);
}

/** Whether the session holds `role`. Exact match; no wildcards. */
export function hasRole(source: ClaimSource, role: string): boolean {
  return roles(source).includes(role);
}

/**
 * Whether the session holds `permission` (`feature:action`). Exact match; no wildcards
 * — a claim of `invoices:*` does not grant `invoices:delete`, because nothing on the
 * issuing side ever mints one.
 */
export function hasPermission(source: ClaimSource, permission: string): boolean {
  return permissions(source).includes(permission);
}

/**
 * Nesting is bounded: RFC 8693 chains are a handful deep in practice, and a claim nested
 * thousands deep is either a bug or an attempt to exhaust the stack. Past the bound the
 * chain is cut, not dropped — the session is still acted.
 */
const MAX_ACTOR_DEPTH = 8;

function parseActor(claim: unknown, depth: number): CboxActor | null {
  if (claim === undefined || claim === null) {
    return null;
  }

  if (typeof claim !== 'object' || Array.isArray(claim)) {
    return { sub: null, actor: null };
  }

  const record = claim as Record<string, unknown>;
  const sub = record['sub'];

  return {
    sub: typeof sub === 'string' && sub !== '' ? sub : null,
    actor: depth + 1 < MAX_ACTOR_DEPTH ? parseActor(record['act'], depth + 1) : null,
  };
}

function stringList(claim: unknown): string[] {
  return Array.isArray(claim)
    ? claim.filter((value): value is string => typeof value === 'string' && value !== '')
    : [];
}

function claimsOf(source: ClaimSource): Readonly<Record<string, unknown>> {
  return isUser(source) ? source.claims : source;
}

/**
 * A `CboxUser` is told apart by the credential it carries alongside its claims. A raw
 * claim set never has an `accessToken` key — JWT claims are snake_case — so a verified
 * payload is never mistaken for a user and read from the wrong place.
 */
function isUser(source: ClaimSource): source is CboxUser {
  return (
    typeof source['claims'] === 'object' &&
    source['claims'] !== null &&
    typeof source['accessToken'] === 'string'
  );
}
