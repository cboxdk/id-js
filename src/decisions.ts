import { AuthenticationError, ConfigurationError } from './errors.js';
import { assertSecureIssuer } from './issuer.js';
import type { OrganizationRole } from './claims.js';

export interface PermissionDecisionConfig {
  issuer: string;
  clientId: string;
  timeoutMs?: number;
}

/** A current server decision; shared membership tiers are not app grants. */
export class PermissionDecision {
  constructor(
    readonly subject: string,
    readonly organization: string | null,
    readonly clientId: string,
    readonly organizationRole: OrganizationRole | null,
    readonly organizationActive: boolean,
    readonly permissions: Readonly<Record<string, boolean>>,
  ) {}

  allows(permission: string): boolean {
    return this.organizationActive && this.permissions[permission] === true;
  }

  allowed(): boolean {
    const values = Object.values(this.permissions);
    return this.organizationActive && values.length > 0 && values.every(value => value === true);
  }
}

/** No positive cache: check each request and again when queued work starts. */
export async function checkPermissions(
  config: PermissionDecisionConfig,
  accessToken: string,
  subject: string,
  organization: string | null,
  permissions: readonly string[],
): Promise<PermissionDecision> {
  assertSecureIssuer(config.issuer);
  const issuer = new URL(config.issuer);
  if (issuer.username || issuer.password || issuer.search || issuer.hash || !config.clientId
    || !subject || organization === '' || !accessToken || accessToken.length > 32768
    || /[\x00-\x20\x7f]/.test(accessToken) || !permissions.length || permissions.length > 50
    || permissions.some(permission => !permission.trim() || new TextEncoder().encode(permission).length > 255)) {
    throw new ConfigurationError('Permission decision request is not configured or valid.');
  }
  const requested = [...new Set(permissions)];
  try {
    const response = await fetch(`${config.issuer.replace(/\/$/, '')}/oauth/decisions`, {
      method: 'POST', redirect: 'error', cache: 'no-store',
      signal: AbortSignal.timeout(Math.max(1, config.timeoutMs ?? 10_000)),
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({ subject, org: organization, permission: requested }),
    });
    if (response.status !== 200) {
      await response.body?.cancel();
      throw new AuthenticationError('Permission decision could not be verified.', undefined, undefined, response.status);
    }
    const reader = response.body?.getReader();
    if (!reader) throw new AuthenticationError('Permission decision response is invalid.');
    let size = 0;
    let raw = '';
    const decoder = new TextDecoder();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 65536) throw new AuthenticationError('Permission decision response exceeded its limit.');
        raw += decoder.decode(value, { stream: true });
      }
      raw += decoder.decode();
    } finally {
      await reader.cancel();
      reader.releaseLock();
    }
    const data: unknown = JSON.parse(raw);
    if (!record(data) || !record(data.subject) || data.mode !== 'rbac'
      || data.subject.type !== 'user' || data.subject.id !== subject
      || data.organization !== organization || data.client_id !== config.clientId
      || typeof data.organization_active !== 'boolean' || typeof data.allowed !== 'boolean'
      || !(data.org_role === null || (typeof data.org_role === 'string'
        && ['owner', 'admin', 'developer', 'member', 'viewer'].includes(data.org_role)))
      || !Array.isArray(data.results) || data.results.length !== requested.length) {
      throw new AuthenticationError('Permission decision response binding is invalid.');
    }
    const checks: Record<string, boolean> = Object.create(null) as Record<string, boolean>;
    for (const result of data.results as unknown[]) {
      if (!record(result) || typeof result.permission !== 'string' || typeof result.allowed !== 'boolean'
        || !requested.includes(result.permission) || Object.hasOwn(checks, result.permission)) {
        throw new AuthenticationError('Permission decision result is invalid.');
      }
      checks[result.permission] = result.allowed;
    }
    const decision = new PermissionDecision(subject, organization, config.clientId,
      data.org_role as OrganizationRole | null, data.organization_active, Object.freeze(checks));
    if (data.allowed !== decision.allowed()) throw new AuthenticationError('Permission decision result is inconsistent.');
    return decision;
  } catch (error) {
    if (error instanceof AuthenticationError) throw error;
    throw new AuthenticationError('Permission decision could not be verified.');
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
