import { NextResponse, type NextRequest } from 'next/server';
import { CboxIdClient } from './client.js';
import { ConfigurationError } from './errors.js';
import type { AuthorizationRequest, AuthorizationRequestOptions, CboxIdConfig, CboxUser } from './types.js';

/**
 * First-class Next.js (App Router) adapter for {@link CboxIdClient}. It wires the
 * framework-agnostic core to short-lived, httpOnly cookies so login is a couple of
 * route handlers:
 *
 * ```ts
 * // app/auth/[...cbox]/route.ts is up to you; a minimal wiring:
 * import { cboxId } from '@/lib/cbox';
 *
 * export async function GET(request: NextRequest) {
 *   return cboxId.signIn();
 * }
 * ```
 *
 * The temporary state/verifier/nonce cookies are httpOnly, `SameSite=Lax`, and
 * expire in 10 minutes, so a stalled login cleans itself up.
 */

const COOKIE = {
  state: 'cbox_id_state',
  verifier: 'cbox_id_verifier',
  nonce: 'cbox_id_nonce',
  // The step-up requirement has to survive the redirect like the nonce does: a
  // `maxAge` the callback cannot see is a `maxAge` nothing verifies.
  maxAge: 'cbox_id_max_age',
  // Likewise the organization a switch bound to: the callback refuses tokens for another.
  organization: 'cbox_id_organization',
} as const;

const TEMP_COOKIE_MAX_AGE = 600; // 10 minutes

export interface CboxIdNext {
  /** The underlying framework-agnostic client. */
  readonly client: CboxIdClient;
  /**
   * Redirect to Cbox ID's authorize endpoint, stashing PKCE/state/nonce in cookies.
   *
   * `maxAge` (seconds) demands a re-authentication no older than that — the OIDC
   * step-up you want before a payment or an admin grant. It round-trips in a cookie
   * and {@link CboxIdNext.callback} verifies the id_token's `auth_time` against it.
   */
  signIn(options?: SignInOptions): Promise<NextResponse>;
  /**
   * Redirect to a new sign-in bound to another organization — the handler behind an
   * organization switcher. See {@link CboxIdClient.switchOrganization}: a person who is
   * not an active member comes back with `error=access_denied`, and {@link callback}
   * throws an `AuthenticationError` whose `error` is `'access_denied'`.
   */
  switchOrganization(organizationId: string, options?: Omit<SignInOptions, 'organization' | 'organizationHint'>): Promise<NextResponse>;
  /** Complete login on your callback route; returns the authenticated user. */
  callback(request: NextRequest): Promise<CboxUser>;
  /** The hosted profile-page URL (`return_to` appended when given). */
  profileUrl(returnTo?: string): string;
  /** A redirect response to the hosted profile page. */
  profileRedirect(returnTo?: string): NextResponse;
  /**
   * RP-initiated logout URL, or null when the instance advertises none. Pass the
   * user's `id_token` as `idTokenHint` when you kept it; `client_id` is sent for
   * you, and is what lets the OP honour `returnTo` at all.
   */
  signOutUrl(returnTo?: string, idTokenHint?: string): Promise<string | null>;
}

/**
 * What {@link CboxIdNext.signIn} accepts: every authorization option except the callback
 * and `state`, which the adapter owns because it stores them in cookies.
 */
export type SignInOptions = Omit<AuthorizationRequestOptions, 'redirectUri' | 'state'>;

/**
 * Build a Next.js adapter. Pass a config, or omit it to read from the environment
 * (`CBOX_ID_ISSUER`, `CBOX_ID_CLIENT_ID`, `CBOX_ID_CLIENT_SECRET`,
 * `CBOX_ID_REDIRECT_URI`).
 */
export function createCboxId(config?: Partial<CboxIdConfig>): CboxIdNext {
  const resolved = resolveConfig(config);
  const client = new CboxIdClient(resolved);

  const tempCookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'lax' as const,
    path: '/',
    maxAge: TEMP_COOKIE_MAX_AGE,
  };

  // One place that stashes PKCE/state/nonce, so a switch cannot forget what a sign-in
  // stores — a missing verifier cookie fails the callback, a missing max-age cookie
  // silently skips the step-up check.
  const redirectTo = (request: AuthorizationRequest): NextResponse => {
    const response = NextResponse.redirect(request.url);
    response.cookies.set(COOKIE.state, request.state, tempCookieOptions);
    response.cookies.set(COOKIE.verifier, request.codeVerifier, tempCookieOptions);
    response.cookies.set(COOKIE.nonce, request.nonce, tempCookieOptions);
    if (typeof request.maxAge === 'number') {
      response.cookies.set(COOKIE.maxAge, String(request.maxAge), tempCookieOptions);
    }
    if (request.organization !== undefined) {
      response.cookies.set(COOKIE.organization, request.organization, tempCookieOptions);
    } else {
      // A plain sign-in after an abandoned switch must not inherit its binding.
      response.cookies.delete(COOKIE.organization);
    }
    return response;
  };

  return {
    client,

    async signIn(options = {}) {
      return redirectTo(await client.createAuthorizationRequest(options));
    },

    async switchOrganization(organizationId, options = {}) {
      return redirectTo(await client.switchOrganization(organizationId, options));
    },

    async callback(request) {
      const storedMaxAge = request.cookies.get(COOKIE.maxAge)?.value;
      const maxAge = storedMaxAge !== undefined ? Number(storedMaxAge) : undefined;
      const organization = request.cookies.get(COOKIE.organization)?.value;

      return client.authenticate({
        params: {
          code: request.nextUrl.searchParams.get('code'),
          state: request.nextUrl.searchParams.get('state'),
          error: request.nextUrl.searchParams.get('error'),
          error_description: request.nextUrl.searchParams.get('error_description'),
        },
        stored: {
          state: request.cookies.get(COOKIE.state)?.value ?? '',
          codeVerifier: request.cookies.get(COOKIE.verifier)?.value ?? '',
          nonce: request.cookies.get(COOKIE.nonce)?.value ?? '',
          ...(maxAge !== undefined && Number.isFinite(maxAge) ? { maxAge } : {}),
          ...(organization !== undefined && organization !== '' ? { organization } : {}),
        },
      });
    },

    profileUrl(returnTo) {
      return client.profileUrl(returnTo);
    },

    profileRedirect(returnTo) {
      return NextResponse.redirect(client.profileUrl(returnTo));
    },

    signOutUrl(returnTo, idTokenHint) {
      return client.logoutUrl(returnTo, idTokenHint);
    },
  };
}

function resolveConfig(config?: Partial<CboxIdConfig>): CboxIdConfig {
  const issuer = config?.issuer ?? process.env['CBOX_ID_ISSUER'];
  const clientId = config?.clientId ?? process.env['CBOX_ID_CLIENT_ID'];
  const redirectUri = config?.redirectUri ?? process.env['CBOX_ID_REDIRECT_URI'];
  const clientSecret = config?.clientSecret ?? process.env['CBOX_ID_CLIENT_SECRET'];

  if (!issuer || !clientId || !redirectUri) {
    throw new ConfigurationError(
      'Cbox ID needs issuer, clientId and redirectUri — pass them to createCboxId() or set CBOX_ID_ISSUER / CBOX_ID_CLIENT_ID / CBOX_ID_REDIRECT_URI.',
    );
  }

  return {
    issuer,
    clientId,
    redirectUri,
    ...(clientSecret ? { clientSecret } : {}),
    ...(config?.scopes ? { scopes: config.scopes } : {}),
    ...(config?.accountPath ? { accountPath: config.accountPath } : {}),
    ...(config?.timeoutMs ? { timeoutMs: config.timeoutMs } : {}),
    ...(config?.cacheTtlMs ? { cacheTtlMs: config.cacheTtlMs } : {}),
  };
}
