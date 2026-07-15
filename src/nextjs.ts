import { NextResponse, type NextRequest } from 'next/server';
import { CboxIdClient } from './client.js';
import { ConfigurationError } from './errors.js';
import type { CboxIdConfig, CboxUser } from './types.js';

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
} as const;

const TEMP_COOKIE_MAX_AGE = 600; // 10 minutes

export interface CboxIdNext {
  /** The underlying framework-agnostic client. */
  readonly client: CboxIdClient;
  /** Redirect to Cbox ID's authorize endpoint, stashing PKCE/state/nonce in cookies. */
  signIn(options?: { scopes?: string[]; prompt?: string; loginHint?: string }): Promise<NextResponse>;
  /** Complete login on your callback route; returns the authenticated user. */
  callback(request: NextRequest): Promise<CboxUser>;
  /** The hosted profile-page URL (`return_to` appended when given). */
  profileUrl(returnTo?: string): string;
  /** A redirect response to the hosted profile page. */
  profileRedirect(returnTo?: string): NextResponse;
  /** RP-initiated logout URL, or null when the instance advertises none. */
  signOutUrl(returnTo?: string): Promise<string | null>;
}

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

  return {
    client,

    async signIn(options = {}) {
      const request = await client.createAuthorizationRequest(options);
      const response = NextResponse.redirect(request.url);
      response.cookies.set(COOKIE.state, request.state, tempCookieOptions);
      response.cookies.set(COOKIE.verifier, request.codeVerifier, tempCookieOptions);
      response.cookies.set(COOKIE.nonce, request.nonce, tempCookieOptions);
      return response;
    },

    async callback(request) {
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
        },
      });
    },

    profileUrl(returnTo) {
      return client.profileUrl(returnTo);
    },

    profileRedirect(returnTo) {
      return NextResponse.redirect(client.profileUrl(returnTo));
    },

    signOutUrl(returnTo) {
      return client.logoutUrl(returnTo);
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
