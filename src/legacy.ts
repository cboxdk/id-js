import { ConfigurationError } from './errors.js';

/**
 * The handler on YOUR side of a legacy migration.
 *
 * Cbox ID offers it an email and a password it has never seen, and your code answers with
 * the person or with nothing. On a yes they are created in Cbox ID as a result of the
 * login that just succeeded, and from their next sign-in the old system is never asked
 * again.
 *
 * WHY THIS IS A FACTORY AND NOT A DOCUMENT. The wire format is simple enough to describe
 * in a paragraph — a signed POST, JSON in, JSON out — and describing it would mean every
 * customer writes the signature check themselves. That check is exactly the part people
 * get wrong: `===` instead of a constant-time compare, no freshness window, no thought
 * about replay. So the factory owns all of it and you write the one function that knows
 * your own database.
 *
 * It is deliberately framework-agnostic: it takes a `Request` and returns a `Response`,
 * which is what Next.js route handlers, Remix, Hono, Bun and Deno all speak natively.
 */

/** What your handler answers with. Returning `null` means "no", and is not an error. */
export interface LegacyUser {
  email: string;
  name?: string | null;
  emailVerified?: boolean;
  /**
   * Your stored hash, when you can expose it.
   *
   * Passing it lets the person keep their password in Cbox ID verbatim — it is stored as
   * is and upgraded to the platform hasher on their next login, exactly like a
   * bulk-imported user. Omit it and Cbox ID hashes the password they just proved they
   * know, which is the honest option when your store cannot hand a hash over.
   */
  passwordHash?: string;
}

export interface LegacyVerifierOptions {
  /** The same secret you declared in your manifest, or configured in the console. */
  secret: string;
  /**
   * Decide whether these credentials are good, and say who they belong to.
   *
   * Return `null` for no. THROWING IS NOT THE SAME as returning null: a throw means your
   * store could not decide, and is answered with a 503 so Cbox ID refuses the sign-in
   * rather than treating an outage as a wrong password.
   */
  verify: (email: string, password: string) => Promise<LegacyUser | null>;
  /**
   * How far out of date a request may be, in seconds. Defaults to 300.
   *
   * A window is what makes a captured request stop working. Too wide and a recording is
   * useful for hours; too narrow and ordinary clock skew starts refusing real traffic.
   */
  toleranceSeconds?: number;
}

/**
 * Build the request handler.
 *
 * ```ts
 * // app/api/cbox-legacy/route.ts
 * export const POST = createLegacyVerifier({
 *   secret: process.env.CBOX_LEGACY_SECRET!,
 *   async verify(email, password) {
 *     const row = await db.users.findByEmail(email)
 *     if (!row || !(await argon2.verify(row.password, password))) return null
 *     return { email: row.email, name: row.name, emailVerified: !!row.confirmedAt }
 *   },
 * })
 * ```
 */
export function createLegacyVerifier(options: LegacyVerifierOptions): (request: Request) => Promise<Response> {
  if (!options.secret || options.secret.length < 32) {
    throw new ConfigurationError(
      'A legacy verifier secret must be at least 32 characters; it is the only thing proving a request came from Cbox ID.',
    );
  }

  const tolerance = options.toleranceSeconds ?? 300;

  return async function handle(request: Request): Promise<Response> {
    // Read once. The signature covers the RAW body, so re-serializing parsed JSON would
    // produce different bytes and every valid request would be refused.
    const raw = await request.text();

    if (!(await isSignedByCboxId(raw, request.headers.get('X-Cbox-Signature'), options.secret, tolerance))) {
      // No detail. A caller who cannot sign is not owed help distinguishing "bad
      // signature" from "stale timestamp" — both mean the same thing to anyone
      // legitimate, and the difference is a hint to anyone else.
      return json({ error: 'unauthorized' }, 401);
    }

    let payload: { email?: unknown; password?: unknown };

    try {
      payload = JSON.parse(raw) as typeof payload;
    } catch {
      return json({ error: 'invalid_request' }, 400);
    }

    const { email, password } = payload;

    if (typeof email !== 'string' || email === '') {
      return json({ error: 'invalid_request' }, 400);
    }

    // No password means Cbox ID is asking "do you know this address" — the tooling path,
    // used for a dry run before cutover. It never reaches here from a sign-in.
    if (typeof password !== 'string') {
      return json({ user: null }, 200);
    }

    let user: LegacyUser | null;

    try {
      user = await options.verify(email, password);
    } catch {
      // 503, not 401. Your store could not decide, and Cbox ID must refuse the sign-in
      // rather than read an outage as a wrong password — but it should also be able to
      // tell the two apart in its own logs, which a 401 would hide.
      return json({ error: 'unavailable' }, 503);
    }

    if (!user) {
      return json({ user: null }, 200);
    }

    return json(
      {
        email: user.email,
        name: user.name ?? null,
        email_verified: user.emailVerified === true,
        ...(user.passwordHash ? { password_hash: user.passwordHash } : {}),
      },
      200,
    );
  };
}

/**
 * Whether this body was signed by Cbox ID, recently.
 *
 * Both halves matter. The HMAC proves it came from something holding the secret; the
 * freshness window is what stops a captured request working forever. Compared in constant
 * time, because a comparison that returns early leaks how much of a guess was right.
 */
async function isSignedByCboxId(
  body: string,
  header: string | null,
  secret: string,
  toleranceSeconds: number,
): Promise<boolean> {
  if (!header) {
    return false;
  }

  const parts: Record<string, string> = {};

  for (const piece of header.split(',')) {
    const [key, value] = piece.split('=', 2);
    if (key && value) {
      parts[key.trim()] = value.trim();
    }
  }

  const timestamp = parts['t'] ?? '';
  const signature = parts['v1'] ?? '';

  if (!/^\d+$/.test(timestamp) || signature === '') {
    return false;
  }

  if (Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp)) > toleranceSeconds) {
    return false;
  }

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${body}`));
  const expected = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');

  return timingSafeEqual(expected, signature);
}

/** Constant-time string compare. Length is not secret; content is. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;

  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return diff === 0;
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
