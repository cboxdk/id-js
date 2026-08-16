# @cboxdk/id-js

Turnkey [Cbox ID](https://github.com/cboxdk/laravel-id) client for JavaScript /
TypeScript. It speaks standard OpenID Connect against a Cbox ID instance — so
integrating is a redirect and a callback, not a rewrite — and adds the conveniences a
hosted-identity product needs:

- **Login** — one redirect, one callback. PKCE (S256), a CSRF `state`, a nonce, and
  full `id_token` verification (signature against the instance's JWKS via
  [`jose`](https://github.com/panva/jose), plus issuer, audience and nonce) are
  handled for you.
- **Hosted profile management** — send a signed-in user to the instance's own account
  page (password, MFA, passkeys, sessions) and back to your app.
- **Back-channel calls** — machine (client-credentials) tokens, UserInfo, RFC 7662
  introspection, RFC 7009 revocation.
- **Webhook / action verification** — confirm an inbound `X-Cbox-Signature`.

Runs on Node, edge runtimes and the browser (built on Web Crypto and `fetch`), with a
first-class **Next.js** adapter.

## Install

> **Where do `issuer`, `clientId` and `redirectUri` come from?**
> Register an application in your environment console — see
> [Integrate your app](https://github.com/cboxdk/cbox-id/blob/main/docs/getting-started/integrate-your-app.md).

```bash
npm install @cboxdk/id-js
```

## Next.js (App Router)

```ts
// lib/cbox.ts
import { createCboxId } from '@cboxdk/id-js/nextjs';

// Reads CBOX_ID_ISSUER / CBOX_ID_CLIENT_ID / CBOX_ID_CLIENT_SECRET / CBOX_ID_REDIRECT_URI
export const cboxId = createCboxId();
```

```ts
// app/auth/sign-in/route.ts
import { cboxId } from '@/lib/cbox';
export const GET = () => cboxId.signIn();
```

```ts
// app/auth/callback/route.ts
import { NextResponse, type NextRequest } from 'next/server';
import { cboxId } from '@/lib/cbox';

export async function GET(request: NextRequest) {
  const user = await cboxId.callback(request); // verifies state, PKCE and the id_token
  // create your own session for `user.id` (the stable subject), then:
  return NextResponse.redirect(new URL('/dashboard', request.url));
}
```

Send users to hosted profile management:

```ts
// app/account/route.ts
import { cboxId } from '@/lib/cbox';
export const GET = () => cboxId.profileRedirect('/dashboard');
```

## Any framework (the core)

`CboxIdClient` is framework-agnostic — it hands you the values to persist and takes
them back:

```ts
import { CboxIdClient } from '@cboxdk/id-js';

const client = new CboxIdClient({
  issuer: 'https://id.acme.com',
  clientId: process.env.CBOX_ID_CLIENT_ID!,
  clientSecret: process.env.CBOX_ID_CLIENT_SECRET,
  redirectUri: 'https://app.acme.com/auth/callback',
});

// Start login — persist state/codeVerifier/nonce (e.g. signed httpOnly cookies).
const { url, state, codeVerifier, nonce } = await client.createAuthorizationRequest();
// redirect the user to `url` ...

// On the callback:
const user = await client.authenticate({
  params: { code, state: callbackState },
  stored: { state, codeVerifier, nonce },
});
```

## In the browser (publishable keys)

Everything above needs a server: it holds your client secret. A **publishable key** is the
opposite — it is public on purpose, it ships in your bundle, and it lets a page read its
own sign-in configuration without routing that through your backend.

```ts
import { CboxIdFrontend } from '@cboxdk/id-js'

const frontend = new CboxIdFrontend({
  issuer: 'https://id.acme.com',
  publishableKey: 'pk_live_…', // safe in your bundle
})

const config = await frontend.config()
// → endpoints, social buttons, and the customer's theme

const { user } = await frontend.session(accessToken)
// → { id, email, name } or null
```

**What makes a public key safe:** every key carries an allow-list of origins, and a request
from anywhere else is refused. A key that leaks still only works from the sites you
registered — the same shape as a Stripe publishable key plus registered domains. Add your
origins when you create the key in the console; exact matches only, so `https://acme.com`
does not cover `https://www.acme.com`.

`config()` is fetched once per instance and shared between however many components ask for
it at the same time. `session()` returns `{ user: null }` rather than throwing when nobody
is signed in — signed-out is a state, not an error, and a user button renders on pages
nobody has signed in on.

The publishable key grants nothing on its own: the access token is the entire authority for
`session()`. Pasting a client secret here throws immediately rather than failing later as an
opaque 401.

Failures are typed, because the four ways this goes wrong need four different responses and
telling them apart from a message string breaks the moment somebody rewords it:

```ts
import { FrontendApiError } from '@cboxdk/id-js'

try {
  await frontend.config()
} catch (e) {
  if (e instanceof FrontendApiError) {
    e.code // 'origin_not_allowed' | 'rate_limited' | 'unavailable' | 'malformed'
    e.retryAfter // seconds, when the server said
  }
}
```

Transient failures are retried twice by default (`retries`). A refusal is not — it is a
configuration problem, and retrying it only delays you finding out. A rate limit is
surfaced rather than hammered.

### Signing in from your own form

> **This half needs a server that implements it.** `config()` and `session()` are served by
> the `cboxdk/laravel-id` package itself, so they work against any instance built on it.
> `signIn()`, `submitSecondFactor()` and the passkey calls are not: they post to
> `/frontend/v1/sign-in*`, which *is* the sign-in policy and therefore lives in the
> application rather than the package. [Cbox ID](https://github.com/cboxdk/cbox-id)
> implements them; a bare `laravel-id` install answers 404 to all four.
>
> In a browser a 404 on a cross-origin request is indistinguishable from a dead network, so
> this surfaces as `FrontendApiError` with `code: 'unavailable'` — nothing mentions a
> missing route. **If `config()` works and `signIn()` says the service is unreachable, this
> is why.**

```ts
const result = await frontend.signIn(email, password)

if (result.status === 'ok') {
  // Spend the ticket on the ordinary authorize flow, with your own PKCE challenge.
  window.location.href = `${config.endpoints.authorization}?${new URLSearchParams({
    client_id, redirect_uri, response_type: 'code',
    code_challenge, code_challenge_method: 'S256',
    login_ticket: result.loginTicket,
  })}`
}
```

**You get a ticket, never a token.** Handing tokens to a page that proved a password is the
implicit grant, which OAuth 2.1 removes: tokens in a URL, in history, in `Referer`, with no
client authentication and no PKCE binding. The ticket is single-use, lasts sixty seconds,
and is for one redirect — not for storing.

The other outcomes are `mfa_required`, `otp_required` and `sso_required`. That last one
matters: showing "wrong password" to somebody whose organization mandates SSO sends them to
support instead of to their identity provider.

For the first two, finish with the code:

```ts
if (result.status === 'mfa_required' || result.status === 'otp_required') {
  // The third argument is not optional for an emailed code: an `otp_required` finished
  // with the default 'mfa' is answered against the wrong challenge and refused.
  const method = result.status === 'otp_required' ? 'otp' : 'mfa'
  const done = await frontend.submitSecondFactor(result.mfaToken, code, method)
  // done.status === 'ok' → spend done.loginTicket exactly as above
}
```

### Passkeys

```ts
const options = await frontend.passkeyOptions()

const assertion = await navigator.credentials.get({
  publicKey: { ...options, challenge: decode(options.challenge) },
})

const result = await frontend.signInWithPasskey(options.challenge_token, serialise(assertion))
```

The `challenge_token` carries the challenge between the two requests WebAuthn needs, in
place of the session cookie a cross-origin page does not have. It is single-use.

**The relying party is the issuer's, not your page's.** WebAuthn binds an assertion to the
origin that asked for it — that is what makes a passkey phishing-resistant — so an embedded
button on `acme.com` still authenticates against the issuer's `rpId`. If your page is on a
different registrable domain from your Cbox ID issuer, passkeys need the hosted page or a
subdomain of the issuer. That is WebAuthn working as designed rather than a limitation to
route around, and it is the first thing that surprises people.

The `mfaToken` carries the pending state, because a cross-origin page has no session cookie
to carry it in. A TOTP code or a recovery code both work — an embedded form that could not
accept a recovery code would strand exactly the people that escape hatch exists for. A wrong
code costs an attempt, not the sign-in: five are allowed before the token dies.

**Present every refusal identically.** `invalid` covers a wrong password, an unknown address
and a locked account — the server refuses to distinguish them, because that is the
enumeration oracle, and a UI that distinguishes them rebuilds it.

## Back-channel calls

```ts
const token = await client.machineToken({ scopes: ['reports.read'] });   // as your app
const claims = await client.userinfo(user.accessToken);                  // as a user
const introspection = await client.introspect(someToken);                // RFC 7662
await client.revoke(user.refreshToken!, 'refresh_token');                // RFC 7009
```

Revoking a refresh token drops the whole token family — that's what "sign out
everywhere" needs. `machineToken`, `introspect` and `revoke` authenticate as the
client, so they require a `clientSecret`; `userinfo` authenticates with the user's
own access token and does not.

## Migrating off an old login

Bulk-importing users with their existing hashes is the first answer, and the better one.
When you cannot export those hashes, Cbox ID can ask your old system instead — and import
each person at the moment they sign in.

Declare where it lives, alongside your roles:

```ts
export default defineAuthz({
  roles: [...],
  legacyLogin: {
    url: 'https://acme.com/api/cbox-legacy',
    secret: process.env.CBOX_LEGACY_SECRET!, // 32+ chars
  },
})
```

It rides the manifest because it is the same kind of fact as a role — something your app
knows about itself, deployed with the code. **It does not take effect on its own:** unlike
a role, this names a URL that every unknown email and the password typed with it will be
offered to, so an operator approves it once in the console. Changing the URL later drops
that approval, deliberately.

Then write the handler — one function, no signature code:

```ts
// app/api/cbox-legacy/route.ts
import { createLegacyVerifier } from '@cboxdk/id-js'

export const POST = createLegacyVerifier({
  secret: process.env.CBOX_LEGACY_SECRET!,
  async verify(email, password) {
    const row = await db.users.findByEmail(email)
    if (!row || !(await argon2.verify(row.password, password))) return null

    return { email: row.email, name: row.name, emailVerified: !!row.confirmedAt }
  },
})
```

The factory owns the HMAC check, the freshness window, the constant-time compare and the
response shape — the parts that are easy to get subtly wrong. You own the one function
that knows your database.

Return `null` for "wrong password". **Throwing is different:** it means your store could
not decide, and is answered with a 503 so Cbox ID refuses the sign-in rather than reading
an outage as a bad password. Returning `passwordHash` lets the person keep their password
verbatim; omit it and Cbox ID hashes the one they just proved they know.

It returns a `Request → Response` handler, so it drops into Next.js route handlers, Remix,
Hono, Bun and Deno unchanged.

## Verify webhooks

```ts
import { verifyWebhook } from '@cboxdk/id-js';

const ok = await verifyWebhook({
  payload: rawBody,                       // the exact bytes received
  signatureHeader: req.headers['x-cbox-signature'],
  secret: process.env.CBOX_ID_WEBHOOK_SECRET!,
});
```

## Token Vault

Broker downstream credentials (API keys for OpenAI, GitHub, …) through the instance's
Token Vault: provision + grant with a `vault.manage` token, and let an authorized
agent client redeem the plaintext with a `vault.lease` token.

```ts
// Provisioning backend (vault.manage)
const admin = client.vault(await client.machineToken({ scopes: ['vault.manage'] }));
const secret = await admin.store({ name: 'openai', provider: 'openai', secret: 'sk-live-…' });
await admin.grant(secret.id, 'agent-1');

// Agent worker (vault.lease) — keyed on its own client
const agent = client.vault(await client.machineToken({ scopes: ['vault.lease'] }));
const lease = await agent.lease(secret.id, 'call openai');
// use lease.secret immediately; it is never persisted
```

A lease with no live grant is refused — the vault is deny-by-default.

## Roles & permissions (federated RBAC)

Declare your app's authorization **roles** and **permissions** in code, then push them
to Cbox ID on deploy. Your app owns what a role *means*; Cbox ID owns identity and who
*holds* each role — assignments arrive back in the token's `roles` / `permissions`
claims for you to enforce. Requires the app's client to hold the `apps.manifest` scope.

```ts
import { defineAuthz, publishManifest } from '@cboxdk/id-js';

// Declare the catalog (validated: keys are `feature:action`, roles must reference
// declared permissions). Keep this next to the code that enforces it.
export const authz = defineAuthz({
  permissions: [
    { key: 'invoices:create', description: 'Create invoices' },
    { key: 'invoices:read', description: 'View invoices' },
  ],
  roles: [
    { key: 'billing-admin', name: 'Billing Admin', description: 'Full billing access',
      permissions: ['invoices:create', 'invoices:read'] },
  ],
});

// Push it — run from a deploy step or a `package.json` script. Idempotent: an
// unchanged catalog is a server-side no-op (the manifest carries a content hash).
const summary = await publishManifest(
  {
    issuer: process.env.CBOX_ID_ISSUER!,
    clientId: process.env.CBOX_ID_CLIENT_ID!,
    clientSecret: process.env.CBOX_ID_CLIENT_SECRET!,
  },
  authz,
);
// → { unchanged, roles_declared, permissions_declared, ... }
```

`publishManifest` mints a client-credentials token (`scope=apps.manifest`) and POSTs
the manifest to `{issuer}/api/v1/apps/manifest`. It is a server-side operation — keep
your `clientSecret` off the browser. The wire format matches the PHP SDK
(`cboxdk/laravel-id-client`), so any SDK can publish the same catalog.

## Security & scope

Login is hardened by default — PKCE, `state`, nonce, and full `id_token` verification
(signature/issuer/audience) via `jose`; webhook checks are constant-time within a
freshness window. Keep `clientSecret` and webhook secrets server-side.

This is a **client**. It authenticates users and calls a Cbox ID instance's standard
endpoints; it does not configure SSO, run SCIM, or manage organizations — those are
platform capabilities of [`cboxdk/laravel-id`](https://github.com/cboxdk/laravel-id).

Report vulnerabilities via this repo's GitHub **Private Vulnerability Reporting**.

## License

MIT © Cbox.
