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

## Back-channel calls

```ts
const token = await client.machineToken({ scopes: ['reports.read'] });   // as your app
const claims = await client.userinfo(user.accessToken);                  // as a user
const introspection = await client.introspect(someToken);                // RFC 7662
await client.revoke(user.refreshToken!, 'refresh_token');                // RFC 7009
```

Revoking a refresh token drops the whole token family — that's what "sign out
everywhere" needs. Both calls are confidential-client, so they require a `clientSecret`.

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
