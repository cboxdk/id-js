# Agents and CLIs: CIBA and the device grant

`@cboxdk/id-js/agent` gets a token for a CLI or an agent acting for a person, without a
browser redirect. It covers OpenID CIBA (poll mode), the RFC 8628 device grant, and RFC 7591
registration with a `private_key_jwt` key. It needs only `fetch` and WebCrypto, so it runs on
Node 20+, Deno, Bun and edge runtimes.

```ts
import {
  registerAgentClient,
  startBackchannel,
  waitForBackchannelToken,
  createBindingCode,
} from '@cboxdk/id-js/agent';
```

Use it instead of writing the polling loop yourself. It handles the interval, `slow_down`,
`Retry-After`, expiry, Ctrl-C and the client assertion.

## CIBA or the device grant?

| | CIBA (backchannel) | Device grant |
|---|---|---|
| Who starts it | Your program, naming the person (`login_hint`) | Your program, for whoever enters the code |
| What the person does | Taps **Approve** in Cbox ID (an email or a notification) and checks that the code matches | Opens a URL and types a code |
| Your program must know who the person is | Yes: a Cbox ID user id or a confirmed email | No |
| Client authentication | `private_key_jwt` (recommended) or a secret. Keyless (`none`) only where the resource allows it | `none` works |
| Good for | Agents and CLIs that already know their user and ask again later (a background agent asking before a sensitive step) | First sign-in on a new machine, or a tool that does not know who will use it |

Rule of thumb: use the device grant when you do not know who the person is yet. Use CIBA once
you do, for example after one device sign-in, or for a long-running agent that asks its owner
to approve before it acts.

## What Cbox ID requires

- **`binding_message`**: required for self-registered clients. Cbox ID shows it beside
  Approve, so put a short code from `createBindingCode()` in it and print the same code in
  your terminal. The person approves only when the two match. At most 255 characters.
- **Keyless CIBA only where the resource allows it.** A self-registered `none` client may use
  CIBA only when the resource has `dynamic_public_backchannel` switched on. Otherwise Cbox ID
  answers `invalid_target` ("this resource lets self-registered clients use CIBA only with
  private_key_jwt"). Use `private_key_jwt` for CIBA unless you have a reason not to: a
  public `client_id` proves nothing about who is asking.
- **`resource`** (RFC 8707): required for self-registered clients, even though the
  TypeScript option is optional (console-registered apps may omit it). Name the API the token is
  for. The poll re-sends the same value automatically, and a mismatch is `invalid_target`.
- **No `user_code`**: Cbox ID does not support `backchannel_user_code_parameter`, so the
  helper never sends one.
- Endpoints are read from `{issuer}/.well-known/oauth-authorization-server`, and the
  document's `issuer` must match the one you configured.

## A Node CLI, end to end

This example registers once, stores the private key, starts CIBA, shows the code and polls.

```js
#!/usr/bin/env node
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  CIBA_GRANT_TYPE,
  registerAgentClient,
  discoverAuthorizationServer,
  startBackchannel,
  waitForBackchannelToken,
  createBindingCode,
  AccessDeniedError,
  ExpiredTokenError,
  GrantCancelledError,
} from '@cboxdk/id-js/agent';

const issuer = process.env.CBOX_ID_ISSUER; // e.g. https://acme.cboxid.com
const resource = 'https://app.cboxbrain.com/mcp';
const dir = join(homedir(), '.config', 'brain');
const file = join(dir, 'client.json');

const metadata = await discoverAuthorizationServer(issuer);

// 1. Register once per installation. Store the client id and the PRIVATE JWK, mode 0600.
let stored = await readFile(file, 'utf8').then(JSON.parse).catch(() => null);
if (stored === null) {
  const registered = await registerAgentClient({
    issuer,
    metadata,
    clientName: `Cbox Brain CLI (${process.env.USER ?? 'unknown'})`,
    grantTypes: [CIBA_GRANT_TYPE, 'refresh_token'],
    scope: 'openid mcp:read mcp:write offline_access',
  });
  stored = { clientId: registered.clientId, privateJwk: registered.keyPair.privateJwk };
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(file, JSON.stringify(stored), { mode: 0o600 });
}

const client = { method: 'private_key_jwt', clientId: stored.clientId, privateKey: stored.privateJwk };

// 2. Start: Cbox ID shows "Brain CLI wants access: K7QM" beside Approve.
const code = createBindingCode();
const authorization = await startBackchannel({
  issuer,
  metadata,
  client,
  loginHint: process.argv[2], // the person's Cbox ID user id or confirmed email
  scope: 'openid mcp:read mcp:write offline_access',
  bindingMessage: `Brain CLI wants access: ${code}`,
  resource,
});

console.log(`Approve the request in Cbox ID. Check that it shows ${code}.`);

// 3. Wait. Ctrl-C cancels at once instead of after the current interval.
const controller = new AbortController();
process.once('SIGINT', () => controller.abort());

try {
  const tokens = await waitForBackchannelToken({
    issuer,
    metadata,
    client,
    authorization,
    signal: controller.signal,
  });
  // Persist tokens.refreshToken (mode 0600) and use refreshAgentTokens() next time,
  // so the person is not asked again on every run.
  console.log('Approved.');
} catch (error) {
  if (error instanceof AccessDeniedError) console.error('Declined.');
  else if (error instanceof ExpiredTokenError) console.error('Nobody approved in time. Run again.');
  else if (error instanceof GrantCancelledError) console.error('Cancelled.');
  else throw error;
  process.exitCode = 1;
}
```

The device grant has the same shape. A public client can use it:

```js
import {
  DEVICE_CODE_GRANT_TYPE,
  registerAgentClient,
  startDeviceAuthorization,
  waitForDeviceToken,
} from '@cboxdk/id-js/agent';

const { auth: client } = await registerAgentClient({
  issuer,
  clientName: 'Cbox Brain CLI',
  grantTypes: [DEVICE_CODE_GRANT_TYPE, 'refresh_token'],
  tokenEndpointAuthMethod: 'none',
  scope: 'openid mcp:read offline_access',
});

const device = await startDeviceAuthorization({ issuer, client, scope: 'openid mcp:read offline_access', resource });
console.log(`Open ${device.verificationUri} and enter ${device.userCode}`);
const tokens = await waitForDeviceToken({ issuer, client, authorization: device });
```

The `idToken` in the result is returned as-is and is **not verified** by this module. If you
need the person's identity from it, verify it with `CboxIdClient` or against the JWKS first.
If you only need the access token for your API, ignore it.

## Polling rules

- The helper waits `interval` seconds (5 if the server omits it) before each poll.
- On `slow_down`, or on HTTP 429, it adds 5 seconds to the interval and keeps the slower rate
  from then on. If the 429 carries `Retry-After`, it waits at least that long.
- On `authorization_pending` it polls again.
- It stops with `ExpiredTokenError` once `expires_in` has passed, without sending another
  poll.
- `signal` aborts the wait at once with `GrantCancelledError`.
- `sleep` and `now` can be injected for tests. `pollBackchannel` and
  `pollDeviceAuthorization` make a single poll and return
  `{ status: 'pending' | 'slow_down' | 'complete' }`, if you want to drive the loop yourself.

## Errors

Every refusal is an `AgentGrantError`, which extends `AuthenticationError` and carries
`error`, `errorDescription`, `status` and `retryAfter`. The error message never contains the
response body.

| `error` | Class | When | What to do |
|---|---|---|---|
| `access_denied` | `AccessDeniedError` | The person declined | Stop. Don't retry by yourself |
| `expired_token` | `ExpiredTokenError` | Nobody approved before `expires_in` (also thrown locally) | Start a new request |
| `invalid_grant` | `InvalidGrantError` | The `auth_req_id`, `device_code` or refresh token is not valid | Start again. For a refresh token, sign in again |
| `invalid_target` | `InvalidTargetError` | The `resource` isn't allowed for this client, doesn't match the start request, or the resource allows CIBA for self-registered clients only with `private_key_jwt` and this client is keyless | Fix the resource, or register with `private_key_jwt` |
| `invalid_client` | `InvalidClientError` | Unknown client, wrong secret, assertion signed by an unregistered key, replayed `jti` | Check the stored credentials. Register again if the client was deleted |
| `unknown_user_id` | `UnknownUserIdError` | `login_hint` doesn't match anyone the server can reach | Ask for the right user id or email |
| `invalid_binding_message` | `InvalidBindingMessageError` | Missing (required from self-registered clients) or longer than 255 characters | Send a short message with a code |
| `slow_down` / HTTP 429 | `SlowDownError` | Rate limited. `retryAfter` is in seconds | The wait helpers handle it. From `start*` or `registerAgentClient`, wait `retryAfter` and retry |
| (cancelled) | `GrantCancelledError` | Your `AbortSignal` fired | None |
| anything else | `AgentGrantError` | For example `invalid_scope`, `unauthorized_client`, or a 5xx | Check `error` and `status` |

A missing endpoint (for example, registration switched off on the instance) throws
`ConfigurationError` before any request is sent.

## API

- `discoverAuthorizationServer(issuer, options?)` returns the RFC 8414 metadata.
- `generateClientKeyPair(alg = 'ES256')` returns `{ alg, kid, publicJwk, privateJwk, privateKey }`.
- `createClientAssertion(auth, audience, { lifetimeSeconds? })` returns an RFC 7523 JWT
  (`iss` = `sub` = client id, `aud`, `jti`, `iat`, `exp` at most 60 s later).
- `registerAgentClient({ issuer, clientName, grantTypes, scope?, tokenEndpointAuthMethod?, alg?, keyPair?, initialAccessToken?, extraMetadata? })`
  returns `{ clientId, clientSecret, keyPair, auth, registrationAccessToken, registrationClientUri, … }`.
- `startBackchannel({ issuer, client, loginHint, scope, bindingMessage, resource?, requestedExpiry?, nonce? })`
  returns `{ authReqId, expiresIn, interval, expiresAt, resource }`.
- `pollBackchannel({ issuer, client, authorization })` returns a `PollResult`.
- `waitForBackchannelToken({ issuer, client, authorization, signal?, sleep?, now? })` returns `AgentTokens`.
- `startDeviceAuthorization({ issuer, client, scope?, resource? })` returns
  `{ deviceCode, userCode, verificationUri, verificationUriComplete, expiresIn, interval, expiresAt, resource }`.
- `pollDeviceAuthorization(...)` and `waitForDeviceToken(...)` work like the CIBA pair.
- `refreshAgentTokens({ issuer, client, refreshToken, scope?, resource? })` returns
  `AgentTokens`. Cbox ID rotates refresh tokens, so always store the new one.
- `createBindingCode(length = 4)` returns a code such as `K7QM` from `BINDING_CODE_ALPHABET`,
  which leaves out 0/O, 1/I/L, 2/Z, 5/S and 8/B.

Every call also takes `metadata` (to skip discovery), `fetch`, `timeoutMs` and `signal`.
`client` is a `ClientAuth`: `private_key_jwt` (a `CryptoKey` or private JWK),
`client_secret_basic`, `client_secret_post` or `none` (which sends `client_id` only).
