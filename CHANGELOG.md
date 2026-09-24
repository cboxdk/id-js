# Changelog

All notable changes to `@cboxdk/id-js` are recorded here. Earlier releases are described
in their [GitHub releases](https://github.com/cboxdk/id-js/releases).

## [0.17.0] - 2026-09-24

Organization selection and support sessions. Needs a Cbox ID instance that understands the
`organization` / `organization_hint` authorize parameters and emits `org_role` and `act`
(laravel-id 1.19). Against an older instance the new fields stay empty, and a switch fails
at the callback instead of silently landing in the old organization (see below).

### Added

- `createAuthorizationRequest()` accepts `organization` (bind the sign-in to one
  organization), `organizationHint` (preselect it in the hosted picker), and the prompts
  `select_organization` and `create_organization`.
- `client.switchOrganization(id)` and, on the Next.js adapter,
  `cboxId.switchOrganization(id)`: a new authorization bound to another organization.
- The organization a sign-in was bound to is echoed on the `AuthorizationRequest` and
  verified at the callback (`stored.organization`): tokens for any other organization are
  refused. The Next.js adapter carries it in a `cbox_id_organization` cookie, and clears
  that cookie on a plain sign-in so an abandoned switch cannot leak its binding into it.
- `CboxUser` gains typed `organization` (`{ id, name, role }` from `org`, `org_name`,
  `org_role`), `roles`, `permissions` and `actor` (the RFC 8693 `act` claim).
- Claim helpers that work on a `CboxUser` or on a claim set you verified yourself:
  `organization()`, `actor()`, `isSupportSession()`, `roles()`, `permissions()`,
  `hasRole()`, `hasPermission()`.
- `client.apiKeysUrl({ clientId?, returnTo?, organization? })` (and `cboxId.apiKeysUrl()`
  on the Next.js adapter): the hosted page where a person creates and revokes API keys for
  your API, `/account/api-keys`, preselected to this app.
- `ApiKeyVerifier` in a new server-only entry, `@cboxdk/id-js/server`, and
  `cboxId.verifyApiKey(key)` on the Next.js adapter: verifies a customer API key with
  `POST /oauth/api-keys/verify` (HTTP Basic client auth) and returns the typed answer
  `{ active, key_id, sub, org, org_role, permissions, client_id, expires_at }`. It refuses
  an answer for any other `client_id`, treats a key past `expires_at` as inactive, refuses
  to run in a browser, and has an optional cache of active answers (`cacheTtlMs`, at most
  60 s, never past the key's expiry). Not exported from the main entry.
- `CboxUser.sessionId` and `sessionId()`: the ID Token's `sid`, the sign-in session a
  back-channel logout token names.
- Staff roles: `tenantAssignable: false` on a `RoleDefinition` publishes the role as
  staff-only (`tenant_assignable: false`), which Cbox ID never offers or accepts on an
  organization's own admin pages.
- Self-serve permissions: `tenantAssignable: true` on a `PermissionDefinition` publishes it
  as one an organization's administrators may put in their own custom roles
  (`tenant_assignable: true`). Permissions stay internal by default.
- Exported wire types `ManifestPermission` and `ManifestRole`.
- Exported types `AuthorizationPrompt`, `AuthorizationRequestOptions`,
  `OrganizationRole`, `CboxActiveOrganization`, `CboxActor`, `ClaimSource`,
  `CboxOrganization`, and `SignInOptions` from `@cboxdk/id-js/nextjs`.

### Fixed

- `CboxIdConfig.accountPath` was documented as defaulting to `/settings`, which on Cbox ID
  is the organization's settings page for its administrators. `profileUrl()` has actually
  defaulted to the person's own account area, `/account`, since 0.8.0; the documentation
  now says so. If you set `accountPath: '/settings'` because of it, remove it: members who
  are not organization admins are redirected away from that page and lose `return_to`.

### Changed

- An error returned to the callback (`?error=access_denied`) now sets
  `AuthenticationError.error` and `.errorDescription`, as the back-channel errors already
  did. A refused organization switch is `access_denied`, and an app answers it by switching
  back, not by signing the person out — which it could not tell apart before.
- `prompt` is typed as `AuthorizationPrompt | AuthorizationPrompt[]` instead of `string`,
  and `prompt: 'none'` combined with another value is refused (OIDC Core §3.1.2.1).
  **Breaking for TypeScript callers that pass a `string` variable**; narrow it to
  `AuthorizationPrompt`.
- `organization` together with `prompt: 'select_organization'` or `'create_organization'`,
  or an empty `organization` / `organizationHint`, throws `ConfigurationError` before any
  redirect.
- The manifest `version` now covers both `tenant_assignable` flags, byte-for-byte as the
  PHP reference hashes them: present only in their non-default state, so a catalog that
  never sets them keeps the version it had. The shared cross-SDK fixture gained the
  `staff_role` and `self_serve_permission` cases.
- `AuthzManifest.permissions` / `.roles` are typed as the wire shapes (`ManifestPermission`,
  `ManifestRole`, snake_case flags) rather than as the declaration types.
- `defineAuthz()` / `buildManifest()` now refuse a key that is not a lowercase
  `feature:action` slug, and a `tenantAssignable` that is not a boolean, with a
  `ConfigurationError` — both were refused by the server on push anyway.
- A role that lists the same permission twice is sent and hashed with it once, as the
  server stores it; the repeat used to give a `version` no server computes.
- `CboxUser` has five new required fields. Code that builds a `CboxUser` by hand (test
  fixtures) must add `organization: null, roles: [], permissions: [], actor: null,
  sessionId: null`.
