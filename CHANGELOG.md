# Changelog

All notable changes to `@cboxdk/id-js` are recorded here. Earlier releases are described
in their [GitHub releases](https://github.com/cboxdk/id-js/releases).

## Unreleased

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
- Exported types `AuthorizationPrompt`, `AuthorizationRequestOptions`,
  `OrganizationRole`, `CboxActiveOrganization`, `CboxActor`, `ClaimSource`,
  `CboxOrganization`, and `SignInOptions` from `@cboxdk/id-js/nextjs`.

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
- `CboxUser` has four new required fields. Code that builds a `CboxUser` by hand (test
  fixtures) must add `organization: null, roles: [], permissions: [], actor: null`.
