# id-js 0.20.0

Status: prepared local candidate. No public tag, registry publication or deployment has occurred.

Add request-bound live permission decisions and catalog checksums; regenerate app catalog, role-definition activation, invitations and native management APIs.

## Upgrade requirements

Workspace team.remove requires its body with roles_version. Team writes use roles arrays and current CAS versions. Re-read state on conflicts. Live permission checks bind subject, organization and app; access-token role projections alone do not authorize sensitive actions.

Dependency installation against public registries remains contingent on the approved release cascade. Local artifact checks prove the enclosed contents only; they do not claim public indexing.
