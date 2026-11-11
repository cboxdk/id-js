import { WorkspaceClient, workspaceOperations, type WorkspaceClientOptions } from './generated/workspace.js';

/**
 * Cbox ID — the organization plane: the customer's own Cbox account, above every
 * environment it owns, with its projects, environments, members and keys.
 *
 * Cbox ID calls the account an organization; this SDK called it a workspace. This is the
 * {@link WorkspaceClient} under its new name — same methods, same options — so code typed
 * against the old name accepts it. It takes a `cbid_org_…` key or a `cbid_ws_…` one.
 *
 * ```ts
 * const org = new OrganizationClient({ apiUrl: 'https://api.cboxid.com', apiKey: process.env.CBOX_ID_ORGANIZATION_KEY })
 * const { data: environments } = await org.environments.list()
 * ```
 */
export class OrganizationClient extends WorkspaceClient {}

/** Options of {@link OrganizationClient}: the {@link WorkspaceClientOptions}. */
export type OrganizationClientOptions = WorkspaceClientOptions;

/** Every operation of the organization plane: {@link workspaceOperations} under its new name. */
export const organizationOperations = workspaceOperations;
