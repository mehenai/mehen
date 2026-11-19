// Workspace approval authority is supplied by authoriseWorkspaceRelay's hooks.
// Bare-engine tests may inspect a request presentation, never mint a grant.
import type { ApprovalSubject } from "@mehen/protocol"
import { VaultError } from "../http.ts"
import { runs } from "../vault/areas/runs.ts"
import type { DevicePrincipal,VaultContext } from "../vault/core.ts"
import type { ApprovalPresentation,RunsService } from "../vault/services.ts"

export type RelayServices = {
  reviewRequest(ctx: VaultContext,device: DevicePrincipal,subject: ApprovalSubject,presentation: ApprovalPresentation): Promise<void>
  placeholdersFor: RunsService["placeholdersFor"]
}
const real: RelayServices = {
  async reviewRequest() { throw new VaultError("internal","The workspace approval handler is unavailable.") },
  placeholdersFor: (ctx,principal,run) => runs.placeholdersFor(ctx,principal,run),
}
export const relayServices: RelayServices = { ...real }
export function setRelayServices(overrides: Partial<RelayServices>): void { Object.assign(relayServices,real,overrides) }
