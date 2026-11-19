import { WorkspaceRefSchema, WorkspaceRoleSchema, type AccountRestriction, type PendingAccountSecurity } from "@mehen/protocol"
import { AccessInitInput, AccessInitOutput, InviteTermsViewSchema, InviteRedeemInput, InviteRedeemOutput } from "../vault/areas/access.ts"
import { SecurityInstallInput, SecurityCommitInput, SecurityOutput, OutboxDrainInput, OutboxDrainOutput, EnrolRegisterInput, PendingEnrolSchema, EnrolReconcileOutputSchema } from "../vault/areas/workspace-runtime.ts"
import { z } from "zod"
import type { Env } from "../env.ts"
import { invokeVault } from "../vault/client.ts"

// DIRECTORY's typed D1-side client. ACCESS owns and validates the corresponding
// system operations; none is exposed as a browser-supplied operation name.
export type DirectoryWorkspaceClient = {
  install(workspace: string, input: { account: string; committedEpoch: number; pending: PendingAccountSecurity | null }): Promise<{ installedEpoch: number }>
  commit(workspace: string, input: { account: string; committedEpoch: number }): Promise<{ installedEpoch: number }>
  restriction(workspace: string, input: { account: string; committedEpoch: number; restriction: AccountRestriction | null }): Promise<void>
  revokeSession(workspace: string, input: { account: string; session: string }): Promise<void>
  mirror(workspace: string, event: { id: string; account: string; at: number; action: string; detail: Record<string, unknown> }): Promise<void>
}
export type WorkspaceOutboxClient = {
  drain(workspace: string, limit: number): Promise<z.infer<typeof OutboxDrainOutput>>
  ack(workspace: string, ids: string[]): Promise<void>
}
export type WorkspaceInitialisationClient = Pick<DirectoryWorkspaceClient, "install"> & {
  init(workspace: string, input: { workspace: string; slug: string; name: string; member: string; owner: { account: string; name: string } }): Promise<{ member: string }>
}
export type InviteRedeemResult = z.infer<typeof InviteRedeemOutput>
export type WorkspaceJoinClient = Pick<DirectoryWorkspaceClient,"install"> & {
  lookupInvite(workspace: string, codeHash: string): Promise<z.infer<typeof InviteTermsViewSchema>>
  redeemInvite(workspace: string, input: z.infer<typeof InviteRedeemInput>): Promise<InviteRedeemResult>
}
export const WorkspaceMetadata = z.strictObject({ workspace: WorkspaceRefSchema,displayRev: z.number().int().nonnegative(),appliedReservations: z.array(z.string()) })
export const AccountMembership = z.strictObject({ member: z.string(),role: WorkspaceRoleSchema,pendingRole: WorkspaceRoleSchema.nullable(),status: z.enum(["unconfirmed","active","suspended"]),teams: z.array(z.string()) })
export type WorkspaceMetadataClient = {
  metadata(workspace: string): Promise<z.infer<typeof WorkspaceMetadata>>
  membership(workspace: string, account: string): Promise<z.infer<typeof AccountMembership>>
}
export type WorkspaceEnrolClient = import("./workspace-enrolment.ts").EnrolMirrorClient & {
  registerEnrol(workspace: string, input: z.infer<typeof EnrolRegisterInput>): Promise<z.infer<typeof PendingEnrolSchema>>
}
export function directoryWorkspaceClient(env: Env): DirectoryWorkspaceClient & WorkspaceInitialisationClient & WorkspaceOutboxClient & WorkspaceJoinClient & WorkspaceMetadataClient & WorkspaceEnrolClient {
  const system = (workspace: string, op: string, input: unknown) => invokeVault(env,workspace,{ op,input,auth: { kind: "system",reason: "account directory" } })
  return {
    init: async (workspace,input) => AccessInitOutput.parse(await system(workspace,"access.init",AccessInitInput.parse(input))),
    registerEnrol: async (workspace,input) => PendingEnrolSchema.parse(await system(workspace,"access.enrol.register",EnrolRegisterInput.parse(input))),
    reconcile: async (workspace,enrolment) => EnrolReconcileOutputSchema.parse(await system(workspace,"access.enrol.reconcile",{ enrolment })),
    mirrored: async (workspace,enrolment,device) => { z.strictObject({ mirrored: z.literal(true) }).parse(await system(workspace,"access.enrol.mirrored",{ enrolment,device })) },
    expire: async (workspace,enrolment) => z.strictObject({ expired: z.boolean() }).parse(await system(workspace,"access.enrol.expire",{ enrolment })),
    discard: async (workspace,enrolment,device) => { z.strictObject({ discarded: z.boolean() }).parse(await system(workspace,"access.enrol.discard",{ enrolment,device })) },
    metadata: async workspace => WorkspaceMetadata.parse(await system(workspace,"access.workspace_ref",{})),
    membership: async (workspace,account) => AccountMembership.parse(await system(workspace,"access.membership",{ account })),
    lookupInvite: async (workspace,codeHash) => InviteTermsViewSchema.parse(await system(workspace,"access.invites.lookup",{ codeHash })),
    redeemInvite: async (workspace,input) => InviteRedeemOutput.parse(await system(workspace,"access.invites.redeem",InviteRedeemInput.parse(input))),
    install: async (workspace,input) => SecurityOutput.parse(await system(workspace,"access.security.install",SecurityInstallInput.parse(input))),
    commit: async (workspace,input) => SecurityOutput.parse(await system(workspace,"access.security.commit",SecurityCommitInput.parse(input))),
    restriction: async (workspace,input) => { await system(workspace,"access.security.restriction",input) },
    revokeSession: async (workspace,input) => { await system(workspace,"access.session_revoke",input) },
    mirror: async (workspace,event) => { z.strictObject({ mirrored: z.literal(true) }).parse(await system(workspace,"access.account_event",event)) },
    drain: async (workspace,limit) => OutboxDrainOutput.parse(await system(workspace,"access.outbox.drain",OutboxDrainInput.parse({ limit }))),
    ack: async (workspace,ids) => { await system(workspace,"access.outbox.ack",{ ids }) },
  }
}
