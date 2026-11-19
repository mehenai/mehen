// Mandates in direct-area tests (areas/mandates-workspace.ts): terms for a
// machine, a mandate signed as the page signs it (the action planned, then
// signed), and the rows a test reads back.
import { MANDATE_CAP_DEFAULTS, type MandateActionAnswer, type MandateChanged, type MandateTerms, type WorkspaceStepUpAction } from "@mehen/protocol"
import type { VaultContext } from "../src/vault/core.ts"
import { workspaceMandateOps } from "../src/vault/areas/mandates-workspace.ts"
import { memberInvocation, memberPrincipal, seedCredential } from "./credentials-test-support.ts"

export const terms = (overrides: Partial<MandateTerms> = {}): MandateTerms => ({
  device: "dev_owner", items: "all", classes: ["change", "delete", "read", "send"], caps: { ...MANDATE_CAP_DEFAULTS }, ttlDays: 30, schedule: null, note: "Building the release", ...overrides,
})
// A machine's proposal names credentials by slug; by default the one
// askedFor seeds.
export const ASKED_KEY = "asked-key"
export function proposedTerms(overrides: Partial<Omit<MandateTerms, "items">> & { items?: "all" | string[] } = {}): Omit<MandateTerms, "device" | "items"> & { items: "all" | string[] } {
  const { device: _device, ...rest } = terms()
  return { ...rest, items: [ASKED_KEY], ...overrides }
}
// As if the machine's held requests on the credential, in these classes,
// had carried a mandateCover hint at this moment: what a proposal of its own
// may name.
export async function askedFor(ctx: VaultContext, device: string, slug = ASKED_KEY, classes: string[] = ["change", "delete", "send"], at = ctx.now()): Promise<void> {
  if (ctx.sql.exec("SELECT 1 FROM items WHERE slug=?", slug).toArray().length === 0) await seedCredential(ctx, slug)
  const item = ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug=?", slug).toArray()[0]!.id
  for (const cls of classes) ctx.sql.exec("INSERT INTO mandate_asked(device,item_id,cls,at) VALUES (?,?,?,?) ON CONFLICT(device,item_id,cls) DO UPDATE SET at=excluded.at", device, item, cls, at)
}
// The action a passkey signs, or { stepUp: null } for a resume without one.
export async function mandateAction(ctx: VaultContext, role: string, input: Record<string, unknown>): Promise<MandateActionAnswer> {
  return await workspaceMandateOps["mandates.action"]!.handler(ctx, memberPrincipal(ctx, role), input, memberInvocation(ctx, role)) as MandateActionAnswer
}
const passkeyAction = (answer: MandateActionAnswer | undefined): WorkspaceStepUpAction | undefined => (answer === undefined || "stepUp" in answer ? undefined : answer)
export async function signMandate(ctx: VaultContext, role: string, signed: MandateTerms, proposal?: string): Promise<MandateChanged> {
  const input = { terms: signed, ...(proposal ? { proposal } : {}) }
  const action = await mandateAction(ctx, role, { op: "sign", ...input })
  return await workspaceMandateOps["mandates.sign"]!.handler(ctx, memberPrincipal(ctx, role), input, memberInvocation(ctx, role, passkeyAction(action))) as MandateChanged
}
// action: what mandates.action answered, a passkey's over it when it names one.
export async function mandateOp(ctx: VaultContext, op: string, role: string, input: Record<string, unknown>, action?: MandateActionAnswer): Promise<unknown> {
  return await workspaceMandateOps[op]!.handler(ctx, memberPrincipal(ctx, role), input, memberInvocation(ctx, role, passkeyAction(action)))
}
export const mandateState = (ctx: VaultContext, id: string) => ctx.sql.exec<{ state: string; rev: number }>("SELECT state,rev FROM mandates WHERE id=?", id).toArray()[0] ?? null
export const receipts = (ctx: VaultContext) => ctx.sql.exec<{ item_id: string; classes: string; method: string; host: string; entry: string }>("SELECT item_id,classes,method,host,entry FROM mandate_uses ORDER BY at,id").toArray()
export const counts = (ctx: VaultContext) => Object.fromEntries(ctx.sql.exec<{ cls: string; n: number }>("SELECT cls,n FROM mandate_counts").toArray().map((r) => [r.cls, r.n]))
export const rateRows = (ctx: VaultContext) => ctx.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM mandate_rate").toArray()[0]!.n
export const notices = (ctx: VaultContext, kind: string) => ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox").toArray().filter((row) => (JSON.parse(row.payload) as { kind: string }).kind === kind).map((row) => row.account).sort()
// Fills the minute's window to the limit's edge, as if that many covered
// requests had gone through just now.
export function fillRate(ctx: VaultContext, mandate: string, n: number): void {
  for (let i = 0; i < n; i++) ctx.sql.exec("INSERT INTO mandate_rate(mandate_id,at) VALUES (?,?)", mandate, ctx.now())
}
