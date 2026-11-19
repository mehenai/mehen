// Mandates (areas/mandates-workspace.ts): signing through the action a
// passkey signs, what the relay lets through on one and what it records,
// caps and the rate trip, pause, resume and stop, the signer's standing at
// each use, what each reader sees, the sweep and the switch.
import { afterEach, describe, expect, it, vi } from "vitest"
import { MANDATE_CAP_DEFAULTS, MANDATE_PROPOSAL_CAP_DEFAULTS, MANDATE_RATE_LIMIT, base64UrlEncode, createProof, getTemplate, scopeChangeIsNarrowing, type ApprovalSubject, type WorkspaceRole, type WorkspaceStepUpAction, type MandateCandidates, type MandateList, type MandateProposalCreated, type MandateProposalView, type MandateReceiptsPage, type MandateView, type WorkspaceRunCreated } from "@mehen/protocol"
import type { ApprovalBundleCreated } from "@mehen/protocol/api"
import { mandateDigest } from "@mehen/protocol/mandates"
import { mandateScheduleText } from "@mehen/protocol/mandate-terms"
import { policyAreaGrantTermsDigest, policyRuleTermsDigest } from "@mehen/protocol/policy-rules"
import { VaultError } from "../src/http.ts"
import type { VaultContext } from "../src/vault/core.ts"
import { can } from "../src/vault/access.ts"
import { MANDATE_ASKED_MIGRATION, MANDATE_PROPOSALS_ITEMS_MIGRATION, MANDATE_CAPPED_ASKS_MIGRATION, MANDATE_COVER_ASKS_MIGRATION, MANDATE_PROPOSALS_CLOSED_BY_MIGRATION, MANDATE_PROPOSALS_MANDATE_MIGRATION, MANDATES_MIGRATION, mandatesArea, sweepMandates, workspaceMandateOps } from "../src/vault/areas/mandates-workspace.ts"
import { AREAS } from "../src/vault/registry.ts"
import { auditLine } from "../src/ui/wording.ts"
import { projects } from "../src/vault/areas/projects.ts"
import { workspaceApproval, workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { fillWorkspaceItem } from "../src/vault/areas/browser-workspace.ts"
import { stepUpDigest } from "../src/vault/areas/items.ts"
import { prepareCredential, registerCredentialServices, storeCredential, workspaceItemOps } from "../src/vault/areas/items-workspace.ts"
import { workspacePushOps, type PushPrepared } from "../src/vault/areas/pushes.ts"
import { authoriseWorkspaceRelay, workspaceRelayOps } from "../src/vault/areas/relay-workspace.ts"
import { workspaceRunOps } from "../src/vault/areas/runs-workspace.ts"
import { accessState, digest, drainOutbox, installSecurity, setSetting, updateRestriction, type WorkspaceInvocationContext } from "../src/vault/areas/workspace-runtime.ts"
import { accessArea } from "../src/vault/areas/access.ts"
import { workspaceDeviceOps } from "../src/vault/areas/workspace-devices.ts"
import { workspaceMemberOps } from "../src/vault/areas/workspace-members.ts"
import { noticeRows } from "../src/ui/pages/needs-you.ts"
import { accountAuth, installTestIdentity } from "./access-test-support.ts"
import { credentialInput, credentialsFixture, deviceInvocation, devicePrincipal, inAccess, memberInvocation, memberPrincipal, seedCredential } from "./credentials-test-support.ts"
import { OPEN_ISSUE, relayAs, seedGithub, setPosture, type Relayed } from "./postures-test-support.ts"
import { PROJECT_RUN_INPUT, approvedProjectRun, projectFixture } from "./projects-workspace-fixture.ts"
import { askedFor, counts, fillRate, mandateAction, mandateOp, mandateState, notices, proposedTerms, rateRows, receipts, signMandate, terms } from "./mandates-test-support.ts"

const DAY = 86_400_000
const READ_ISSUES = { method: "GET", url: "https://api.github.com/repos/acme/app/issues", headers: [] as [string, string][] }
const PROJECT = { kind: "project", project: "prj_a" } as const
const json = (value: unknown) => base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)) as Uint8Array<ArrayBuffer>)
const itemId = (ctx: VaultContext, slug: string) => ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug=?", slug).toArray()[0]!.id
const rulesOn = (ctx: VaultContext): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, POLICY_RULES: "on" } })
// A Slack bot token on the template's binding and policy, which holds a post.
async function seedSlack(ctx: VaultContext) {
  const template = getTemplate("slack-bot")!
  const prepared = await prepareCredential(ctx, { ...credentialInput("slack-work"), provider: "slack-bot", binding: template.binding, policy: template.policy }, null)
  return ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
}
const POST_MESSAGE = { method: "POST", url: "https://slack.com/api/chat.postMessage", headers: [["content-type", "application/json"]] as [string, string][], body: json({ channel: "C1", text: "The build is green." }) }
// A dev (unprotected) run on dev_owner with two held credentials, TOKEN
// (key-workspace) and OTHER (second-key), each as a placeholder, both bound
// to one host.
async function twoPlaceholderRun(ctx: VaultContext, host = "api.example.com"): Promise<{ run: string; placeholders: string[] }> {
  registerCredentialServices()
  await seedCredential(ctx, "second-key")
  ctx.sql.exec("UPDATE items SET policy=? WHERE slug='second-key'", JSON.stringify({ default: "approve", rules: [] }))
  ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','dev','OTHER','second-key','key','member:mem_owner',?)", ctx.now())
  ctx.sql.exec("UPDATE items SET binding=? WHERE slug IN ('key-workspace','second-key')", JSON.stringify({ hosts: [host] }))
  const run = await workspaceRunOps["runs.create"]!.handler(ctx, devicePrincipal("dev_owner"), { ...PROJECT_RUN_INPUT, env: "dev", vars: ["TOKEN", "OTHER"] }, await deviceInvocation(ctx, "dev_owner")) as WorkspaceRunCreated
  return { run: run.run, placeholders: run.vars.flatMap((v) => v.delivery === "placeholder" ? [v.value] : []) }
}
async function relayRun(ctx: VaultContext, request: Record<string, unknown>, device = "dev_owner"): Promise<Relayed> {
  try { return { material: await authoriseWorkspaceRelay(ctx, devicePrincipal(device), request, await deviceInvocation(ctx, device)), error: null } }
  catch (error) { if (error instanceof VaultError) return { material: null, error }; throw error }
}
const bothPlaceholders = (run: { run: string; placeholders: string[] }) => ({ run: run.run, method: "POST", url: "https://api.example.com/tasks", headers: [["content-type", "application/json"], ["Authorization", `Bearer ${run.placeholders[0]}`], ["Authorization", `Bearer ${run.placeholders[1]}`]], body: json({ title: "one" }) })
const at = (ctx: VaultContext, ms: number): VaultContext => Object.assign(Object.create(ctx) as VaultContext, { now: () => ms })
const audits = (ctx: VaultContext, action: string) => ctx.sql.exec<{ actor: string; target: string; detail: string }>("SELECT actor,target,detail FROM audit WHERE action=?", action).toArray().map((row) => ({ ...row, detail: JSON.parse(row.detail) as Record<string, unknown> }))
async function refusal(run: () => Promise<unknown> | unknown): Promise<{ code: string; message: string; extra?: Record<string, unknown> }> {
  try { await run() } catch (error) { return { code: (error as { code: string }).code, message: (error as Error).message, extra: (error as { extra?: Record<string, unknown> }).extra } }
  throw new Error("Expected a refusal")
}
// A change to a member by the owner, with the passkey it needs.
const memberOp = async (ctx: VaultContext, op: string, input: Record<string, unknown>, action: WorkspaceStepUpAction) => await workspaceMemberOps[op]!.handler(ctx, memberPrincipal(ctx, "owner"), input, memberInvocation(ctx, "owner", action))
const machineOp = async (ctx: VaultContext, op: string, device: string, input: Record<string, unknown> = {}) => await workspaceMandateOps[op]!.handler(ctx, devicePrincipal(device), input, await deviceInvocation(ctx, device))
// A request the final transaction sees changed: run just before it.
function beforeFinal(ctx: VaultContext, change: () => void): void {
  const real = ctx.storage.transactionSync.bind(ctx.storage)
  let done = false
  vi.spyOn(ctx.storage, "transactionSync").mockImplementation(((fn: () => unknown) => {
    if (!done) { done = true; change() }
    return real(fn)
  }) as typeof ctx.storage.transactionSync)
}
afterEach(() => { vi.restoreAllMocks() })

describe("signing a mandate", () => {
  it("signs the terms, the workspace and the signer, replaces the machine's mandate before it, and tells owners and admins", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const signed = terms()
      expect(await mandateAction(ctx, "owner", { op: "sign", terms: signed })).toEqual({ type: "mandate.sign", device: "dev_owner", digest: await mandateDigest({ terms: signed, workspace: ctx.tenant, signer: "mem_owner" }) })
      const first = (await signMandate(ctx, "owner", signed)).mandate
      expect(first).toMatchObject({ device: { id: "dev_owner" }, signer: { name: "owner" }, state: "active", rev: 1, items: "all", hiddenItems: 0, classes: ["change", "delete", "read", "send"], today: { read: 0, change: 0, send: 0, delete: 0 }, endedReason: null })
      expect(Date.parse(first.expiresAt) - Date.parse(first.createdAt)).toBe(30 * DAY)
      expect(notices(ctx, "mandate_signed")).toEqual(["acc_admin", "acc_owner"])
      const second = (await signMandate(ctx, "owner", terms({ ttlDays: 7 }))).mandate
      expect(mandateState(ctx, first.id)).toEqual({ state: "stopped", rev: 2 })
      expect(mandateState(ctx, second.id)).toEqual({ state: "active", rev: 1 })
      expect(audits(ctx, "mandate.sign").map((row) => row.detail.replaced)).toEqual([null, first.id])
    })
  })

  it("is the machine owner's alone, never a guest's or for a team's machine, and only over credentials they manage", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedGithub(ctx)
      expect((await refusal(() => mandateAction(ctx, "owner", { op: "sign", terms: terms({ device: "dev_member" }) }))).code).toBe("forbidden")
      expect((await refusal(() => mandateAction(ctx, "guest", { op: "sign", terms: terms({ device: "dev_guest" }) }))).code).toBe("forbidden")
      expect((await refusal(() => mandateAction(ctx, "owner", { op: "sign", terms: terms({ device: "dev_service" }) }))).code).toBe("forbidden")
      expect(await refusal(() => mandateAction(ctx, "member", { op: "sign", terms: terms({ device: "dev_member", items: [item.id] }) }))).toMatchObject({ code: "bad_request", message: "You do not manage where \"github-work\" lives, so you cannot let a machine use it without asking." })
      expect((await refusal(() => mandateAction(ctx, "owner", { op: "sign", terms: { ...terms(), schedule: { tz: "UTC", windows: [{ days: [1], from: "09:00", to: "09:00" }] } } }))).code).toBe("bad_request")
    })
  })

  it("offers the sign page exactly the credentials signing accepts, for the reader's own machine only", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const seeded = [await seedGithub(ctx), await seedGithub(ctx, "owner-own", { kind: "member", member: "mem_owner" }), await seedGithub(ctx, "member-own", { kind: "member", member: "mem_member" })]
      for (const [role, device] of [["owner", "dev_owner"], ["member", "dev_member"]] as const) {
        const offered = (await mandateOp(ctx, "mandates.candidates", role, { device }) as MandateCandidates).items
        const signable: string[] = []
        for (const item of seeded) if (await mandateAction(ctx, role, { op: "sign", terms: terms({ device, items: [item.id] }) }).then(() => true, () => false)) signable.push(item.id)
        expect(offered.map((c) => c.id).sort(), role).toEqual(signable.sort())
        expect(offered.map((c) => c.slug), role).toEqual([...offered.map((c) => c.slug)].sort())
      }
      expect((await mandateOp(ctx, "mandates.candidates", "owner", { device: "dev_owner" }) as MandateCandidates).items.map((c) => c.slug)).toContain("github-work")
      expect((await mandateOp(ctx, "mandates.candidates", "member", { device: "dev_member" }) as MandateCandidates).items.map((c) => c.slug)).not.toContain("github-work")
      for (const [role, device] of [["owner", "dev_member"], ["owner", "dev_service"], ["guest", "dev_guest"], ["owner", "dev_absent"]] as const) {
        expect(await refusal(() => mandateOp(ctx, "mandates.candidates", role, { device })), `${role} ${device}`).toMatchObject({ code: "not_found", message: "No such machine." })
      }
      const off = Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, MANDATES: "tn_elsewhere0001" } })
      expect((await refusal(() => mandateOp(off, "mandates.candidates", "owner", { device: "dev_owner" }))).code).toBe("not_found")
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      const managedSign = await refusal(() => mandateAction(ctx, "owner", { op: "sign", terms: terms() }))
      expect(managedSign.code).toBe("forbidden")
      expect(await refusal(() => mandateOp(ctx, "mandates.candidates", "owner", { device: "dev_owner" }))).toMatchObject({ code: managedSign.code, message: managedSign.message })
      setSetting(ctx, "managed", null)
      setSetting(ctx, "frozen", true)
      const frozenSign = await refusal(() => mandateAction(ctx, "owner", { op: "sign", terms: terms() }))
      expect(frozenSign.code).toBe("frozen")
      expect(await refusal(() => mandateOp(ctx, "mandates.candidates", "owner", { device: "dev_owner" }))).toMatchObject({ code: frozenSign.code, message: frozenSign.message })
    })
  })

  it("needs a passkey over exactly these terms, and none in a cooling-off", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const other = await mandateAction(ctx, "owner", { op: "sign", terms: terms({ ttlDays: 7 }) })
      expect((await refusal(() => mandateOp(ctx, "mandates.sign", "owner", { terms: terms() }, other))).code).toBe("forbidden")
      expect((await refusal(() => mandateOp(ctx, "mandates.sign", "owner", { terms: terms() }))).code).toBe("forbidden")
      updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + DAY, notice: "ntc_owner" })
      expect((await refusal(() => signMandate(ctx, "owner", terms()))).code).toBe("forbidden")
      expect(ctx.sql.exec("SELECT * FROM mandates").toArray()).toEqual([])
    })
  })

  it("closes the machine's proposal it signs, which only that machine's owner may read", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await askedFor(ctx, "dev_owner", "github-work")
      const proposed = proposedTerms({ items: ["github-work"] })
      const created = await machineOp(ctx, "mandates.propose", "dev_owner", { terms: proposed, reason: "To ship the release without asking each time" }) as MandateProposalCreated
      expect(created.url).toBe(`${ctx.env.VAULT_ORIGIN}/w/work/sign-mandate?proposal=${created.id}`)
      const view = await mandateOp(ctx, "mandates.proposal", "owner", { id: created.id }) as MandateProposalView
      expect(view).toMatchObject({ state: "open", items: [{ slug: "github-work" }], hiddenItems: 0 })
      expect((await refusal(() => mandateOp(ctx, "mandates.proposal", "admin", { id: created.id }))).code).toBe("not_found")
      const item = (view.items as { id: string }[])[0]!.id
      const signed = (await signMandate(ctx, "owner", terms({ items: [item] }), created.id)).mandate
      expect(await mandateOp(ctx, "mandates.proposal", "owner", { id: created.id })).toMatchObject({ state: "signed", mandate: signed.id })
      expect((await refusal(() => signMandate(ctx, "owner", terms(), created.id))).code).toBe("bad_request")
    })
  })

  it("names the proposal a mandate was signed from on every view, to every reader, and null for one signed without", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner")
      const proposed = proposedTerms()
      const created = await machineOp(ctx, "mandates.propose", "dev_owner", { terms: proposed, reason: "Release work" }) as MandateProposalCreated
      const fromProposal = (await signMandate(ctx, "owner", terms(), created.id)).mandate
      const plain = (await signMandate(ctx, "member", terms({ device: "dev_member" }))).mandate
      expect([fromProposal.proposal, plain.proposal]).toEqual([created.id, null])
      for (const [mandate, proposal] of [[fromProposal, created.id], [plain, null]] as const) {
        for (const person of ["owner", "admin"]) expect((await mandateOp(ctx, "mandates.show", person, { id: mandate.id }) as MandateView).proposal, person).toBe(proposal)
      }
      expect((await mandateOp(ctx, "mandates.list", "owner", {}) as MandateList).mandates.map((m) => [m.id, m.proposal]).sort()).toEqual([[fromProposal.id, created.id], [plain.id, null]].sort())
      expect((await machineOp(ctx, "mandates.mine", "dev_owner") as MandateList).mandates.map((m) => m.proposal)).toEqual([created.id])
      expect((await machineOp(ctx, "mandates.mine_one", "dev_member", { id: plain.id }) as MandateView).proposal).toBeNull()
      expect((await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: fromProposal.id, rev: 1 }) as { mandate: MandateView }).mandate.proposal).toBe(created.id)
      expect((await mandateOp(ctx, "mandates.stop", "member", { id: plain.id, rev: 1 }) as { mandate: MandateView }).mandate).toHaveProperty("proposal", null)
    })
  })

  it("lets a machine have three proposals open at once, names them when it asks for a fourth, and never from a workload", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner")
      const proposed = proposedTerms()
      const created: MandateProposalCreated[] = []
      for (let i = 0; i < 3; i++) created.push(await machineOp(at(ctx, ctx.now() + i), "mandates.propose", "dev_owner", { terms: proposed, reason: `Release work ${i}` }) as MandateProposalCreated)
      const refused = await refusal(() => machineOp(ctx, "mandates.propose", "dev_owner", { terms: proposed, reason: "Release work 3" }))
      expect(refused).toMatchObject({ code: "conflict", extra: { next: { url: created[2]!.url } } })
      expect(refused.message).toContain("already has 3 mandates waiting")
      expect(refused.message).toContain("`mehen mandate ls`")
      const workload = { kind: "device" as const, deviceId: "dev_owner", workload: "wkl_ci" }
      expect((await refusal(async () => workspaceMandateOps["mandates.propose"]!.handler(ctx, workload, { terms: proposed, reason: "x" }, await deviceInvocation(ctx, "dev_owner")))).code).toBe("forbidden")
    })
  })

  it("refuses a proposal in a frozen workspace when the machine makes it, not only when someone signs it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { device: _device, ...proposed } = terms()
      setSetting(ctx, "frozen", true)
      expect(await refusal(() => machineOp(ctx, "mandates.propose", "dev_owner", { terms: proposed, reason: "Release work" }))).toMatchObject({ code: "frozen", message: "This workspace is frozen." })
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM mandate_proposals").one().n).toBe(0)
    })
  })

  it("tells a workload and a team's machine what to do instead, with a command to run", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { device: _device, ...proposed } = terms()
      const workload = { kind: "device" as const, deviceId: "dev_owner", workload: "wkl_ci" }
      const fromWorkload = await refusal(async () => workspaceMandateOps["mandates.propose"]!.handler(ctx, workload, { terms: proposed, reason: "x" }, await deviceInvocation(ctx, "dev_owner")))
      expect(fromWorkload).toMatchObject({ code: "forbidden", extra: { next: { command: expect.stringMatching(/^mehen policy propose /) } } })
      expect(fromWorkload.message).toContain("its requests always ask in this version")
      expect(fromWorkload.message).toContain("Run the work as the machine itself")
      ctx.sql.exec("UPDATE devices SET owner_kind='team',owner_id='tm_service' WHERE id='dev_owner'")
      const fromTeam = await refusal(() => machineOp(ctx, "mandates.propose", "dev_owner", { terms: proposed, reason: "x" }))
      expect(fromTeam).toMatchObject({ code: "forbidden", extra: { next: { command: expect.stringMatching(/^mehen policy propose /) } } })
      expect(fromTeam.message).toContain("signed by two people in a later version")
      expect(fromTeam.message).toContain("`mehen policy propose`")
    })
  })

  it("hands back the open proposal with the same terms and reason, creating nothing and counting against no limit", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner")
      await askedFor(ctx, "dev_member")
      const proposed = proposedTerms()
      const first = await machineOp(ctx, "mandates.propose", "dev_owner", { terms: proposed, reason: "Release work" }) as MandateProposalCreated
      expect(first).not.toHaveProperty("existing")
      const reordered = { ...proposed, caps: { delete: proposed.caps.delete, send: proposed.caps.send, change: proposed.caps.change, read: proposed.caps.read } }
      for (let i = 0; i < 12; i++) expect(await machineOp(ctx, "mandates.propose", "dev_owner", { terms: i % 2 ? reordered : proposed, reason: "Release work" })).toEqual({ ...first, existing: true })
      expect(ctx.sql.exec("SELECT id FROM mandate_proposals").toArray()).toEqual([{ id: first.id }])
      expect(audits(ctx, "mandate.propose")).toHaveLength(1)
      const other = await machineOp(ctx, "mandates.propose", "dev_owner", { terms: proposed, reason: "Other work" }) as MandateProposalCreated
      expect(other.id).not.toBe(first.id)
      expect((await machineOp(ctx, "mandates.propose", "dev_member", { terms: proposed, reason: "Release work" }) as MandateProposalCreated).id).not.toBe(first.id)
    })
  })

  it("lists open proposals to their machine and to the person who may sign for it, and to nobody else", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await askedFor(ctx, "dev_owner", "github-work", ["change"])
      await askedFor(ctx, "dev_owner", "key-other", ["change"])
      await askedFor(ctx, "dev_member", "github-work", ["change"])
      const proposed = proposedTerms({ items: ["github-work"], classes: ["change", "read"], caps: { ...MANDATE_PROPOSAL_CAP_DEFAULTS, send: 0, delete: 0 } })
      const older = await machineOp(ctx, "mandates.propose", "dev_owner", { terms: { ...proposed, items: ["github-work", "key-other"] }, reason: "Both" }) as MandateProposalCreated
      const newer = await machineOp(at(ctx, ctx.now() + 1), "mandates.propose", "dev_owner", { terms: proposed, reason: "Release work" }) as MandateProposalCreated
      const members = await machineOp(ctx, "mandates.propose", "dev_member", { terms: proposed, reason: "Theirs" }) as MandateProposalCreated
      const mine = (await machineOp(ctx, "mandates.mine", "dev_owner") as MandateList).proposals
      expect(mine.map((p) => p.id)).toEqual([newer.id, older.id])
      expect(mine[0]).toEqual({ id: newer.id, url: newer.url, expiresAt: newer.expiresAt, createdAt: expect.any(String), device: { id: "dev_owner", name: expect.any(String) }, classes: ["change", "read"], items: ["github-work"], hiddenItems: 0, reason: "Release work" })
      expect(mine[1]).toMatchObject({ items: ["github-work", "key-other"], hiddenItems: 0 })
      expect((await mandateOp(ctx, "mandates.list", "owner", {}) as MandateList).proposals.map((p) => p.id)).toEqual([newer.id, older.id])
      expect((await mandateOp(ctx, "mandates.list", "member", {}) as MandateList).proposals.map((p) => p.id)).toEqual([members.id])
      expect((await mandateOp(ctx, "mandates.list", "admin", {}) as MandateList).proposals).toEqual([])
      expect((await machineOp(ctx, "mandates.mine", "dev_member") as MandateList).proposals.map((p) => p.id)).toEqual([members.id])
      expect((await machineOp(at(ctx, Date.parse(newer.expiresAt)), "mandates.mine", "dev_owner") as MandateList).proposals).toEqual([])
    })
  })

  it("closes a machine's other open proposals when a mandate is signed for it, and their page names that mandate", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner")
      await askedFor(ctx, "dev_member")
      const proposed = proposedTerms()
      const a = await machineOp(ctx, "mandates.propose", "dev_owner", { terms: proposed, reason: "One" }) as MandateProposalCreated
      const b = await machineOp(ctx, "mandates.propose", "dev_owner", { terms: proposed, reason: "Two" }) as MandateProposalCreated
      const theirs = await machineOp(ctx, "mandates.propose", "dev_member", { terms: proposed, reason: "Theirs" }) as MandateProposalCreated
      const signed = (await signMandate(ctx, "owner", terms(), a.id)).mandate
      expect(await mandateOp(ctx, "mandates.proposal", "owner", { id: a.id })).toMatchObject({ state: "signed", mandate: signed.id })
      expect(await mandateOp(ctx, "mandates.proposal", "owner", { id: b.id })).toMatchObject({ state: "expired", mandate: signed.id })
      expect(await mandateOp(ctx, "mandates.proposal", "member", { id: theirs.id })).toMatchObject({ state: "open", mandate: null })
      expect((await machineOp(ctx, "mandates.mine", "dev_owner") as MandateList).proposals).toEqual([])
      const plain = (await signMandate(ctx, "member", terms({ device: "dev_member" }))).mandate
      expect(await mandateOp(ctx, "mandates.proposal", "member", { id: theirs.id })).toMatchObject({ state: "expired", mandate: plain.id })
      expect((await refusal(() => signMandate(ctx, "owner", terms(), b.id))).code).toBe("bad_request")
    })
  })
})

describe("a machine proposes only what it asked for", () => {
  const propose = (ctx: VaultContext, device: string, proposed: Record<string, unknown>) => machineOp(ctx, "mandates.propose", device, { terms: proposed, reason: "Release work" })
  const proposals = (ctx: VaultContext) => ctx.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM mandate_proposals").one().n

  it("counts each held request a mandate could cover, by credential and class, and tells the machine what it may propose", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      expect(await machineOp(ctx, "mandates.mine_asked", "dev_owner")).toEqual({ items: [], classes: [] })
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.extra.mandateCover).toMatchObject({ classes: ["change"], state: "none" })
      expect(await machineOp(ctx, "mandates.mine_asked", "dev_owner")).toEqual({ items: ["github-work"], classes: ["change"] })
      expect(await machineOp(ctx, "mandates.mine_asked", "dev_member")).toEqual({ items: [], classes: [] })
      const created = await propose(ctx, "dev_owner", proposedTerms({ items: ["github-work"], classes: ["change", "read"], caps: { ...MANDATE_PROPOSAL_CAP_DEFAULTS, send: 0, delete: 0 } })) as MandateProposalCreated
      expect(created.id).toMatch(/^mdp_/)
    })
  })

  it("refuses every credential, naming what the machine asked for, and creates nothing", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner")
      const refused = await refusal(() => propose(ctx, "dev_owner", proposedTerms({ items: "all" })))
      expect(refused).toMatchObject({ code: "forbidden", extra: { mandateRefused: "items_all", next: { command: "mehen mandate propose --items asked-key --classes change,delete,read,send --days 30 --caps change=100,delete=5,read=500,send=10 --note <why>" } } })
      expect(refused.message).toBe("A machine cannot propose a mandate for every credential: drop items all and name the credentials it asked for. It asked for asked-key in the last 30 days. A person can choose wider terms on the sign page.")
      expect(proposals(ctx)).toBe(0)
      // With nothing asked for, there is nothing to propose instead.
      const none = await refusal(() => propose(ctx, "dev_member", proposedTerms({ items: "all" })))
      expect(none).toMatchObject({ code: "forbidden", extra: { mandateRefused: "items_all", next: { say: expect.stringContaining("Ask for each request as usual") } } })
      expect(none.extra?.next).not.toHaveProperty("command")
    })
  })

  it("refuses a credential the machine did not ask for, saying which to drop", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await askedFor(ctx, "dev_owner")
      const refused = await refusal(() => propose(ctx, "dev_owner", proposedTerms({ items: ["asked-key", "github-work", "no-such-key"] })))
      expect(refused).toMatchObject({ code: "forbidden", extra: { mandateRefused: "item_unasked" } })
      expect(refused.message).toContain("This machine has not asked for github-work, no-such-key: drop them from the proposal.")
      expect(proposals(ctx)).toBe(0)
    })
  })

  it("refuses a class besides read the machine did not ask for, saying which to drop; read needs no ask", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner", "asked-key", ["change"])
      const refused = await refusal(() => propose(ctx, "dev_owner", proposedTerms()))
      expect(refused).toMatchObject({ code: "forbidden", extra: { mandateRefused: "class_unasked", next: { command: "mehen mandate propose --items asked-key --classes change,read --days 30 --caps change=100,read=500 --note <why>" } } })
      expect(refused.message).toContain("This machine has not asked to delete or send: drop delete and send from the proposal.")
      expect(proposals(ctx)).toBe(0)
      expect(await propose(ctx, "dev_owner", proposedTerms({ classes: ["change", "read"], caps: { ...MANDATE_PROPOSAL_CAP_DEFAULTS, send: 0, delete: 0 } }))).toMatchObject({ id: expect.stringMatching(/^mdp_/) })
      expect(await propose(ctx, "dev_owner", proposedTerms({ classes: ["read"], caps: { read: 10, change: 0, send: 0, delete: 0 } }))).toMatchObject({ id: expect.stringMatching(/^mdp_/) })
    })
  })

  it("forgets an ask after 30 days, and the sweep prunes it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const now = ctx.now()
      await askedFor(ctx, "dev_owner", "asked-key", ["change", "delete", "send"], now - 30 * DAY)
      expect(await refusal(() => propose(ctx, "dev_owner", proposedTerms()))).toMatchObject({ code: "forbidden", extra: { mandateRefused: "item_unasked" } })
      await askedFor(ctx, "dev_owner", "asked-key", ["change", "delete", "send"], now - 30 * DAY + 60_000)
      expect(await propose(ctx, "dev_owner", proposedTerms())).toMatchObject({ id: expect.stringMatching(/^mdp_/) })
      sweepMandates(at(ctx, now + 60_000))
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM mandate_asked").one().n).toBe(0)
    })
  })

  it("never counts another machine's asks, even its owner's own", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_member")
      await askedFor(ctx, "dev_admin")
      expect(await refusal(() => propose(ctx, "dev_owner", proposedTerms()))).toMatchObject({ code: "forbidden", extra: { mandateRefused: "item_unasked" } })
      expect(await propose(ctx, "dev_member", proposedTerms())).toMatchObject({ id: expect.stringMatching(/^mdp_/) })
    })
  })

  it("starts, on upgrade, from the held asks with a hint the vault still keeps, by machine, credential and class", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      for (const [device, request] of [["dev_owner", OPEN_ISSUE], ["dev_owner", READ_ISSUES], ["dev_member", READ_ISSUES]] as const) expect((await relayAs(ctx, device, request)).error?.extra.mandateCover).toBeDefined()
      const recorded = ctx.sql.exec("SELECT device,item_id,cls,at FROM mandate_asked ORDER BY device,cls").toArray()
      expect(recorded.map((r) => [r.device, r.cls])).toEqual([["dev_member", "read"], ["dev_owner", "change"], ["dev_owner", "read"]])
      // A vault from before this table: the asks are kept, the table is not.
      ctx.sql.exec("DROP TABLE mandate_asked")
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM mandate_cover_asks").one().n).toBe(3)
      ctx.sql.exec(MANDATE_ASKED_MIGRATION)
      expect(ctx.sql.exec("SELECT device,item_id,cls,at FROM mandate_asked ORDER BY device,cls").toArray()).toEqual(recorded)
      expect(await machineOp(ctx, "mandates.mine_asked", "dev_owner")).toEqual({ items: ["github-work"], classes: ["change"] })
      expect(await propose(ctx, "dev_owner", proposedTerms({ items: ["github-work"], classes: ["change", "read"], caps: { ...MANDATE_PROPOSAL_CAP_DEFAULTS, send: 0, delete: 0 } }))).toMatchObject({ id: expect.stringMatching(/^mdp_/) })
      // On an empty vault the migration makes the table and copies nothing.
      ctx.sql.exec("DROP TABLE mandate_asked")
      ctx.sql.exec("DELETE FROM mandate_cover_asks")
      ctx.sql.exec(MANDATE_ASKED_MIGRATION)
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM mandate_asked").one().n).toBe(0)
    })
  })

  it("counts what its own mandate let through, so it can propose those terms again with one more kind", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await signMandate(ctx, "owner", terms({ classes: ["change", "read"], caps: { ...MANDATE_CAP_DEFAULTS, send: 0, delete: 0 } }))
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error).toBeNull()
      expect(await machineOp(ctx, "mandates.mine_asked", "dev_owner")).toEqual({ items: ["github-work"], classes: ["change"] })
      // Another machine's mandate uses never count for this one.
      expect(await machineOp(ctx, "mandates.mine_asked", "dev_member")).toEqual({ items: [], classes: [] })
      expect(await propose(ctx, "dev_owner", proposedTerms({ items: ["github-work"], classes: ["change", "read"], caps: { ...MANDATE_PROPOSAL_CAP_DEFAULTS, send: 0, delete: 0 } }))).toMatchObject({ id: expect.stringMatching(/^mdp_/) })
    })
  })

  it("refuses more than 30 days, saying what to lower, and proposes the allowed length in next.command", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner")
      const refused = await refusal(() => propose(ctx, "dev_owner", proposedTerms({ ttlDays: 90 })))
      expect(refused).toMatchObject({ code: "forbidden", extra: { mandateRefused: "term_too_long", next: { command: "mehen mandate propose --items asked-key --classes change,delete,read,send --days 30 --caps change=100,delete=5,read=500,send=10 --note <why>" } } })
      expect(refused.message).toContain("A machine can propose a mandate for at most 30 days: lower 90 days to 30.")
      expect(proposals(ctx)).toBe(0)
      for (const ttlDays of [1, 7, 30] as const) expect(await propose(ctx, "dev_owner", { ...proposedTerms({ ttlDays }), note: `For ${ttlDays} days` })).toMatchObject({ id: expect.stringMatching(/^mdp_/) })
    })
  })

  it("refuses a cap above the proposal defaults, naming each to lower, and proposes the allowed caps in next.command", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner")
      const refused = await refusal(() => propose(ctx, "dev_owner", proposedTerms({ caps: { ...MANDATE_PROPOSAL_CAP_DEFAULTS, send: 11, read: 5000 } })))
      expect(refused).toMatchObject({ code: "forbidden", extra: { mandateRefused: "caps_too_high", next: { command: "mehen mandate propose --items asked-key --classes change,delete,read,send --days 30 --caps change=100,delete=5,read=500,send=10 --note <why>" } } })
      expect(refused.message).toContain("A machine can propose at most 500 reads, 100 changes, 10 sends and 5 deletes a day: lower read from 5000 to 500, send from 11 to 10.")
      expect(proposals(ctx)).toBe(0)
      expect(await propose(ctx, "dev_owner", proposedTerms({ caps: { read: 1, change: 1, send: 1, delete: 1 } }))).toMatchObject({ id: expect.stringMatching(/^mdp_/) })
    })
  })

  it("never tells a machine the slug of a credential it can no longer reach, in what it may propose or in a refusal", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await askedFor(ctx, "dev_owner", "github-work", ["change"])
      await askedFor(ctx, "dev_owner", "asked-key", ["send"])
      expect(await machineOp(ctx, "mandates.mine_asked", "dev_owner")).toEqual({ items: ["asked-key", "github-work"], classes: ["change", "send"] })
      // The machine's scope narrows to tagged credentials: github-work is out of its reach.
      ctx.sql.exec("UPDATE items SET tags=? WHERE slug='asked-key'", JSON.stringify(["reach"]))
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.tags',json(?)) WHERE id='dev_owner'", JSON.stringify(["reach"]))
      expect(await machineOp(ctx, "mandates.mine_asked", "dev_owner")).toEqual({ items: ["asked-key"], classes: ["send"] })
      const refused = await refusal(() => propose(ctx, "dev_owner", proposedTerms({ items: "all" })))
      expect(refused).toMatchObject({ code: "forbidden", extra: { mandateRefused: "items_all" } })
      expect(JSON.stringify(refused)).not.toContain("github-work")
      expect((refused.extra?.next as { command: string }).command).toContain("--items asked-key ")
    })
  })

  it("keeps the proposal's hours in every retry, quoted for a shell, so following it never widens them", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner", "asked-key", ["change"])
      const schedule = { tz: "Europe/Paris", windows: [{ days: [1, 2, 3, 4, 5], from: "08:00", to: "19:00" }, { days: [0, 6], from: "22:00", to: "02:00" }] }
      const words = (command: string) => [...command.matchAll(/'((?:[^']|'\\'')*)'|(\S+)/g)].map((m) => m[1] !== undefined ? m[1].replace(/'\\''/g, "'") : (m[2] as string))
      for (const [refusal_, overrides] of [["class_unasked", {}], ["caps_too_high", { classes: ["change", "read"], caps: { read: 500, change: 2000, send: 0, delete: 0 } }], ["term_too_long", { classes: ["change", "read"], caps: { read: 500, change: 100, send: 0, delete: 0 }, ttlDays: 90 }]] as const) {
        const refused = await refusal(() => propose(ctx, "dev_owner", proposedTerms({ ...overrides, schedule } as never)))
        expect(refused.extra?.mandateRefused, refusal_).toBe(refusal_)
        const argv = words((refused.extra?.next as { command: string }).command)
        expect(argv[argv.indexOf("--schedule") + 1], refusal_).toBe(mandateScheduleText(schedule))
        expect(mandateScheduleText(schedule)).toBe("Europe/Paris mon-fri 08:00-19:00; sat,sun 22:00-02:00")
      }
    })
  })

  it("counts no ask or use dated after now, as after a clock set back, and the sweep removes such asks", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const now = ctx.now(), earlier = at(ctx, now - 3_600_000)
      await askedFor(ctx, "dev_owner", "asked-key", ["send"], now)
      await signMandate(ctx, "owner", terms({ classes: ["change", "read"], caps: { ...MANDATE_CAP_DEFAULTS, send: 0, delete: 0 } }))
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error).toBeNull()
      expect(await machineOp(ctx, "mandates.mine_asked", "dev_owner")).toEqual({ items: ["asked-key", "github-work"], classes: ["change", "send"] })
      // An hour earlier, both the ask and the use lie in the future.
      expect(await machineOp(earlier, "mandates.mine_asked", "dev_owner")).toEqual({ items: [], classes: [] })
      expect(await refusal(() => propose(earlier, "dev_owner", proposedTerms({ classes: ["read", "send"], caps: { read: 500, change: 0, send: 10, delete: 0 } })))).toMatchObject({ extra: { mandateRefused: "item_unasked" } })
      sweepMandates(earlier)
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM mandate_asked").one().n).toBe(0)
    })
  })

  it("names no retry when the credentials it would name are more than a mandate holds, and says to choose at most 200", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      for (let i = 0; i < 201; i++) await askedFor(ctx, "dev_owner", `key-${String(i).padStart(3, "0")}`, ["change"])
      const refused = await refusal(() => propose(ctx, "dev_owner", proposedTerms({ items: "all" })))
      expect(refused).toMatchObject({ code: "forbidden", extra: { mandateRefused: "items_all", next: { say: "A mandate names at most 200 credentials: choose at most 200 of those this machine asked for with --items and propose again." } } })
      expect(refused.extra?.next).not.toHaveProperty("command")
      expect(refused.message).toContain("It asked for 201 credentials in the last 30 days")
    })
  }, 120_000)

  it("stops counting an ask a person rejected, keeps one abandoned or another ask of the same credential and kind", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const ask = async () => { const { error } = await relayAs(ctx, "dev_owner", OPEN_ISSUE); expect(error?.extra.mandateCover).toBeDefined(); return error!.extra.approval as string }
      const deny = async (id: string) => {
        const row = workspaceApproval(ctx, id)!
        const subject = JSON.parse(row.subject) as ApprovalSubject
        await workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, "owner"), { id, decision: "deny" }, memberInvocation(ctx, "owner", { type: "approval.decide", approval: id, digest: row.digest, decision: "deny", constraints: subject.constraints }))
      }
      const asked = () => machineOp(ctx, "mandates.mine_asked", "dev_owner")
      const first = await ask()
      expect(await asked()).toEqual({ items: ["github-work"], classes: ["change"] })
      await deny(first)
      expect(await asked()).toEqual({ items: [], classes: [] })
      // Asked again, and left to lapse unanswered: it counts.
      const second = await ask()
      expect(second).not.toBe(first)
      expect(await machineOp(at(ctx, ctx.now() + 2 * 3_600_000), "mandates.mine_asked", "dev_owner")).toEqual({ items: ["github-work"], classes: ["change"] })
      // Another ask of the same credential and kind keeps it when one is rejected.
      await askedFor(ctx, "dev_owner", "github-work", ["change"])
      await deny(second)
      expect(await asked()).toEqual({ items: ["github-work"], classes: ["change"] })
    })
  })

  it("closes a proposal whose credential is deleted, never signs it for one made later under the same slug, and refuses a slug that now names another credential", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner", "asked-key", ["change"])
      const narrow = proposedTerms({ classes: ["change", "read"], caps: { read: 500, change: 100, send: 0, delete: 0 } })
      const first = await propose(ctx, "dev_owner", narrow) as MandateProposalCreated
      const old = itemId(ctx, "asked-key")
      await workspaceItemOps["items.delete"]!.handler(ctx, memberPrincipal(ctx), { slug: "asked-key" }, memberInvocation(ctx, "owner", { type: "item.delete", item: old }))
      expect(await mandateOp(ctx, "mandates.proposal", "owner", { id: first.id })).toMatchObject({ state: "expired" })
      await seedCredential(ctx, "asked-key")
      expect(itemId(ctx, "asked-key")).not.toBe(old)
      expect((await refusal(() => signMandate(ctx, "owner", terms({ items: [itemId(ctx, "asked-key")] }), first.id))).code).toBe("bad_request")
      // A slug moved to another credential while the proposal is open.
      await askedFor(ctx, "dev_owner", "asked-key", ["change"])
      const second = await propose(at(ctx, ctx.now() + 1), "dev_owner", { ...narrow, note: "Again" }) as MandateProposalCreated
      const proposedId = itemId(ctx, "asked-key")
      ctx.sql.exec("UPDATE items SET slug='asked-key-old' WHERE id=?", proposedId)
      await seedCredential(ctx, "asked-key")
      expect(await mandateOp(ctx, "mandates.proposal", "owner", { id: second.id })).toMatchObject({ items: [], hiddenItems: 1 })
      const moved = await refusal(() => signMandate(ctx, "owner", terms({ items: [itemId(ctx, "asked-key")] }), second.id))
      expect(moved).toMatchObject({ code: "conflict" })
      expect(moved.message).toContain("This proposal named asked-key, which now is another credential than the one proposed.")
    })
  })

  it("names no retry for an explicit list that shares no credential with what was asked for, and says to choose", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await askedFor(ctx, "dev_owner", "asked-key", ["change"])
      const refused = await refusal(() => propose(ctx, "dev_owner", proposedTerms({ items: ["github-work"], classes: ["change", "read"], caps: { read: 500, change: 100, send: 0, delete: 0 } })))
      expect(refused).toMatchObject({ code: "forbidden", extra: { mandateRefused: "item_unasked", next: { say: "None of the credentials this proposal names were asked for: choose from those this machine asked for with --items and propose again." } } })
      expect(refused.extra?.next).not.toHaveProperty("command")
      // An explicit list that shares some keeps only those, never others.
      const partly = await refusal(() => propose(ctx, "dev_owner", proposedTerms({ items: ["asked-key", "github-work"], classes: ["change", "read"], caps: { read: 500, change: 100, send: 0, delete: 0 } })))
      expect((partly.extra?.next as { command: string }).command).toContain("--items asked-key ")
    })
  })

  it("closes every unsigned proposal from before credential ids were kept, binds none, and never resolves one without them by its slugs", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "kept-key")
      const now = ctx.now()
      const narrow = () => ({ ...proposedTerms({ classes: ["change", "read"], caps: { read: 500, change: 100, send: 0, delete: 0 } }) })
      const { mandate } = await signMandate(ctx, "owner", terms({ items: [itemId(ctx, "kept-key")] }))
      // As an earlier vault left them: no item_ids column.
      ctx.sql.exec("ALTER TABLE mandate_proposals DROP COLUMN item_ids")
      ctx.sql.exec("ALTER TABLE mandate_proposals DROP COLUMN closed_reason")
      const legacy = (id: string, items: unknown) => ctx.sql.exec("INSERT INTO mandate_proposals(id,device,terms,reason,created_at,expires_at) VALUES (?,?,?,?,?,?)", id, "dev_owner", JSON.stringify({ ...narrow(), items }), "Old", now + 1, now + 7 * DAY)
      // Even one whose credential exists and is older than it: a clock or a remake could fool any check.
      legacy("mdp_kept000000000001", ["kept-key"])
      legacy("mdp_everything000001", "all")
      legacy("mdp_gone000000000001", ["gone-key"])
      ctx.sql.exec(MANDATE_PROPOSALS_ITEMS_MIGRATION)
      const state = (id: string) => ctx.sql.exec<{ closed_at: number | null; closed_reason: string | null; item_ids: string | null }>("SELECT closed_at,closed_reason,item_ids FROM mandate_proposals WHERE id=?", id).one()
      for (const id of ["mdp_kept000000000001", "mdp_everything000001", "mdp_gone000000000001"]) expect(state(id), id).toMatchObject({ closed_at: expect.any(Number), closed_reason: "unbound", item_ids: null })
      // A closed legacy proposal shows what it named as text, offers none of it, and says the machine can propose again.
      const view = await mandateOp(ctx, "mandates.proposal", "owner", { id: "mdp_kept000000000001" }) as MandateProposalView
      expect(view).toMatchObject({ state: "expired", items: [], unbound: ["kept-key"], closedReason: "unbound" })
      expect((await refusal(() => signMandate(ctx, "owner", terms({ items: [itemId(ctx, "kept-key")] }), "mdp_kept000000000001"))).code).toBe("bad_request")
      // Deleting its credential and making it again changes nothing: it stays closed and cannot be signed.
      await workspaceItemOps["items.delete"]!.handler(ctx, memberPrincipal(ctx), { slug: "kept-key" }, memberInvocation(ctx, "owner", { type: "item.delete", item: itemId(ctx, "kept-key") }))
      await seedCredential(ctx, "kept-key")
      expect((await refusal(() => signMandate(ctx, "owner", terms({ items: [itemId(ctx, "kept-key")] }), "mdp_kept000000000001"))).code).toBe("bad_request")
      // The signed mandate is untouched by the upgrade; the machine can propose again.
      expect(ctx.sql.exec<{ state: string }>("SELECT state FROM mandates WHERE id=?", mandate.id).one().state).toBe("active")
      await askedFor(ctx, "dev_owner", "kept-key", ["change"])
      expect(await propose(ctx, "dev_owner", { ...narrow(), items: ["kept-key"] })).toMatchObject({ id: expect.stringMatching(/^mdp_/) })
    })
  })

  it("lets the person who signs widen a narrow proposal on the sign page, every term, length and caps included, with the passkey as before", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await askedFor(ctx, "dev_owner", "asked-key", ["change"])
      const created = await propose(ctx, "dev_owner", proposedTerms({ classes: ["change", "read"], caps: { ...MANDATE_PROPOSAL_CAP_DEFAULTS, send: 0, delete: 0 } })) as MandateProposalCreated
      // Every credential, every kind, the protocol's own caps and 90 days.
      const wide = terms({ ttlDays: 90, caps: { ...MANDATE_CAP_DEFAULTS } })
      const action = await mandateAction(ctx, "owner", { op: "sign", terms: wide, proposal: created.id })
      expect(action).toMatchObject({ type: "mandate.sign" })
      expect(await refusal(() => mandateOp(ctx, "mandates.sign", "owner", { terms: wide, proposal: created.id }))).toMatchObject({ code: "forbidden", message: "This needs a passkey confirmation of the exact action." })
      const signed = (await signMandate(ctx, "owner", wide, created.id)).mandate
      expect(signed).toMatchObject({ items: "all", classes: ["change", "delete", "read", "send"], caps: { ...MANDATE_CAP_DEFAULTS }, proposal: created.id })
      expect(Date.parse(signed.expiresAt) - Date.parse(signed.createdAt)).toBe(90 * DAY)
    })
  })
})

describe("the relay on a mandate", () => {
  it("lets a covered request through, names the mandate, and records a receipt, a count, a rate row and a mandate.use row", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms())
      const { material, error } = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(error).toBeNull()
      expect(material?.mandate).toBe(mandate.id)
      expect(receipts(ctx)).toEqual([{ item_id: item.id, classes: '["change"]', method: "POST", host: "api.github.com", entry: expect.any(String) }])
      expect([counts(ctx), rateRows(ctx)]).toEqual([{ change: 1 }, 1])
      expect(audits(ctx, "mandate.use").map((row) => row.detail)).toMatchObject([{ mandate: mandate.id, classes: ["change"], method: "POST", host: "api.github.com" }])
      expect(JSON.stringify(audits(ctx, "mandate.use"))).not.toContain("/repos/acme")
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).material?.mandate).toBe(mandate.id)
      expect([counts(ctx), rateRows(ctx)]).toEqual([{ change: 1, read: 1 }, 1])
    })
  })

  it("asks for a class it does not tick, and for any other machine", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await signMandate(ctx, "owner", terms({ classes: ["read"], caps: { read: 10, change: 0, send: 0, delete: 0 } }))
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.code).toBe("approval_required")
      expect((await relayAs(ctx, "dev_admin", READ_ISSUES)).error?.code).toBe("approval_required")
      expect(receipts(ctx)).toEqual([])
    })
  })

  it("tells the machine a mandate could let an ask like this through, and why this one asked", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const cover = async (request: Record<string, unknown>, device = "dev_owner") => {
        const { error } = await relayAs(ctx, device, request)
        expect(error?.code).toBe("approval_required")
        return error?.extra.mandateCover
      }
      const page = (id: string) => `${ctx.env.VAULT_ORIGIN}/w/work/mandates/${id}`
      expect(await cover(READ_ISSUES)).toEqual({ classes: ["read"], state: "none", mandate: null, url: null })
      const { mandate } = await signMandate(ctx, "owner", terms({ classes: ["read"], caps: { read: 10, change: 0, send: 0, delete: 0 } }))
      expect(await cover(OPEN_ISSUE)).toEqual({ classes: ["change"], state: "unticked", mandate: mandate.id, url: page(mandate.id) })
      await mandateOp(ctx, "mandates.pause", "owner", { id: mandate.id, rev: 1 })
      expect(await cover(READ_ISSUES)).toEqual({ classes: ["read"], state: "paused", mandate: mandate.id, url: page(mandate.id) })
      ctx.sql.exec("UPDATE mandates SET state='tripped',paused_by=NULL WHERE id=?", mandate.id)
      expect(await cover(READ_ISSUES)).toMatchObject({ state: "tripped", mandate: mandate.id })
      const elsewhere = (new Date(ctx.now()).getUTCDay() + 3) % 7
      ctx.sql.exec("UPDATE mandates SET state='active',terms=json_set(terms,'$.schedule',json(?)) WHERE id=?", JSON.stringify({ tz: "UTC", windows: [{ days: [elsewhere], from: "00:00", to: "23:59" }] }), mandate.id)
      expect(await cover(READ_ISSUES)).toMatchObject({ state: "outside_schedule", mandate: mandate.id })
      // Its signer no longer stands behind it: never said as such.
      ctx.sql.exec("UPDATE mandates SET terms=json_set(terms,'$.schedule',json('null')),lapsed_at=1 WHERE id=?", mandate.id)
      expect(await cover(READ_ISSUES)).toMatchObject({ state: "not_covering", mandate: mandate.id })
      const { rev } = mandateState(ctx, mandate.id)!
      await mandateOp(ctx, "mandates.stop", "owner", { id: mandate.id, rev })
      expect(await cover(READ_ISSUES)).toEqual({ classes: ["read"], state: "ended", mandate: mandate.id, url: page(mandate.id) })
      // Never to a workload, and never in a managed workspace.
      const workload = { kind: "device" as const, deviceId: "dev_owner", workload: "wkl_task" }
      const fromWorkload = await refusal(async () => authoriseWorkspaceRelay(ctx, workload, { item: "github-work", ...READ_ISSUES }, await deviceInvocation(ctx, "dev_owner")))
      expect(fromWorkload.extra).not.toHaveProperty("mandateCover")
      const off = Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, MANDATES: "off" } })
      expect((await relayAs(off, "dev_owner", READ_ISSUES)).error?.extra).not.toHaveProperty("mandateCover")
    })
  })

  it("offers the ask's machine's owner alone a mandate for asks like it, or the paused one", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const approval = (await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.extra.approval as string
      expect(await mandateOp(ctx, "mandates.cover_ask", "owner", { approval })).toEqual({ device: { id: "dev_owner", name: expect.any(String) }, classes: ["change"], state: "sign", mandate: null })
      for (const person of ["admin", "member"]) expect((await refusal(() => mandateOp(ctx, "mandates.cover_ask", person, { approval }))).code, person).toBe("not_found")
      const { mandate } = await signMandate(ctx, "owner", terms({ classes: ["read"], caps: { read: 10, change: 0, send: 0, delete: 0 } }))
      await mandateOp(ctx, "mandates.pause", "owner", { id: mandate.id, rev: 1 })
      expect(await mandateOp(ctx, "mandates.cover_ask", "owner", { approval })).toMatchObject({ state: "paused", mandate: mandate.id })
      expect((await refusal(() => mandateOp(ctx, "mandates.cover_ask", "owner", { approval: "apr_absent" }))).code).toBe("not_found")
    })
  })

  it("sets a sweep for a burst of cover asks once, with no aggregate read on the relay's path", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const sweeps = () => ctx.sql.exec<{ due_at: number }>("SELECT due_at FROM schedule WHERE area='mandates'").toArray()
      ctx.sql.exec("DELETE FROM schedule WHERE area='mandates'")
      const ask = async (n: number) => {
        const { error } = await relayAs(at(ctx, ctx.now() + n * 60_000), "dev_owner", { ...READ_ISSUES, url: `${READ_ISSUES.url}?page=${n}` })
        expect(error?.extra.mandateCover, String(n)).toMatchObject({ state: "none" })
      }
      await ask(0)
      const first = sweeps()
      expect(first).toHaveLength(1)
      const exec = vi.spyOn(ctx.sql, "exec")
      for (let n = 1; n <= 5; n++) await ask(n)
      expect(sweeps()).toEqual(first)
      expect(exec.mock.calls.map((call) => String(call[0])).filter((query) => query.includes("MIN(") || query.includes("UNION ALL"))).toEqual([])
      expect(ctx.sql.exec("SELECT COUNT(*) AS n FROM mandate_cover_asks").one().n).toBe(6)
    })
  })

  it("offers it only to an owner who may also see the ask, as its page does", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const approval = (await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.extra.approval as string
      expect(await mandateOp(ctx, "mandates.cover_ask", "owner", { approval })).toMatchObject({ state: "sign" })
      // The credential is now another member's own: the owner may still sign
      // for the machine, but no longer see the ask.
      ctx.sql.exec("UPDATE items SET home_kind='member',home_id='mem_admin' WHERE slug='github-work'")
      expect((await workspaceApprovalOps["approvals.view"]!.handler(ctx, memberPrincipal(ctx, "owner"), { id: approval }, memberInvocation(ctx, "owner")) as { view: string }).view).not.toBe("detail")
      expect(await refusal(() => mandateOp(ctx, "mandates.cover_ask", "owner", { approval }))).toMatchObject({ code: "not_found", message: "No such ask." })
    })
  })

  it("puts the same hint on a bundle's ask", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const planned = await workspaceRelayOps["approvals.bundle"]!.handler(ctx, devicePrincipal("dev_owner"), { reason: "Triage", requests: [{ item: "github-work", ...OPEN_ISSUE }] }, await deviceInvocation(ctx, "dev_owner")) as ApprovalBundleCreated
      expect(planned.results).toEqual([expect.objectContaining({ outcome: "ask", mandateCover: { classes: ["change"], state: "none", mandate: null, url: null } })])
    })
  })

  it("tells no machine whose owner could never sign one, and judges an owner without their identity check or cooling-off", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      // A project's credential, which a team's machine and a guest's reach.
      await seedGithub(ctx, "github-project", PROJECT)
      const asked = async (device: string, slug = "github-work") => {
        const { error } = await relayAs(ctx, device, READ_ISSUES, slug)
        expect(error?.code, device).toBe("approval_required")
        return error?.extra
      }
      expect(await asked("dev_service", "github-project")).not.toHaveProperty("mandateCover")
      expect(await asked("dev_guest", "github-project")).not.toHaveProperty("mandateCover")
      const coolingOff = (on: boolean) => updateRestriction(ctx, "acc_owner", 0, on ? { reason: "recovery", until: ctx.now() + DAY, notice: "ntc_owner" } : null)
      const gated = (on: boolean) => setSetting(ctx, "identity_rule", on ? { provider: "google", domains: ["example.com"], roles: ["owner"] } : null)
      for (const [label, set] of [["cooling-off", coolingOff], ["identity gate", gated]] as const) {
        set(true)
        expect((await asked("dev_owner"))?.mandateCover, label).toMatchObject({ state: "none" })
        set(false)
      }
      const { mandate } = await signMandate(ctx, "owner", terms())
      for (const [label, set] of [["cooling-off", coolingOff], ["identity gate", gated]] as const) {
        set(true)
        expect((await asked("dev_owner"))?.mandateCover, label).toMatchObject({ state: "not_covering", mandate: mandate.id })
        set(false)
      }
    })
  })

  it("reads not_covering, whatever else holds, once its signer no longer stands behind it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const other = await seedGithub(ctx, "github-other")
      const cover = async (request: Record<string, unknown> = READ_ISSUES) => (await relayAs(ctx, "dev_owner", request)).error?.extra.mandateCover
      const elsewhere = { tz: "UTC", windows: [{ days: [(new Date(ctx.now()).getUTCDay() + 3) % 7], from: "00:00", to: "23:59" }] }
      const lapsedWith: [string, NonNullable<Parameters<typeof terms>[0]>, string | null, Record<string, unknown>][] = [
        ["paused", {}, "UPDATE mandates SET state='paused',paused_by='signer' WHERE id=?", READ_ISSUES],
        ["tripped", {}, "UPDATE mandates SET state='tripped' WHERE id=?", READ_ISSUES],
        ["an unticked class", { classes: ["read"], caps: { read: 10, change: 0, send: 0, delete: 0 } }, null, OPEN_ISSUE],
        ["an unticked credential", { items: [other.id] }, null, READ_ISSUES],
        ["outside its schedule", { schedule: elsewhere }, null, READ_ISSUES],
      ]
      for (const [label, overrides, change, request] of lapsedWith) {
        const { mandate } = await signMandate(ctx, "owner", terms(overrides))
        if (change) ctx.sql.exec(change, mandate.id)
        ctx.sql.exec("UPDATE mandates SET lapsed_at=1 WHERE id=?", mandate.id)
        expect(await cover(request), label).toMatchObject({ state: "not_covering", mandate: mandate.id })
      }
      // A signer suspended and reinstated, while outside its schedule.
      await seedGithub(ctx, "github-kim", PROJECT)
      const { mandate } = await signMandate(ctx, "kim", terms({ device: "dev_kim", schedule: elsewhere }))
      for (const change of ["suspend", "reinstate"] as const) await memberOp(ctx, `access.members.${change}`, { member: "mem_kim" }, { type: `member.${change}`, member: "mem_kim" })
      expect((await relayAs(ctx, "dev_kim", READ_ISSUES, "github-kim")).error?.extra.mandateCover, "suspended").toMatchObject({ state: "not_covering", mandate: mandate.id })
      // A demoted signer, before and without any lapse written, while paused.
      const demoted = (await signMandate(ctx, "owner", terms())).mandate
      await mandateOp(ctx, "mandates.pause", "owner", { id: demoted.id, rev: 1 })
      ctx.sql.exec("UPDATE members SET role='admin' WHERE id='mem_owner'")
      expect(await cover(), "demoted").toMatchObject({ state: "not_covering", mandate: demoted.id })
    })
  })

  it("asks once a class's cap is reached, saying so, while other classes still pass", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms({ caps: { read: 10, change: 1, send: 1, delete: 1 } }))
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error).toBeNull()
      const { error } = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(error?.code).toBe("approval_required")
      expect(error?.extra).toMatchObject({ mandate: { id: mandate.id, capped: ["change"] } })
      expect(error?.extra).not.toHaveProperty("mandateCover")
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error).toBeNull()
      expect(counts(ctx)).toEqual({ change: 1, read: 1 })
    })
  })

  it("lets one of two requests racing for the last unit through, and the other gets conflict", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms({ caps: { read: 10, change: 1, send: 1, delete: 1 } }))
      beforeFinal(ctx, () => ctx.sql.exec("INSERT INTO mandate_counts(mandate_id,day,cls,n) VALUES (?,?,'change',1)", mandate.id, Math.floor(ctx.now() / DAY)))
      expect(await refusal(() => relayAs(ctx, "dev_owner", OPEN_ISSUE).then((r) => { if (r.error) throw r.error }))).toMatchObject({ code: "conflict", message: "This machine's mandate changed since this request was checked; send it again." })
      expect(receipts(ctx)).toEqual([])
    })
  })

  it("asks for request 121 in a minute and trips, telling the signer, owners and admins", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "member", terms({ device: "dev_member" }))
      await signMandate(ctx, "owner", terms())
      const own = (await signMandate(ctx, "owner", terms())).mandate
      fillRate(ctx, own.id, MANDATE_RATE_LIMIT)
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.code).toBe("approval_required")
      expect(mandateState(ctx, own.id)).toEqual({ state: "tripped", rev: 2 })
      expect(audits(ctx, "mandate.trip").map((row) => row.target)).toEqual([own.id])
      expect(notices(ctx, "mandate_tripped")).toEqual(["acc_admin", "acc_owner"])
      expect(mandateState(ctx, mandate.id)?.state).toBe("active")
      // Reads are never counted toward the rate, but a tripped mandate covers none.
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error?.code).toBe("approval_required")
      expect(rateRows(ctx)).toBe(MANDATE_RATE_LIMIT)
    })
  })

  it("answers conflict and writes nothing when the limit is reached only at the final boundary, and the resend trips and asks", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms())
      fillRate(ctx, mandate.id, MANDATE_RATE_LIMIT - 1)
      beforeFinal(ctx, () => fillRate(ctx, mandate.id, 1))
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.code).toBe("conflict")
      expect([mandateState(ctx, mandate.id), receipts(ctx), counts(ctx), rateRows(ctx), audits(ctx, "mandate.trip")]).toEqual([{ state: "active", rev: 1 }, [], {}, MANDATE_RATE_LIMIT, []])
      vi.restoreAllMocks()
      expect((await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.code).toBe("approval_required")
      expect(mandateState(ctx, mandate.id)).toEqual({ state: "tripped", rev: 2 })
    })
  })

  it("never covers what a standing rule, grant or posture already covers", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await setPosture(ctx, "owner", "github-work", { level: "routine", machines: null })
      await signMandate(ctx, "owner", terms())
      const { material } = await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(material?.postures).toEqual(["routine"])
      expect(material).not.toHaveProperty("mandate")
      expect(receipts(ctx)).toEqual([])
    })
  })

  it("never covers a credential bound by a wildcard sent to another subdomain, a protected credential, a workload, a managed or a frozen workspace", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await signMandate(ctx, "owner", terms())
      ctx.sql.exec("UPDATE items SET binding=? WHERE slug='github-work'", JSON.stringify({ hosts: ["api.github.com", "*.github.com"] }))
      expect((await relayAs(ctx, "dev_owner", { ...READ_ISSUES, url: "https://attacker.github.com/repos/acme/app/issues" })).error?.code).toBe("approval_required")
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error).toBeNull()
      const guarded = vi.spyOn(projects, "isProtectedItem").mockReturnValue(true)
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error?.code).toBe("approval_required")
      guarded.mockRestore()
      ctx.sql.exec("INSERT INTO workloads(id,device,label,jwk,thumbprint,scope,created_at,expires_at,hard_expires_at) VALUES ('wkl_task','dev_owner','task','{}','thumb-task','{}',?,?,?)", ctx.now(), ctx.now() + DAY, ctx.now() + DAY)
      const proof = await createProof({ deviceId: "dev_owner", workloadId: "wkl_task", sign: async () => new Uint8Array(64) }, { method: "POST", url: "https://vault.test/v1/relay" }, { tenant: ctx.tenant })
      const workload: WorkspaceInvocationContext = { workspace: { id: ctx.tenant, slug: "work", name: "Work" }, auth: { kind: "device", proof, method: "POST", url: "https://vault.test/v1/relay", bodyHash: "" } }
      expect(await refusal(() => authoriseWorkspaceRelay(ctx, { kind: "device", deviceId: "dev_owner", workload: "wkl_task" }, { item: "github-work", ...READ_ISSUES }, workload))).toMatchObject({ code: "approval_required" })
      // A frozen workspace refuses every use before the approve hook, so
      // the mandate is never asked; coveringMandate's own frozen check
      // stands behind that.
      setSetting(ctx, "frozen", true)
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error?.code).toBe("frozen")
      setSetting(ctx, "frozen", false)
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error).toMatchObject({ code: "approval_required", message: "This request needs approval." })
      expect(receipts(ctx)).toHaveLength(1)
    })
  })

  it("covers nothing with MANDATES off here", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await signMandate(ctx, "owner", terms())
      const off = Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, MANDATES: "tn_elsewhere0001" } })
      expect((await relayAs(off, "dev_owner", OPEN_ISSUE)).error?.code).toBe("approval_required")
      expect((await refusal(() => mandateOp(off, "mandates.list", "owner", {}))).code).toBe("not_found")
      expect((await refusal(() => machineOp(off, "mandates.mine", "dev_owner"))).code).toBe("not_found")
    })
  })

  it("lets a Slack post through as a send, debiting send, and asks once the send cap is reached", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedSlack(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms({ caps: { read: 10, change: 10, send: 1, delete: 1 } }))
      const first = await relayAs(ctx, "dev_owner", POST_MESSAGE, "slack-work")
      expect(first.error).toBeNull()
      expect(first.material?.mandate).toBe(mandate.id)
      expect(receipts(ctx)).toEqual([{ item_id: item.id, classes: '["change","send"]', method: "POST", host: "slack.com", entry: expect.any(String) }])
      expect(counts(ctx)).toEqual({ change: 1, send: 1 })
      const { error } = await relayAs(ctx, "dev_owner", POST_MESSAGE, "slack-work")
      expect(error?.code).toBe("approval_required")
      expect(error?.extra).toMatchObject({ mandate: { id: mandate.id, capped: ["send"] } })
      expect(counts(ctx)).toEqual({ change: 1, send: 1 })
    })
  })

  it("keeps which cap a new ask hit, for a person who may read the machine, and nothing for an ask with any other reason", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedSlack(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms({ classes: ["change", "read", "send"], caps: { read: 10, change: 10, send: 1, delete: 0 } }))
      expect((await relayAs(ctx, "dev_owner", POST_MESSAGE, "slack-work")).error).toBeNull()
      const capped = (await relayAs(ctx, "dev_owner", POST_MESSAGE, "slack-work")).error?.extra?.approval as string
      expect(capped).toEqual(expect.any(String))
      // Sent again, the same open ask comes back and nothing more is kept.
      expect((await relayAs(ctx, "dev_owner", POST_MESSAGE, "slack-work")).error?.extra?.approval).toBe(capped)
      expect(ctx.sql.exec("SELECT approval FROM mandate_capped_asks").toArray()).toEqual([{ approval: capped }])
      for (const role of ["owner", "admin"]) expect(await mandateOp(ctx, "mandates.capped_ask", role, { approval: capped }), role).toEqual({ mandate: mandate.id, capped: [{ class: "send", cap: 1 }] })
      expect(await refusal(() => mandateOp(ctx, "mandates.capped_ask", "member", { approval: capped }))).toMatchObject({ code: "not_found", message: "No such ask." })
      // A delete is not ticked: it asks, and no cap is why.
      const unticked = (await relayAs(ctx, "dev_owner", { method: "DELETE", url: "https://slack.com/api/files.delete", headers: [] }, "slack-work")).error?.extra?.approval as string
      expect(unticked).toEqual(expect.any(String))
      expect((await refusal(() => mandateOp(ctx, "mandates.capped_ask", "owner", { approval: unticked }))).code).toBe("not_found")
      const off = Object.assign(Object.create(ctx) as VaultContext, { env: { ...ctx.env, MANDATES: "tn_elsewhere0001" } })
      expect((await refusal(() => mandateOp(off, "mandates.capped_ask", "owner", { approval: capped }))).code).toBe("not_found")
      const keptAt = ctx.sql.exec<{ at: number }>("SELECT at FROM mandate_capped_asks").toArray()[0]!.at
      sweepMandates(at(ctx, keptAt + 2 * DAY))
      expect(ctx.sql.exec("SELECT approval FROM mandate_capped_asks").toArray()).toHaveLength(1)
      sweepMandates(at(ctx, keptAt + 2 * DAY + 1))
      expect(ctx.sql.exec("SELECT approval FROM mandate_capped_asks").toArray()).toEqual([])
    })
  })

  it("keeps no capped ask for a planned request that hits a cap", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedSlack(ctx)
      await signMandate(ctx, "owner", terms({ classes: ["change", "read", "send"], caps: { read: 10, change: 10, send: 1, delete: 0 } }))
      expect((await relayAs(ctx, "dev_owner", POST_MESSAGE, "slack-work")).error).toBeNull()
      const planned = await workspaceRelayOps["approvals.bundle"]!.handler(ctx, devicePrincipal("dev_owner"), { reason: "Post the summary", requests: [{ item: "slack-work", ...POST_MESSAGE }] }, await deviceInvocation(ctx, "dev_owner")) as ApprovalBundleCreated
      expect(planned.results.map((r) => r.outcome)).toEqual(["ask"])
      expect(ctx.sql.exec("SELECT approval FROM mandate_capped_asks").toArray()).toEqual([])
    })
  })

  it("debits a run's request once per class, with a receipt for each placeholder it covered", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const run = await twoPlaceholderRun(ctx)
      expect(run.placeholders).toHaveLength(2)
      const { mandate } = await signMandate(ctx, "owner", terms())
      const relayed = await relayRun(ctx, bothPlaceholders(run))
      expect(relayed.error).toBeNull()
      expect(relayed.material?.mandate).toBe(mandate.id)
      expect(receipts(ctx).map((r) => [r.item_id, r.classes]).sort()).toEqual([[itemId(ctx, "key-workspace"), '["change"]'], [itemId(ctx, "second-key"), '["change"]']].sort())
      expect([counts(ctx), rateRows(ctx)]).toEqual([{ change: 1 }, 1])
    })
  })

  it("gives a request with one credential under a posture and one under the mandate one receipt, debiting only the mandate one's classes", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const run = await twoPlaceholderRun(ctx, "api.github.com")
      await setPosture(ctx, "owner", "key-workspace", { level: "routine", machines: null })
      const { mandate } = await signMandate(ctx, "owner", terms({ items: [itemId(ctx, "second-key")] }))
      const relayed = await relayRun(ctx, { ...bothPlaceholders(run), url: OPEN_ISSUE.url, body: OPEN_ISSUE.body })
      expect(relayed.error).toBeNull()
      expect(relayed.material).toMatchObject({ postures: ["routine"], mandate: mandate.id })
      expect(receipts(ctx).map((r) => r.item_id)).toEqual([itemId(ctx, "second-key")])
      expect([counts(ctx), rateRows(ctx)]).toEqual([{ change: 1 }, 1])
      expect(audits(ctx, "posture.use")).toHaveLength(1)
    })
  })

  it("consumes nothing, the reservation included, when a later credential of the request asks", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      const run = await twoPlaceholderRun(ctx)
      await signMandate(ctx, "owner", terms({ items: [itemId(ctx, "key-workspace")] }))
      const { error } = await relayRun(ctx, bothPlaceholders(run))
      expect(error?.code).toBe("approval_required")
      // The relay checks a run's credentials by slug, so key-workspace passed
      // on the mandate before second-key asked.
      expect((JSON.parse(workspaceApproval(ctx, error!.extra.approval as string)!.subject) as ApprovalSubject).item).toBe("second-key")
      expect(error?.extra).not.toHaveProperty("mandate")
      expect([receipts(ctx), counts(ctx), rateRows(ctx), audits(ctx, "mandate.use")]).toEqual([[], {}, 0, []])
    })
  })

  it("records nothing in plan mode, and never trips there", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms())
      const bundle = async () => await workspaceRelayOps["approvals.bundle"]!.handler(ctx, devicePrincipal("dev_owner"), { reason: "Triage", requests: [{ item: "github-work", ...OPEN_ISSUE }] }, await deviceInvocation(ctx, "dev_owner")) as ApprovalBundleCreated
      expect((await bundle()).results.map((r) => r.outcome)).toEqual(["allowed"])
      expect([receipts(ctx), counts(ctx), rateRows(ctx), audits(ctx, "mandate.use")]).toEqual([[], {}, 0, []])
      fillRate(ctx, mandate.id, MANDATE_RATE_LIMIT)
      expect((await bundle()).results.map((r) => r.outcome)).toEqual(["ask"])
      expect([mandateState(ctx, mandate.id), audits(ctx, "mandate.trip"), notices(ctx, "mandate_tripped")]).toEqual([{ state: "active", rev: 1 }, [], []])
      expect([receipts(ctx), counts(ctx), rateRows(ctx)]).toEqual([[], {}, MANDATE_RATE_LIMIT])
    })
  })

  it("never covers a request in a protected run, which its own approval lets through", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerCredentialServices()
      ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES('prj_a','staging','TOKEN','key-workspace','key','member:mem_owner',?)", ctx.now())
      await signMandate(ctx, "owner", terms())
      const run = await approvedProjectRun(ctx, { ...PROJECT_RUN_INPUT, env: "staging" }, "dev_owner", "owner")
      const placeholder = run.result.vars.find((v) => v.delivery === "placeholder")!.value
      const relayed = await relayRun(ctx, { run: run.run, method: "POST", url: "https://api.example.com/tasks", headers: [["content-type", "application/json"], ["Authorization", `Bearer ${placeholder}`]], body: json({ title: "one" }) })
      expect(relayed.error).toBeNull()
      expect(relayed.material).not.toHaveProperty("mandate")
      expect([receipts(ctx), counts(ctx), rateRows(ctx)]).toEqual([[], {}, 0])
    })
  })

  it("never covers what a standing rule or a task grant already covers", async () => {
    for (const remember of ["rule", "area"] as const) {
      const f = await credentialsFixture()
      await inAccess(f.tenant, async (raw) => {
        const ctx = rulesOn(raw)
        await seedGithub(ctx)
        const asked = (await relayAs(ctx, "dev_owner", OPEN_ISSUE)).error?.extra.approval as string
        const view = await workspaceApprovalOps["approvals.view"]!.handler(ctx, memberPrincipal(ctx, "owner"), { id: asked }, memberInvocation(ctx, "owner")) as { view: string; approval: { rememberOptions?: { rule?: { terms: Parameters<typeof policyRuleTermsDigest>[0] | null }; area?: { terms: Parameters<typeof policyAreaGrantTermsDigest>[0] | null } } } }
        const offered = view.approval.rememberOptions
        const input = remember === "rule"
          ? { id: asked, decision: "approve", remember: { kind: "rule", path: offered!.rule!.terms!.path, ttlSeconds: offered!.rule!.terms!.ttlSeconds, termsDigest: await policyRuleTermsDigest(offered!.rule!.terms!) } }
          : { id: asked, decision: "approve", remember: { kind: "area", areas: offered!.area!.terms!.areas, ttlSeconds: offered!.area!.terms!.ttlSeconds, maxUses: offered!.area!.terms!.maxUses, termsDigest: await policyAreaGrantTermsDigest(offered!.area!.terms!) } }
        const action = await workspaceApprovalOps["approvals.action"]!.handler(ctx, memberPrincipal(ctx, "owner"), input, memberInvocation(ctx, "owner"))
        await workspaceApprovalOps["approvals.decide"]!.handler(ctx, memberPrincipal(ctx, "owner"), input, memberInvocation(ctx, "owner", action as never))
        await signMandate(ctx, "owner", terms())
        const { material, error } = await relayAs(ctx, "dev_owner", { ...OPEN_ISSUE, body: json({ title: "Another flaky test", body: "It fails on Wednesdays." }) })
        expect([remember, error]).toEqual([remember, null])
        expect(material).not.toHaveProperty("mandate")
        expect([audits(ctx, "rule.use"), receipts(ctx), counts(ctx)]).toEqual([[expect.anything()], [], {}])
      })
    }
  })
})

describe("the signer at each use", () => {
  it("ends cover for good on a role change, demoted then promoted again, and on a suspension, reinstated or not, until the signer resumes it with a passkey", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { mandate } = await signMandate(ctx, "kim", terms({ device: "dev_kim" }))
      await seedGithub(ctx, "github-work", PROJECT)
      const covered = async () => (await relayAs(ctx, "dev_kim", READ_ISSUES)).error === null
      const resumeWithPasskey = async () => {
        const { rev } = mandateState(ctx, mandate.id)!
        const action = await mandateAction(ctx, "kim", { op: "resume", id: mandate.id, rev })
        expect(action).toMatchObject({ type: "mandate.resume", rev })
        expect((await refusal(() => mandateOp(ctx, "mandates.resume", "kim", { id: mandate.id, rev }))).code).toBe("forbidden")
        expect(await mandateOp(ctx, "mandates.resume", "kim", { id: mandate.id, rev }, action)).toMatchObject({ mandate: { state: "active", rev: rev + 1, signerCurrent: true } })
      }
      const role = (after: WorkspaceRole, before: WorkspaceRole) => memberOp(ctx, "access.members.role", { member: "mem_kim", role: after }, { type: "member.role", member: "mem_kim", before, after })
      expect(await covered()).toBe(true)
      await role("admin", "member")
      await role("member", "admin")
      expect([mandateState(ctx, mandate.id), await covered()]).toEqual([{ state: "active", rev: 3 }, false])
      expect(await mandateOp(ctx, "mandates.show", "kim", { id: mandate.id })).toMatchObject({ state: "active", signerCurrent: false })
      await resumeWithPasskey()
      expect(await covered()).toBe(true)
      for (const change of ["suspend", "reinstate"] as const) await memberOp(ctx, `access.members.${change}`, { member: "mem_kim" }, { type: `member.${change}`, member: "mem_kim" })
      expect([mandateState(ctx, mandate.id), await covered()]).toEqual([{ state: "active", rev: 5 }, false])
      await resumeWithPasskey()
      expect(await covered()).toBe(true)
      expect(ctx.sql.exec("SELECT lapsed_at FROM mandates WHERE id=?", mandate.id).toArray()).toEqual([{ lapsed_at: null }])
    })
  })

  it("tells its signer alone, once per lapse, when a mandate lapses, on an access change or an account recovery", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { mandate } = await signMandate(ctx, "kim", terms({ device: "dev_kim" }))
      const role = (after: WorkspaceRole, before: WorkspaceRole) => memberOp(ctx, "access.members.role", { member: "mem_kim", role: after }, { type: "member.role", member: "mem_kim", before, after })
      expect(notices(ctx, "mandate_lapsed")).toEqual([])
      await role("admin", "member")
      await role("member", "admin")
      expect(notices(ctx, "mandate_lapsed")).toEqual(["acc_kim"])
      const shown = drainOutbox(ctx, 100).events.filter((e) => e.payload.kind === "mandate_lapsed")
      expect(shown.map((e) => [e.url, e.payload])).toEqual([[`${ctx.env.VAULT_ORIGIN}/w/work/mandates/${mandate.id}`, expect.objectContaining({ mandate: mandate.id, device: "dev_kim", signer: { member: "mem_kim", name: expect.any(String) }, classes: mandate.classes, expiresAt: mandate.expiresAt })]])
      const { rev } = mandateState(ctx, mandate.id)!
      await mandateOp(ctx, "mandates.resume", "kim", { id: mandate.id, rev }, await mandateAction(ctx, "kim", { op: "resume", id: mandate.id, rev }))
      await memberOp(ctx, "access.members.suspend", { member: "mem_kim" }, { type: "member.suspend", member: "mem_kim" })
      expect(notices(ctx, "mandate_lapsed")).toEqual(["acc_kim", "acc_kim"])
      // The owner's account recovers: a new epoch here, which a restriction
      // alone, under the same epoch, is not.
      const owners = (await signMandate(ctx, "owner", terms())).mandate
      updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + DAY, notice: "ntc_owner" })
      updateRestriction(ctx, "acc_owner", 0, null)
      expect([ctx.sql.exec("SELECT lapsed_at FROM mandates WHERE id=?", owners.id).toArray(), notices(ctx, "mandate_lapsed")]).toEqual([[{ lapsed_at: null }], ["acc_kim", "acc_kim"]])
      installSecurity(ctx, "acc_owner", 1, null)
      installSecurity(ctx, "acc_owner", 2, null)
      expect([ctx.sql.exec("SELECT lapsed_at FROM mandates WHERE id=?", owners.id).toArray(), notices(ctx, "mandate_lapsed")]).toEqual([[{ lapsed_at: expect.any(Number) }], ["acc_kim", "acc_kim", "acc_owner"]])
      expect(await mandateOp(ctx, "mandates.show", "admin", { id: owners.id })).toMatchObject({ state: "active", signerCurrent: false })
    })
  })

  it("ends cover for good when the machine is revoked or rescoped wider, never when rescoped narrower", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { mandate } = await signMandate(ctx, "kim", terms({ device: "dev_kim" }))
      await seedGithub(ctx, "github-work", PROJECT)
      const covered = async () => (await relayAs(ctx, "dev_kim", READ_ISSUES)).error === null
      const wide = accessState(ctx).devices.find((d) => d.id === "dev_kim")!.scope
      const narrow = { ...wide, serviceRuns: false, maxEnvironment: "unprotected" as const }
      expect(scopeChangeIsNarrowing(wide, narrow) && !scopeChangeIsNarrowing(narrow, wide)).toBe(true)
      expect(await workspaceDeviceOps["devices.rescope"]!.handler(ctx, memberPrincipal(ctx, "kim"), { device: "dev_kim", before: wide, after: narrow }, memberInvocation(ctx, "kim", { type: "device.rescope", device: "dev_kim", thumbprint: "dev_kim", before: wide, after: narrow }))).toMatchObject({ state: "committed" })
      expect([mandateState(ctx, mandate.id), await covered()]).toEqual([{ state: "active", rev: 1 }, true])
      const proposed = await workspaceDeviceOps["devices.rescope"]!.handler(ctx, memberPrincipal(ctx, "kim"), { device: "dev_kim", before: narrow, after: wide }, memberInvocation(ctx, "kim", { type: "device.rescope", device: "dev_kim", thumbprint: "dev_kim", before: narrow, after: wide })) as { id: string }
      expect(await workspaceDeviceOps["devices.rescope_accept"]!.handler(ctx, memberPrincipal(ctx, "kim"), { proposal: proposed.id }, memberInvocation(ctx, "kim", { type: "device.rescope_accept", device: "dev_kim", thumbprint: "dev_kim", account: "acc_kim", before: narrow, after: wide, admission: false }))).toMatchObject({ state: "committed" })
      expect([mandateState(ctx, mandate.id), await covered()]).toEqual([{ state: "active", rev: 2 }, false])
      const action = await mandateAction(ctx, "kim", { op: "resume", id: mandate.id, rev: 2 })
      await mandateOp(ctx, "mandates.resume", "kim", { id: mandate.id, rev: 2 }, action)
      expect(await covered()).toBe(true)
      await workspaceDeviceOps["devices.revoke"]!.handler(ctx, memberPrincipal(ctx, "owner"), { device: "dev_kim" }, memberInvocation(ctx, "owner", { type: "device.revoke", device: "dev_kim" }))
      expect(mandateState(ctx, mandate.id)).toEqual({ state: "active", rev: 4 })
      // Were the machine somehow back, the lapse would still hold.
      ctx.sql.exec("UPDATE devices SET revoked_at=NULL WHERE id='dev_kim'")
      expect(await covered()).toBe(false)
    })
  })

  it("ends cover for good when an identity rule change gates the signer, the rule since dropped, and not for a signer no rule ever gated", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const kims = (await signMandate(ctx, "kim", terms({ device: "dev_kim" }))).mandate
      const owners = (await signMandate(ctx, "owner", terms())).mandate
      const setRule = async (rule: { provider: "google"; domains: string[]; roles: WorkspaceRole[] } | null, revision: number) => {
        const action = { type: "workspace.identity_rule", rule } as WorkspaceStepUpAction
        const operationCheck = { id: "opc_rule", subjectDigest: digest(action), identityRuleRev: revision, gateGeneration: revision, succeededAt: new Date(ctx.now() - 1000).toISOString(), expiresAt: new Date(ctx.now() + 600_000).toISOString() }
        await accessArea.workspaceOps!["access.identity_rule"]!.handler(ctx, memberPrincipal(ctx, "owner"), { rule }, { ...memberInvocation(ctx, "owner", action), auth: { ...accountAuth("owner", action), operationCheck } })
      }
      await setRule({ provider: "google", domains: ["example.com"], roles: ["member"] }, 0)
      await setRule(null, 1)
      expect([mandateState(ctx, kims.id), mandateState(ctx, owners.id)]).toEqual([{ state: "active", rev: 3 }, { state: "active", rev: 1 }])
      expect(notices(ctx, "mandate_lapsed")).toEqual(["acc_kim"])
      expect(await mandateOp(ctx, "mandates.show", "kim", { id: kims.id })).toMatchObject({ signerCurrent: false })
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error).toBeNull()
    })
  })

  it("ends cover on a cooling-off while it runs and on a machine given away, never on the signing session's end", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await signMandate(ctx, "owner", terms())
      const covered = async () => (await relayAs(ctx, "dev_owner", READ_ISSUES)).error === null
      expect(await covered()).toBe(true)
      // Signing out of the browser that signed revokes its session only.
      ctx.sql.exec("UPDATE account_security SET state=json_set(state,'$.revokedSessionIds',json('[\"ses_owner\"]')) WHERE account='acc_owner'")
      expect(await covered()).toBe(true)
      updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + DAY, notice: "ntc_owner" })
      expect(await covered()).toBe(false)
      updateRestriction(ctx, "acc_owner", 0, null)
      expect(await covered()).toBe(true)
      ctx.sql.exec("UPDATE devices SET owner_id='mem_admin' WHERE id='dev_owner'")
      expect(await covered()).toBe(false)
    })
  })

  it("ends cover on any change to the signer's account security: a new epoch, a change pending, the account being deleted", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      await signMandate(ctx, "owner", terms())
      const covered = async () => (await relayAs(ctx, "dev_owner", READ_ISSUES)).error === null
      const set = (path: string, value: string) => ctx.sql.exec(`UPDATE account_security SET state=json_set(state,'${path}',json(?)) WHERE account='acc_owner'`, value)
      expect(await covered()).toBe(true)
      for (const [path, changed, back] of [["$.installedEpoch", "1", "0"], ["$.pending", JSON.stringify({ transitionId: "trn_recovery", reservedEpoch: 1, revokedSessionIds: [], removedFactorIds: [], restriction: null }), "null"], ["$.deleting", "true", "false"]] as const) {
        set(path, changed)
        expect([path, await covered()]).toEqual([path, false])
        set(path, back)
        expect([path, await covered()]).toEqual([path, true])
      }
    })
  })

  it("ends cover when the identity rule or the gate changes after a signer it covers signed, not when the session ends", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      setSetting(ctx, "identity_rule", { provider: "google", domains: ["example.com"], roles: ["owner", "admin", "member"] })
      setSetting(ctx, "identity_rule_rev", 1)
      const generation = ctx.sql.exec<{ gate_generation: number }>("SELECT gate_generation FROM members WHERE id='mem_owner'").toArray()[0]!.gate_generation
      const sessionCheck = { id: "chk_owner", checkSequence: 1, gateGeneration: generation, identityRuleRev: 1, succeededAt: new Date(ctx.now() - 1000).toISOString(), expiresAt: new Date(ctx.now() + 600_000).toISOString() }
      installTestIdentity(ctx, { ...accountAuth("owner"), sessionCheck })
      const invocation = (action?: Parameters<typeof accountAuth>[1]): WorkspaceInvocationContext => ({ auth: { ...accountAuth("owner", action), sessionCheck }, workspace: { id: ctx.tenant, slug: "work", name: "Work" } })
      const signed = terms()
      const action = await workspaceMandateOps["mandates.action"]!.handler(ctx, memberPrincipal(ctx, "owner"), { op: "sign", terms: signed }, invocation()) as Parameters<typeof accountAuth>[1]
      await workspaceMandateOps["mandates.sign"]!.handler(ctx, memberPrincipal(ctx, "owner"), { terms: signed }, invocation(action))
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error).toBeNull()
      // A session ending or another browser does not end it.
      ctx.sql.exec("UPDATE account_security SET state=json_set(state,'$.revokedSessionIds',json('[\"ses_owner\"]')) WHERE account='acc_owner'")
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error).toBeNull()
      ctx.sql.exec("UPDATE members SET gate_generation=gate_generation+1 WHERE id='mem_owner'")
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error?.code).toBe("approval_required")
      ctx.sql.exec("UPDATE members SET gate_generation=gate_generation-1 WHERE id='mem_owner'")
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error).toBeNull()
      setSetting(ctx, "identity_rule_rev", 2)
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error?.code).toBe("approval_required")
    })
  })

  it("stops covering a credential once the signer no longer manages its home, their role unchanged, and covers one added later while they do", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await signMandate(ctx, "kim", terms({ device: "dev_kim" }))
      await seedGithub(ctx, "github-work", PROJECT)
      const answer = async () => (await relayAs(ctx, "dev_kim", READ_ISSUES)).error?.code ?? null
      expect(await answer()).toBeNull()
      // Kim's share on prj_a drops from manage to use: the machine still
      // reaches the credential, but Kim no longer manages where it lives.
      ctx.sql.exec("UPDATE project_shares SET value=json_set(value,'$.level','use') WHERE id='shr_kim'")
      expect(await answer()).toBe("approval_required")
      ctx.sql.exec("UPDATE project_shares SET value=json_set(value,'$.level','manage') WHERE id='shr_kim'")
      expect(await answer()).toBeNull()
      // Rehomed to the workspace, which a member does not manage, while the
      // machine still reaches it.
      ctx.sql.exec("UPDATE items SET home_kind='workspace',home_id=NULL WHERE slug='github-work'")
      expect(await answer()).toBe("approval_required")
      expect(ctx.sql.exec("SELECT role FROM members WHERE id='mem_kim'").toArray()).toEqual([{ role: "member" }])
    })
  })

  it("tells a member who signed when their mandate trips, with the owners and admins", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx, "github-mine", { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const { mandate } = await signMandate(ctx, "member", terms({ device: "dev_member" }))
      expect((await relayAs(ctx, "dev_member", OPEN_ISSUE, "github-mine")).error).toBeNull()
      fillRate(ctx, mandate.id, MANDATE_RATE_LIMIT)
      expect((await relayAs(ctx, "dev_member", OPEN_ISSUE, "github-mine")).error?.code).toBe("approval_required")
      expect(mandateState(ctx, mandate.id)).toEqual({ state: "tripped", rev: 2 })
      expect(notices(ctx, "mandate_tripped")).toEqual(["acc_admin", "acc_member", "acc_owner"])
    })
  })
})

describe("what a mandate never authorises", () => {
  it("never lets a machine reveal, fill or push a credential it covers", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "openai-prod")
      const openai = itemId(ctx, "openai-prod")
      const pushable = ctx.sql.exec<{ version: number; config_rev: number }>("SELECT version,config_rev FROM items WHERE id=?", openai).toArray()[0]!
      const change = { pushable: true }
      await workspaceItemOps["items.update"]!.handler(ctx, memberPrincipal(ctx), { slug: "openai-prod", change }, memberInvocation(ctx, "owner", { type: "item.update", item: openai, digest: await stepUpDigest({ change, version: pushable.version, configRevision: pushable.config_rev }) }))
      const via = await prepareCredential(ctx, { ...credentialInput("gh-token"), provider: "github-pat", account: "acme-bot", ceiling: "placeholder", binding: { hosts: ["api.github.com"] }, policy: getTemplate("github-pat")!.policy, secretFields: { key: "ghp_test-via-never-returned" } }, null)
      ctx.storage.transactionSync(() => storeCredential(ctx, via, memberPrincipal(ctx), "item.create"))
      const login = await prepareCredential(ctx, { ...credentialInput("github-login"), kind: "password-login", ceiling: "fill", binding: { hosts: ["github.com"] }, injection: null, publicFields: { url: "https://github.com/login", username: "alex@example.com" }, secretFields: { password: "synthetic-fill-password" } }, null)
      ctx.storage.transactionSync(() => storeCredential(ctx, login, memberPrincipal(ctx), "item.create"))
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.modes',json('[\"relay\",\"sign\",\"mint\",\"placeholder\",\"lease\",\"fill\"]')) WHERE id='dev_owner'")
      await signMandate(ctx, "owner", terms())
      const machine = devicePrincipal("dev_owner")
      expect(can(accessState(ctx), machine, { type: "credential.reveal" }, { credential: openai }, ctx.now()).allowed).toBe(false)
      const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]) as CryptoKeyPair
      const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey) as JsonWebKey
      const fill = await refusal(async () => fillWorkspaceItem(ctx, machine, { item: "github-login", field: "password", origin: "https://github.com", page: "/login", recipient: { kty: "EC", crv: "P-256", x: String(jwk.x), y: String(jwk.y) } }, await deviceInvocation(ctx, "dev_owner")))
      expect(fill.code).toBe("approval_required")
      const prepared = await workspacePushOps["push.prepare"]!.handler(ctx, machine, { item: "openai-prod", to: { provider: "github", owner: "acme", repo: "api", store: "actions", environment: null, name: "OPENAI_API_KEY" } }, await deviceInvocation(ctx, "dev_owner")) as PushPrepared
      const system = { auth: { kind: "system" as const, reason: "push" }, workspace: { id: ctx.tenant, slug: "work", name: "Work" } }
      const push = await refusal(() => workspacePushOps["push.ask"]!.handler(ctx, { kind: "system" }, { ticket: prepared.ticket, preview: null }, system))
      expect(push.code).toBe("approval_required")
      expect([receipts(ctx), counts(ctx), audits(ctx, "mandate.use")]).toEqual([[], {}, []])
    })
  })

  it("never turns a held credential into a lease", async () => {
    const f = await projectFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerCredentialServices()
      ctx.sql.exec("UPDATE items SET ceiling='lease' WHERE slug='key-workspace'")
      await signMandate(ctx, "owner", terms())
      const run = await workspaceRunOps["runs.create"]!.handler(ctx, devicePrincipal("dev_owner"), { ...PROJECT_RUN_INPUT, env: "dev" }, await deviceInvocation(ctx, "dev_owner")) as WorkspaceRunCreated
      expect(run.vars.map((v) => v.delivery)).toEqual(["placeholder"])
      expect((await refusal(async () => workspaceRunOps["runs.lease"]!.handler(ctx, devicePrincipal("dev_owner"), { run: run.run, item: "key-workspace" }, await deviceInvocation(ctx, "dev_owner"))))).toMatchObject({ code: "not_found", message: "No such credential in this run." })
      expect([receipts(ctx), counts(ctx)]).toEqual([[], {}])
    })
  })
})

describe("pausing, resuming and stopping", () => {
  it("stops the next request when the machine, an admin or the signer pauses it; a pause of a paused or tripped one changes nothing, whatever revision it names, bar an admin's over another's", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      for (const pauser of ["machine", "admin", "owner"] as const) {
        const { mandate } = await signMandate(ctx, "owner", terms())
        const paused = pauser === "machine" ? await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: mandate.id, rev: 1 }) : await mandateOp(ctx, "mandates.pause", pauser, { id: mandate.id, rev: 1 })
        expect((paused as { mandate: MandateView }).mandate).toMatchObject({ state: "paused", rev: 2 })
        expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error?.code).toBe("approval_required")
        expect(await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: mandate.id, rev: 2 })).toMatchObject({ mandate: { state: "paused", rev: 2 } })
        expect(await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: mandate.id, rev: 1 })).toMatchObject({ mandate: { state: "paused", rev: 2 } })
        for (const person of pauser === "admin" ? ["admin", "owner"] : ["owner"]) expect(await mandateOp(ctx, "mandates.pause", person, { id: mandate.id, rev: 1 })).toMatchObject({ mandate: { state: "paused", rev: 2 } })
      }
      const tripped = (await signMandate(ctx, "owner", terms())).mandate
      fillRate(ctx, tripped.id, MANDATE_RATE_LIMIT)
      await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(mandateState(ctx, tripped.id)).toEqual({ state: "tripped", rev: 2 })
      expect(await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: tripped.id, rev: 1 })).toMatchObject({ mandate: { state: "tripped", rev: 2 } })
      for (const person of ["admin", "owner"]) expect(await mandateOp(ctx, "mandates.pause", person, { id: tripped.id, rev: 1 })).toMatchObject({ mandate: { state: "tripped", rev: 2 } })
      expect(audits(ctx, "mandate.pause")).toHaveLength(3)
      const owners = (await signMandate(ctx, "owner", terms())).mandate
      expect((await refusal(() => mandateOp(ctx, "mandates.pause", "member", { id: owners.id, rev: 1 }))).code).toBe("not_found")
      expect((await refusal(() => machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: owners.id, rev: 2 }))).code).toBe("conflict")
      await mandateOp(ctx, "mandates.stop", "owner", { id: owners.id, rev: 1 })
      for (const rev of [1, 2]) {
        expect((await refusal(() => machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: owners.id, rev }))).code).toBe("conflict")
        for (const person of ["admin", "owner"]) expect((await refusal(() => mandateOp(ctx, "mandates.pause", person, { id: owners.id, rev }))).code).toBe("conflict")
      }
    })
  })

  it("lets the signer resume without a passkey what they or the machine paused, while they still stand behind it, and asks one after a trip or once their standing lapsed", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      for (const pauser of ["owner", "machine"] as const) {
        const { mandate } = await signMandate(ctx, "owner", terms())
        if (pauser === "machine") await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: mandate.id, rev: 1 })
        else await mandateOp(ctx, "mandates.pause", "owner", { id: mandate.id, rev: 1 })
        const basis = ctx.sql.exec<{ basis: string }>("SELECT basis FROM mandates WHERE id=?", mandate.id).toArray()[0]!.basis
        expect(await mandateAction(ctx, "owner", { op: "resume", id: mandate.id, rev: 2 })).toEqual({ stepUp: null })
        expect((await refusal(() => mandateAction(ctx, "admin", { op: "resume", id: mandate.id, rev: 2 }))).code).toBe("forbidden")
        expect((await refusal(() => mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 1 }))).code).toBe("conflict")
        setSetting(ctx, "frozen", true)
        expect((await refusal(() => mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 2 }))).code).toBe("frozen")
        setSetting(ctx, "frozen", false)
        updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + DAY, notice: "ntc_owner" })
        expect((await refusal(() => mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 2 }))).code).toBe("forbidden")
        updateRestriction(ctx, "acc_owner", 0, null)
        expect(await mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 2 })).toMatchObject({ mandate: { state: "active", rev: 3, signerCurrent: true } })
        expect(ctx.sql.exec<{ basis: string; paused_by: string | null }>("SELECT basis,paused_by FROM mandates WHERE id=?", mandate.id).toArray()[0]).toEqual({ basis, paused_by: null })
        expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error).toBeNull()
      }
      expect(audits(ctx, "mandate.resume").map((row) => row.detail)).toMatchObject([{ from: "paused", stepUp: false }, { from: "paused", stepUp: false }])

      // Paused by the signer, then their role changed: a passkey again.
      const lapsed = (await signMandate(ctx, "owner", terms())).mandate
      await mandateOp(ctx, "mandates.pause", "owner", { id: lapsed.id, rev: 1 })
      ctx.sql.exec("UPDATE members SET role='admin' WHERE id='mem_owner'")
      expect(await mandateAction(ctx, "owner", { op: "resume", id: lapsed.id, rev: 2 })).toMatchObject({ type: "mandate.resume", rev: 2, from: "lapsed" })
      expect((await refusal(() => mandateOp(ctx, "mandates.resume", "owner", { id: lapsed.id, rev: 2 }))).code).toBe("forbidden")
      ctx.sql.exec("UPDATE members SET role='owner' WHERE id='mem_owner'")

      // Tripped: a passkey, whoever paused it before.
      const tripped = (await signMandate(ctx, "owner", terms())).mandate
      fillRate(ctx, tripped.id, MANDATE_RATE_LIMIT)
      await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      expect(mandateState(ctx, tripped.id)).toEqual({ state: "tripped", rev: 2 })
      const action = await mandateAction(ctx, "owner", { op: "resume", id: tripped.id, rev: 2 })
      expect(action).toMatchObject({ type: "mandate.resume", rev: 2, from: "tripped" })
      expect((await refusal(() => mandateOp(ctx, "mandates.resume", "owner", { id: tripped.id, rev: 2 }))).code).toBe("forbidden")
      expect(await mandateOp(ctx, "mandates.resume", "owner", { id: tripped.id, rev: 2 }, action)).toMatchObject({ mandate: { state: "active", rev: 3 } })
      expect(audits(ctx, "mandate.resume").map((row) => row.detail).at(-1)).toMatchObject({ from: "tripped", stepUp: true })
    })
  })

  it("takes an admin's pause over the signer's or the machine's, so resuming it needs the signer's passkey", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      for (const pauser of ["owner", "machine"] as const) {
        const { mandate } = await signMandate(ctx, "owner", terms())
        if (pauser === "machine") await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: mandate.id, rev: 1 })
        else await mandateOp(ctx, "mandates.pause", "owner", { id: mandate.id, rev: 1 })
        const pauses = audits(ctx, "mandate.pause").length
        expect(await mandateOp(ctx, "mandates.pause", "admin", { id: mandate.id, rev: 2 })).toMatchObject({ mandate: { state: "paused", rev: 3 } })
        expect(ctx.sql.exec<{ paused_by: string }>("SELECT paused_by FROM mandates WHERE id=?", mandate.id).toArray()[0]).toEqual({ paused_by: "admin" })
        expect(audits(ctx, "mandate.pause").slice(pauses)).toEqual([{ actor: "member:mem_admin", target: mandate.id, detail: { device: "dev_owner" } }])
        const action = await mandateAction(ctx, "owner", { op: "resume", id: mandate.id, rev: 3 })
        expect(action).toEqual({ type: "mandate.resume", mandate: mandate.id, digest: expect.any(String), rev: 3, from: "paused" })
        expect((await refusal(() => mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 3 }))).code).toBe("forbidden")
        // A second pause by anyone now changes nothing.
        for (const person of ["admin", "owner"]) expect(await mandateOp(ctx, "mandates.pause", person, { id: mandate.id, rev: 1 })).toMatchObject({ mandate: { state: "paused", rev: 3 } })
        expect(await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: mandate.id, rev: 3 })).toMatchObject({ mandate: { state: "paused", rev: 3 } })
        expect(await mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 3 }, action)).toMatchObject({ mandate: { state: "active", rev: 4 } })
      }
    })
  })

  it("lets a workload on the machine pull the brake, as the machine's own pause, and nothing else", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms())
      const workload = { kind: "device" as const, deviceId: "dev_owner", workload: "wkl_ci" }
      const invocation = await deviceInvocation(ctx, "dev_owner")
      const asWorkload = async (op: string, input: Record<string, unknown>) => await workspaceMandateOps[op]!.handler(ctx, workload, input, invocation)
      expect(await asWorkload("mandates.mine_pause", { id: mandate.id, rev: 1 })).toMatchObject({ mandate: { state: "paused", rev: 2 } })
      expect(ctx.sql.exec<{ paused_by: string }>("SELECT paused_by FROM mandates WHERE id=?", mandate.id).toArray()[0]).toEqual({ paused_by: "machine" })
      expect(audits(ctx, "mandate.pause")).toEqual([{ actor: "device:dev_owner", target: mandate.id, detail: { device: "dev_owner", workload: "wkl_ci" } }])
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error?.code).toBe("approval_required")
      expect(await mandateAction(ctx, "owner", { op: "resume", id: mandate.id, rev: 2 })).toEqual({ stepUp: null })
      const members = (await signMandate(ctx, "member", terms({ device: "dev_member" }))).mandate
      expect((await refusal(() => asWorkload("mandates.mine_pause", { id: members.id, rev: 1 }))).code).toBe("not_found")
      for (const op of ["mandates.mine", "mandates.mine_one", "mandates.mine_uses"]) expect((await refusal(() => asWorkload(op, { id: mandate.id }))).code, op).toBe("forbidden")
    })
  })

  it("never lets a machine resume its mandate, however it was paused", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms())
      await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: mandate.id, rev: 1 })
      expect(workspaceMandateOps["mandates.resume"]!.auth).toEqual(["account"])
      expect(workspaceMandateOps["mandates.action"]!.auth).toEqual(["account"])
      expect(Object.keys(workspaceMandateOps).filter((op) => op.includes("resume"))).toEqual(["mandates.resume"])
      // Called as the machine even so, the mandate is not one it may act on.
      expect((await refusal(async () => workspaceMandateOps["mandates.resume"]!.handler(ctx, devicePrincipal("dev_owner"), { id: mandate.id, rev: 2 }, await deviceInvocation(ctx, "dev_owner")))).code).toBe("not_found")
      expect(mandateState(ctx, mandate.id)).toEqual({ state: "paused", rev: 2 })
    })
  })

  it("resumes only with the signer's passkey over the revision paused, never once stopped", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms())
      await mandateOp(ctx, "mandates.pause", "admin", { id: mandate.id, rev: 1 })
      expect((await refusal(() => mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 2 }))).code).toBe("forbidden")
      expect((await refusal(() => mandateAction(ctx, "admin", { op: "resume", id: mandate.id, rev: 2 }))).code).toBe("forbidden")
      const action = await mandateAction(ctx, "owner", { op: "resume", id: mandate.id, rev: 2 })
      expect(action).toEqual({ type: "mandate.resume", mandate: mandate.id, digest: expect.any(String), rev: 2, from: "paused" })
      updateRestriction(ctx, "acc_owner", 0, { reason: "recovery", until: ctx.now() + DAY, notice: "ntc_owner" })
      expect((await refusal(() => mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 2 }, action))).code).toBe("forbidden")
      updateRestriction(ctx, "acc_owner", 0, null)
      expect(await mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 2 }, action)).toMatchObject({ mandate: { state: "active", rev: 3 } })
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error).toBeNull()
      expect(await mandateOp(ctx, "mandates.stop", "admin", { id: mandate.id, rev: 3 })).toMatchObject({ mandate: { state: "stopped", rev: 4, endedReason: "stopped" } })
      expect((await refusal(() => mandateAction(ctx, "owner", { op: "resume", id: mandate.id, rev: 4 }))).code).toBe("conflict")
      expect((await refusal(() => machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: mandate.id, rev: 4 }))).code).toBe("conflict")
    })
  })
})

describe("a signer who no longer stands behind their mandate", () => {
  it("shows it active with signerCurrent false, covering nothing, until the signer resumes it with a passkey, which records them as they are now", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms())
      expect(mandate).toMatchObject({ state: "active", signerCurrent: true })
      expect((await refusal(() => mandateAction(ctx, "owner", { op: "resume", id: mandate.id, rev: 1 }))).code).toBe("conflict")
      ctx.sql.exec("UPDATE members SET role='admin' WHERE id='mem_owner'")
      expect(await mandateOp(ctx, "mandates.show", "owner", { id: mandate.id })).toMatchObject({ state: "active", rev: 1, signerCurrent: false })
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error?.code).toBe("approval_required")
      expect((await refusal(() => mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 1 }))).code).toBe("forbidden")
      const action = await mandateAction(ctx, "owner", { op: "resume", id: mandate.id, rev: 1 })
      expect(action).toMatchObject({ type: "mandate.resume", from: "lapsed" })
      expect(await mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 1 }, action)).toMatchObject({ mandate: { state: "active", rev: 2, signerCurrent: true } })
      expect(JSON.parse(ctx.sql.exec<{ basis: string }>("SELECT basis FROM mandates WHERE id=?", mandate.id).toArray()[0]!.basis)).toMatchObject({ role: "admin" })
      expect((await relayAs(ctx, "dev_owner", READ_ISSUES)).error).toBeNull()
      expect(audits(ctx, "mandate.resume").map((row) => row.detail)).toMatchObject([{ from: "lapsed" }])
    })
  })
})

describe("what each reader sees", () => {
  it("says whether the signer still stands behind a live mandate to people only, never to the machine, and never once it has ended", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { mandate } = await signMandate(ctx, "owner", terms())
      expect(mandate.signerCurrent).toBe(true)
      for (const person of ["owner", "admin"]) expect((await mandateOp(ctx, "mandates.show", person, { id: mandate.id }) as MandateView).signerCurrent).toBe(true)
      expect(await machineOp(ctx, "mandates.mine_one", "dev_owner", { id: mandate.id })).not.toHaveProperty("signerCurrent")
      expect((await machineOp(ctx, "mandates.mine", "dev_owner") as MandateList).mandates[0]).not.toHaveProperty("signerCurrent")
      expect((await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: mandate.id, rev: 1 }) as { mandate: MandateView }).mandate).not.toHaveProperty("signerCurrent")
      expect((await mandateOp(ctx, "mandates.stop", "owner", { id: mandate.id, rev: 2 }) as { mandate: MandateView }).mandate).not.toHaveProperty("signerCurrent")
      expect((await mandateOp(ctx, "mandates.list", "owner", {}) as MandateList).mandates[0]).not.toHaveProperty("signerCurrent")
      const expiring = (await signMandate(ctx, "owner", terms({ ttlDays: 1 }))).mandate
      expect(await mandateOp(at(ctx, ctx.now() + 2 * DAY), "mandates.show", "owner", { id: expiring.id })).toMatchObject({ state: "expired" })
      expect(await mandateOp(at(ctx, ctx.now() + 2 * DAY), "mandates.show", "owner", { id: expiring.id })).not.toHaveProperty("signerCurrent")
    })
  })

  it("tells a person whether they signed it, and the machine nothing about it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { mandate } = await signMandate(ctx, "owner", terms())
      expect(mandate.signer).toEqual({ name: expect.any(String), self: true })
      expect((await mandateOp(ctx, "mandates.show", "admin", { id: mandate.id }) as MandateView).signer.self).toBe(false)
      expect((await mandateOp(ctx, "mandates.list", "admin", {}) as MandateList).mandates[0]?.signer.self).toBe(false)
      expect((await mandateOp(ctx, "mandates.pause", "admin", { id: mandate.id, rev: 1 }) as { mandate: MandateView }).mandate.signer.self).toBe(false)
      expect((await machineOp(ctx, "mandates.mine_one", "dev_owner", { id: mandate.id }) as MandateView).signer).not.toHaveProperty("self")
      expect((await machineOp(ctx, "mandates.mine", "dev_owner") as MandateList).mandates[0]?.signer).not.toHaveProperty("self")
      expect((await machineOp(ctx, "mandates.mine_pause", "dev_owner", { id: mandate.id, rev: 2 }) as { mandate: MandateView }).mandate.signer).not.toHaveProperty("self")
    })
  })

  it("shows an admin a member's private credential only as one they cannot see, and the machine and the signer its slug", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedGithub(ctx, "github-mine", { kind: "member", member: "mem_member" })
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.privateCredentials',json('true')) WHERE id='dev_member'")
      const { mandate } = await signMandate(ctx, "member", terms({ device: "dev_member", items: [item.id] }))
      expect((await relayAs(ctx, "dev_member", READ_ISSUES, "github-mine")).error).toBeNull()
      expect(audits(ctx, "mandate.use")).toEqual([])
      const admin = await mandateOp(ctx, "mandates.uses", "admin", { id: mandate.id }) as MandateReceiptsPage
      expect(admin.receipts).toEqual([{ id: expect.any(String), at: expect.any(String), classes: ["read"], method: "GET", credential: null }])
      expect(await mandateOp(ctx, "mandates.show", "admin", { id: mandate.id })).toMatchObject({ items: [], hiddenItems: 1 })
      expect((await mandateOp(ctx, "mandates.uses", "member", { id: mandate.id }) as MandateReceiptsPage).receipts[0]?.credential).toMatchObject({ slug: "github-mine", host: "api.github.com" })
      expect((await machineOp(ctx, "mandates.mine_uses", "dev_member", { id: mandate.id }) as MandateReceiptsPage).receipts[0]?.credential).toMatchObject({ slug: "github-mine" })
      expect((await mandateOp(ctx, "mandates.list", "kim", {}) as MandateList).mandates).toEqual([])
      expect((await refusal(() => machineOp(ctx, "mandates.mine_one", "dev_owner", { id: mandate.id }))).code).toBe("not_found")
    })
  })

  it("stops showing a member the slugs and hosts of a project's credentials once they lose access to it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const item = await seedGithub(ctx, "github-work", PROJECT)
      const { mandate } = await signMandate(ctx, "kim", terms({ device: "dev_kim", items: [item.id] }))
      expect((await relayAs(ctx, "dev_kim", READ_ISSUES)).error).toBeNull()
      const seen = async () => [await mandateOp(ctx, "mandates.show", "kim", { id: mandate.id }) as MandateView, (await mandateOp(ctx, "mandates.uses", "kim", { id: mandate.id }) as MandateReceiptsPage).receipts] as const
      const [before, beforeUses] = await seen()
      expect([before.items, before.hiddenItems, beforeUses[0]?.credential]).toEqual([["github-work"], 0, { slug: "github-work", host: "api.github.com", entry: expect.any(String), run: null }])
      ctx.sql.exec("DELETE FROM project_shares WHERE id='shr_kim'")
      const [after, afterUses] = await seen()
      expect([after.items, after.hiddenItems, afterUses[0]?.credential]).toEqual([[], 1, null])
      expect(JSON.stringify([after, afterUses])).not.toMatch(/github-work|api\.github\.com/)
    })
  })

  it("lists, newest first, the mandates on every machine a reader may read, however many machines that is", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      for (let i = 0; i < 150; i++) ctx.sql.exec("INSERT INTO devices(id,name,backend,jwk,thumbprint,scope,created_at,owner_kind,owner_id) VALUES (?,?,'software','{}',?,?,?,'member','mem_member')", `dev_extra${i}`, `dev_extra${i}`, `dev_extra${i}`, JSON.stringify({ tags: [], projects: [], maxEnvironment: "protected", modes: ["relay"], privateCredentials: false }), ctx.now())
      const members = (await signMandate(ctx, "member", terms({ device: "dev_member" }))).mandate
      const owners = (await signMandate(at(ctx, ctx.now() + 1), "owner", terms())).mandate
      expect((await mandateOp(ctx, "mandates.list", "owner", {}) as MandateList).mandates.map((m) => m.id)).toEqual([owners.id, members.id])
      expect((await mandateOp(ctx, "mandates.list", "member", {}) as MandateList).mandates.map((m) => m.id)).toEqual([members.id])
    })
  })
})

describe("the audit", () => {
  it("tells each act on a mandate and each use of a shared credential on one, never with a path", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms({ classes: ["change", "read"], caps: { read: 10, change: 5, send: 0, delete: 0 }, ttlDays: 7 }))
      await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      await mandateOp(ctx, "mandates.pause", "admin", { id: mandate.id, rev: 1 })
      await mandateOp(ctx, "mandates.resume", "owner", { id: mandate.id, rev: 2 }, await mandateAction(ctx, "owner", { op: "resume", id: mandate.id, rev: 2 }))
      fillRate(ctx, mandate.id, MANDATE_RATE_LIMIT)
      await relayAs(ctx, "dev_owner", OPEN_ISSUE)
      await mandateOp(ctx, "mandates.stop", "owner", { id: mandate.id, rev: 4 })
      const rows = ctx.sql.exec<{ actor: string; action: string; target: string; detail: string }>("SELECT actor,action,target,detail FROM audit WHERE action LIKE 'mandate.%' ORDER BY rowid").toArray()
      const said = rows.map((row) => { const l = auditLine({ actor: row.actor, action: row.action, target: row.target, detail: row.detail }, { self: "mem_owner", devices: new Map([["dev_owner", "Mac mini"]]) }); return l.actor + l.pieces.map((p) => p.text).join("") })
      expect(said).toEqual([
        "You let Mac mini read and change without asking for 7 days",
        "An agent on Mac mini used github-work to change without asking, on its mandate: POST api.github.com",
        "Another member paused what Mac mini may do without asking",
        "You let Mac mini carry on without asking again",
        "The vault stopped letting Mac mini through without asking after too many requests in a minute",
        "You stopped what Mac mini may do without asking",
      ])
      const sign = auditLine({ actor: rows[0]!.actor, action: rows[0]!.action, target: rows[0]!.target, detail: rows[0]!.detail }, { self: "mem_owner", devices: new Map() })
      expect(sign.link).toEqual({ href: `/mandates/${mandate.id}`, label: "Open the mandate" })
    })
  })
})

describe("the sweep", () => {
  it("expires a mandate with no rule anchors present, and closes and prunes what is past", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const { mandate } = await signMandate(ctx, "owner", terms({ ttlDays: 1 }))
      await relayAs(ctx, "dev_owner", READ_ISSUES)
      expect(ctx.sql.exec("SELECT * FROM policy_rule_anchors").toArray()).toEqual([])
      const later = at(ctx, ctx.now() + 31 * DAY)
      expect((await workspaceMandateOps["mandates.show"]!.handler(later, memberPrincipal(later, "owner"), { id: mandate.id }, memberInvocation(later, "owner")) as MandateView).state).toBe("expired")
      await mandatesArea.alarm!(later, "mandate-sweep")
      expect(mandateState(ctx, mandate.id)).toEqual({ state: "expired", rev: 2 })
      expect(audits(ctx, "mandate.expire").map((row) => row.target)).toEqual([mandate.id])
      expect([receipts(ctx), counts(ctx), rateRows(ctx)]).toEqual([[], {}, 0])
      sweepMandates(later)
      expect(audits(ctx, "mandate.expire")).toHaveLength(1)
    })
  })

  it("tells the signer alone, once, three days before a mandate ends, never one no longer than that, and wakes for that moment", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedGithub(ctx)
      const ending = (mandate: string) => ctx.sql.exec<{ account: string; payload: string }>("SELECT account,payload FROM notice_outbox").toArray().filter((row) => { const p = JSON.parse(row.payload) as { kind: string; mandate: string }; return p.kind === "mandate_ending" && p.mandate === mandate }).map((row) => row.account)
      const sweepDue = () => ctx.sql.exec<{ due_at: number }>("SELECT due_at FROM schedule WHERE area='mandates' AND key='mandate-sweep'").toArray()[0]?.due_at
      const { mandate } = await signMandate(ctx, "owner", terms({ ttlDays: 7 }))
      const expiresAt = Date.parse(mandate.expiresAt), noticeAt = expiresAt - 3 * DAY
      expect(ending(mandate.id)).toEqual([])
      sweepMandates(at(ctx, noticeAt - DAY / 2))
      expect([ending(mandate.id), sweepDue()]).toEqual([[], noticeAt])
      sweepMandates(at(ctx, noticeAt - 1))
      expect(ending(mandate.id)).toEqual([])
      await mandatesArea.alarm!(at(ctx, noticeAt), "mandate-sweep")
      expect(ending(mandate.id)).toEqual(["acc_owner"])
      expect(JSON.parse(ctx.sql.exec<{ payload: string }>("SELECT payload FROM notice_outbox WHERE payload LIKE '%mandate_ending%'").toArray()[0]!.payload)).toMatchObject({ kind: "mandate_ending", mandate: mandate.id, device: "dev_owner", expiresAt: mandate.expiresAt, signer: { member: "mem_owner" } })
      const shown = drainOutbox(at(ctx, noticeAt), 100).events.filter((e) => e.payload.kind === "mandate_ending")
      expect(shown.map((e) => e.url)).toEqual([`${ctx.env.VAULT_ORIGIN}/w/work/mandates/${mandate.id}`])
      expect(noticeRows(shown, ctx.env.VAULT_ORIGIN, false).toString()).toContain("may do without asking ends unless you sign it again, on")
      sweepMandates(at(ctx, noticeAt + DAY))
      sweepMandates(at(ctx, noticeAt + 2 * DAY))
      expect([ending(mandate.id), sweepDue()]).toEqual([["acc_owner"], expiresAt])

      // A day-long mandate has no three days before its end: no notice, at
      // signing or after, and the sweep wakes only for its end.
      const short = (await signMandate(ctx, "owner", terms({ ttlDays: 1 }))).mandate
      expect(ctx.sql.exec("SELECT ending_noticed_at=created_at AS at_signing FROM mandates WHERE id=?", short.id).toArray()).toEqual([{ at_signing: 1 }])
      expect([ending(short.id), sweepDue()]).toEqual([[], Date.parse(short.expiresAt)])
      sweepMandates(at(ctx, ctx.now() + DAY / 2))
      expect(ending(short.id)).toEqual([])
    })
  })

  it("tells a signer suspended when it was due once they are reinstated, the mandate still live though lapsed, without the sweep spinning meanwhile", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      const { mandate } = await signMandate(ctx, "kim", terms({ device: "dev_kim", ttlDays: 7 }))
      const noticeAt = Date.parse(mandate.expiresAt) - 3 * DAY
      const ending = () => notices(ctx, "mandate_ending")
      const sweepDue = () => ctx.sql.exec<{ due_at: number }>("SELECT due_at FROM schedule WHERE area='mandates' AND key='mandate-sweep'").toArray()[0]?.due_at
      await memberOp(ctx, "access.members.suspend", { member: "mem_kim" }, { type: "member.suspend", member: "mem_kim" })
      sweepMandates(at(ctx, noticeAt))
      expect([ending(), ctx.sql.exec("SELECT ending_noticed_at FROM mandates WHERE id=?", mandate.id).toArray(), sweepDue()]).toEqual([[], [{ ending_noticed_at: null }], noticeAt + DAY])
      await memberOp(ctx, "access.members.reinstate", { member: "mem_kim" }, { type: "member.reinstate", member: "mem_kim" })
      sweepMandates(at(ctx, noticeAt + DAY))
      expect([ending(), mandateState(ctx, mandate.id)]).toEqual([["acc_kim"], { state: "active", rev: 2 }])
      sweepMandates(at(ctx, noticeAt + 2 * DAY))
      expect(ending()).toEqual(["acc_kim"])
    })
  })

  it("is its own area after pushes, with its own migrations, each added after the last", () => {
    expect(AREAS.at(-1)).toBe(mandatesArea)
    expect(mandatesArea.migrations).toEqual([MANDATES_MIGRATION, MANDATE_CAPPED_ASKS_MIGRATION, MANDATE_PROPOSALS_CLOSED_BY_MIGRATION, MANDATE_COVER_ASKS_MIGRATION, MANDATE_PROPOSALS_MANDATE_MIGRATION, MANDATE_ASKED_MIGRATION, MANDATE_PROPOSALS_ITEMS_MIGRATION])
  })
})
