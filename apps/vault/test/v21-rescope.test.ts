// Changing a machine's scope and a project's repositories: what the review
// says, the digest the browser signs matching the server's, and a
// workspace machine's rescope proposal.

import { describe, expect, it } from "vitest"
import type { DeviceScope } from "@mehen/protocol/api"
import { describeScopeChange, remoteChangeDigest as clientRemoteDigest } from "../src/ui/client/rescope.ts"
import type { RescopeProposalView, WorkspaceDeviceView, WorkspaceProject } from "@mehen/protocol/workspace"
import { renderDocument } from "../src/ui/layout.ts"
import { type MachinesData, machinePage } from "../src/ui/pages/machines.ts"
import { GUEST_SHARED_PROJECTS, PEOPLE_DEVICE, PEOPLE_PROJECTS, THUMBPRINT, peopleShell } from "../src/ui/people-gallery.ts"
import { remoteChangeDigest } from "../src/vault/areas/projects.ts"

const DEFAULTS: DeviceScope = { tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "sign", "mint", "placeholder"] }
const NAMES = new Map([
  ["prj_a", "agent-runtime"],
  ["prj_b", "mehen"],
])

describe("describeScopeChange", () => {
  it("says nothing when nothing changed", () => {
    expect(describeScopeChange(DEFAULTS, { ...DEFAULTS }, NAMES)).toEqual([])
  })

  it("marks every line that lets the machine reach more as widening", () => {
    const wider: DeviceScope = { tags: [], projects: [], maxEnvironment: "protected", modes: ["relay", "sign", "mint", "placeholder", "lease"] }
    const lines = describeScopeChange({ ...DEFAULTS, tags: ["ai"], projects: ["prj_a"] }, wider, NAMES)
    expect(lines.every((l) => l.widens)).toBe(true)
    expect(lines.map((l) => l.text)).toEqual([
      "Every credential, not only credentials tagged ai",
      "Every project, not only agent-runtime",
      "May now use lease: the real value goes into one program on the machine",
      "Protected environments too (prod); each use still needs your approval",
    ])
  })

  it("marks narrowing lines as not widening, and names projects by slug", () => {
    const lines = describeScopeChange(DEFAULTS, { tags: ["ai", "code"], projects: ["prj_a", "prj_gone"], maxEnvironment: "unprotected", modes: ["relay"] }, NAMES)
    expect(lines.some((l) => l.widens)).toBe(false)
    expect(lines.map((l) => l.text)).toEqual([
      "Only credentials tagged ai or code, no longer every credential",
      "Only agent-runtime and prj_gone, no longer every project",
      "May no longer use sign",
      "May no longer use mint",
      "May no longer use placeholder",
    ])
  })

  it("splits a swap of tags into what it gains and what it loses", () => {
    const lines = describeScopeChange({ ...DEFAULTS, tags: ["ai"] }, { ...DEFAULTS, tags: ["code"] }, NAMES)
    expect(lines).toEqual([
      { text: "Also credentials tagged code", widens: true },
      { text: "No longer credentials tagged ai", widens: false },
    ])
  })
})

describe("remoteChangeDigest", () => {
  it("is the digest the server checks, and differs between bind and unbind", async () => {
    const bind = { project: "prj_a", remote: "git@github.com:Owner/App.git", bound: true }
    expect(await clientRemoteDigest(bind)).toBe(remoteChangeDigest(bind))
    expect(await clientRemoteDigest({ ...bind, bound: false })).toBe(remoteChangeDigest({ ...bind, bound: false }))
    expect(await clientRemoteDigest({ ...bind, bound: false })).not.toBe(await clientRemoteDigest(bind))
  })
})

describe("workspace rescope view", () => {
  it("keeps the accepted scope separate from a private-tick proposal and never accepts an admission signature", async () => {
    const { accessFixture, inAccess, registerFixtureLifecycleHooks, accountAuth, workspaceInvoke, accessSnapshot } = await import("./access-test-support.ts")
    const { accessState } = await import("../src/vault/areas/workspace-runtime.ts")
    const { RescopeProposalViewSchema, WorkspaceDeviceViewSchema } = await import("@mehen/protocol")
    const { tenant } = await accessFixture()
    const thumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    const before = await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); ctx.sql.exec("UPDATE devices SET thumbprint=? WHERE id='dev_member'", thumbprint); return accessState(ctx).devices.find((d) => d.id === "dev_member")!.scope })
    const after = { ...before, privateCredentials: true }
    const proposed = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_member", before, after }, accountAuth("admin", { type: "device.rescope", device: "dev_member", thumbprint, before, after }))
    if (!proposed.ok) throw new Error(JSON.stringify(proposed))
    const proposal = RescopeProposalViewSchema.parse(proposed.value)
    const listed = await workspaceInvoke(tenant, "devices.list", {}, accountAuth("member"))
    expect(listed).toMatchObject({ ok: true, value: { devices: [{ scope: before, pendingRescope: { before, after } }] } })
    if (listed.ok) {
      const value = listed.value as { devices: unknown[] }
      const device = WorkspaceDeviceViewSchema.parse(value.devices[0])
      expect(device.pendingRescope).not.toHaveProperty("signatures")
      expect(device.scope.privateCredentials).toBe(false)
    }
    const snapshot = await accessSnapshot(tenant)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("member", { type: "device.rescope", device: "dev_member", thumbprint, before, after }))).toEqual({ ok: false, error: { status: 403, vaultError: { error: "forbidden", message: "This needs a passkey confirmation of the exact action." } } })
    expect(await accessSnapshot(tenant)).toBe(snapshot)
  })
})

// Ruling F2(a): mehen below 0.3.17 fails on a scope holding fill, so the
// vault never adds fill to a machine whose CLI last proved an older version,
// or none (BROWSER_FILL is on in the test env).
describe("a fill rescope and a machine's mehen", () => {
  it("refuses fill while the machine's last mehen is below 0.3.17 or unknown, on every path, and lets the owner accept it from 0.3.17", async () => {
    const { accessFixture, inAccess, registerFixtureLifecycleHooks, accountAuth, workspaceInvoke, accessSnapshot } = await import("./access-test-support.ts")
    const { accessState } = await import("../src/vault/areas/workspace-runtime.ts")
    const { RescopeProposalViewSchema } = await import("@mehen/protocol")
    const { tenant } = await accessFixture()
    const before = await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); return accessState(ctx).devices.find((d) => d.id === "dev_member")!.scope })
    const after = { ...before, modes: [...before.modes, "fill" as const] }
    const lastCli = (version: string | null) => inAccess(tenant, (ctx) => { ctx.sql.exec("UPDATE devices SET last_cli_version=? WHERE id='dev_member'", version) })
    const refusal = (runs: string) => ({ ok: false, error: { status: 403, vaultError: { error: "mode_refused", message: `dev_member ${runs}; typing into web pages needs 0.3.17 or later.`, next: { say: "Update mehen on that machine first, then allow it again." } } } })
    const rescope = (role: string) => workspaceInvoke(tenant, "devices.rescope", { device: "dev_member", before, after }, accountAuth(role, { type: "device.rescope", device: "dev_member", thumbprint: "dev_member", before, after }))
    for (const [version, runs] of [[null, "runs an unknown version of mehen"], ["0.3.16", "runs mehen 0.3.16"], ["0.3.17-rc.1", "runs mehen 0.3.17-rc.1"]] as const) {
      await lastCli(version)
      const snapshot = await accessSnapshot(tenant)
      for (const role of ["admin", "member"]) expect(await rescope(role)).toEqual(refusal(runs))
      for (const kind of ["rescope", "rescope_propose"]) expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_member", change: { kind, before, after } }, accountAuth("admin"))).toEqual(refusal(runs))
      expect(await accessSnapshot(tenant)).toBe(snapshot)
    }
    await lastCli("0.3.17")
    const proposed = await rescope("admin")
    if (!proposed.ok) throw new Error(JSON.stringify(proposed))
    const proposal = RescopeProposalViewSchema.parse(proposed.value)
    const accept = { type: "device.rescope_accept" as const, device: "dev_member", thumbprint: "dev_member", account: "acc_member", before, after, admission: false }
    // The machine went back to an older mehen before its owner accepted.
    await lastCli("0.3.15")
    expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_member", change: { kind: "rescope_accept", proposal: proposal.id } }, accountAuth("member"))).toEqual(refusal("runs mehen 0.3.15"))
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("member", accept))).toEqual(refusal("runs mehen 0.3.15"))
    await lastCli("0.3.19")
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("member", accept))).toMatchObject({ ok: true, value: { state: "committed" } })
    await inAccess(tenant, (ctx) => expect(accessState(ctx).devices.find((d) => d.id === "dev_member")?.scope.modes).toContain("fill"))
    // Keeping fill is not adding it: a narrowing that keeps it goes through.
    await lastCli(null)
    const narrower = { ...after, modes: after.modes.filter((mode) => mode !== "lease") }
    expect(await workspaceInvoke(tenant, "devices.rescope", { device: "dev_member", before: after, after: narrower }, accountAuth("member", { type: "device.rescope", device: "dev_member", thumbprint: "dev_member", before: after, after: narrower }))).toMatchObject({ ok: true, value: { state: "committed" } })
  })

  // Every released mehen reads a scope of at least one mode, and one below
  // 0.3.17 is answered without fill, so fill is never a machine's only mode.
  it("refuses a machine scope whose only mode is fill on every path, its mehen however new", async () => {
    const { accessFixture, inAccess, registerFixtureLifecycleHooks, accountAuth, workspaceInvoke, accessSnapshot } = await import("./access-test-support.ts")
    const { accessState, digest } = await import("../src/vault/areas/workspace-runtime.ts")
    const { RescopeProposalViewSchema } = await import("@mehen/protocol")
    const { tenant } = await accessFixture()
    const before = await inAccess(tenant, (ctx) => { registerFixtureLifecycleHooks(); ctx.sql.exec("UPDATE devices SET last_cli_version='0.3.17' WHERE id='dev_member'"); return accessState(ctx).devices.find((d) => d.id === "dev_member")!.scope })
    const widened = { ...before, modes: [...before.modes, "fill" as const] }
    const fillOnly = { ...before, modes: ["fill" as const] }
    const refused = { ok: false, error: { status: 403, vaultError: { error: "mode_refused", message: "A machine needs at least one other way to use credentials besides typing into web pages." } } }
    let snapshot = await accessSnapshot(tenant)
    for (const role of ["admin", "member"]) expect(await workspaceInvoke(tenant, "devices.rescope", { device: "dev_member", before, after: fillOnly }, accountAuth(role, { type: "device.rescope", device: "dev_member", thumbprint: "dev_member", before, after: fillOnly }))).toEqual(refused)
    for (const kind of ["rescope", "rescope_propose"]) expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_member", change: { kind, before, after: fillOnly } }, accountAuth("admin"))).toEqual(refused)
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    // A proposal left open from before, whose scope is fill alone, is not accepted or admitted either.
    const proposed = await workspaceInvoke(tenant, "devices.rescope", { device: "dev_member", before, after: widened }, accountAuth("admin", { type: "device.rescope", device: "dev_member", thumbprint: "dev_member", before, after: widened }))
    if (!proposed.ok) throw new Error(JSON.stringify(proposed))
    const proposal = RescopeProposalViewSchema.parse(proposed.value)
    await inAccess(tenant, (ctx) => {
      const stored = JSON.parse(ctx.sql.exec<{ value: string }>("SELECT value FROM device_rescope_proposals WHERE id=?", proposal.id).toArray()[0]!.value)
      ctx.sql.exec("UPDATE device_rescope_proposals SET value=? WHERE id=?", JSON.stringify({ ...stored, after: fillOnly, afterDigest: digest(fillOnly) }), proposal.id)
    })
    snapshot = await accessSnapshot(tenant)
    const accept = { type: "device.rescope_accept" as const, device: "dev_member", thumbprint: "dev_member", account: "acc_member", before, after: fillOnly, admission: false }
    for (const kind of ["rescope_accept", "rescope_admit"]) expect(await workspaceInvoke(tenant, "access.devices.action", { device: "dev_member", change: { kind, proposal: proposal.id } }, accountAuth("member"))).toEqual(refused)
    expect(await workspaceInvoke(tenant, "devices.rescope_accept", { proposal: proposal.id }, accountAuth("member", accept))).toEqual(refused)
    expect(await workspaceInvoke(tenant, "devices.rescope_admit", { proposal: proposal.id }, accountAuth("admin", { type: "device.rescope", device: "dev_member", thumbprint: "dev_member", before, after: fillOnly }))).toEqual(refused)
    expect(await accessSnapshot(tenant)).toBe(snapshot)
    await inAccess(tenant, (ctx) => expect(accessState(ctx).devices.find((d) => d.id === "dev_member")?.scope).toEqual(before))
  })
})

// The workspace machine page's rescope card is an ask: a
// proposal whose machine, people or scope entries carry hidden or control
// characters renders its warning first, turns red, emphasises Reject and
// quietens accepting; both stay passkey-signed actions.
describe("the warned rescope card", () => {
  const shell = peopleShell("member", { member: "mem_tom01" })
  const tom = { viewer: { member: "mem_tom01", role: "member" as const, blocked: false }, projects: PEOPLE_PROJECTS, now: Date.parse("2026-10-27T18:30:00Z") }
  const proposal = (overrides: Partial<RescopeProposalView>): WorkspaceDeviceView => ({
    ...PEOPLE_DEVICE,
    pendingRescope: { id: "rsp_w", device: PEOPLE_DEVICE.device, thumbprint: THUMBPRINT, before: PEOPLE_DEVICE.scope, after: { ...PEOPLE_DEVICE.scope, maxEnvironment: "protected" }, beforeDigest: "b", afterDigest: "a", proposer: { member: "mem_alex01", name: "Alex Rae" }, requiredSigners: [{ account: shell.identity.account, name: "Tom Barker", as: "owner_acceptance" }], signedBy: [], expiresAt: "2026-10-28T18:30:00.000Z", state: "open", ...overrides },
  })
  const card = (device: WorkspaceDeviceView, data: MachinesData = tom, as = shell) => /<section class="card decision[^"]*" data-region="proposal"[\s\S]*?<\/section>/.exec(renderDocument(machinePage(as, device, data)).value)?.[0] ?? ""

  it("warns on a hidden character in a scope entry and in a proposer's name, warning first, Reject emphasised", () => {
    const hostile = [
      proposal({ after: { ...PEOPLE_DEVICE.scope, tags: ["prod\u200bkeys"] } }),
      proposal({ proposer: { member: "mem_x", name: "Al\u202eex" } }),
      proposal({ requiredSigners: [{ account: shell.identity.account, name: "Tom\u0007", as: "owner_acceptance" }] }),
    ]
    for (const device of hostile) {
      const html = card(device)
      expect(html).toMatch(/^<section class="card decision warned" data-region="proposal"[^>]*>\s*<div data-region="warnings"><div class="notice error" role="alert">/)
      expect(html).toContain('<button type="button" class="btn danger" data-action="rescope-reject" data-proposal="rsp_w">')
      expect(html.indexOf('data-action="rescope-reject"')).toBeLessThan(html.indexOf('data-action="rescope-accept"'))
      expect(html).toContain('class="btn quiet" data-action="rescope-accept" data-proposal="rsp_w"')
      expect(html).not.toContain("btn primary")
      expect(html).not.toMatch(/[\u200b\u202e\u0007]/)
      expect(html).not.toMatch(/rescope-decline|Do not accept|nothing is sent/)
    }
  })

  it("does not warn on plain text, offers Reject quietly after Accept, and nothing to reject when there is nothing to accept", () => {
    const plain = card(proposal({}))
    expect(plain.startsWith(`<section class="card decision" data-region="proposal" data-proposal="rsp_w" data-device="dev_tomlaptop01" data-thumbprint="${THUMBPRINT}">`)).toBe(true)
    expect(plain).not.toContain('data-region="warnings"')
    expect(plain).toContain('class="btn primary" data-action="rescope-accept"')
    expect(plain).toContain('<button type="button" class="btn quiet" data-action="rescope-reject" data-proposal="rsp_w">')
    expect(plain.indexOf('data-action="rescope-accept"')).toBeLessThan(plain.indexOf('data-action="rescope-reject"'))
    const held = card(proposal({ proposer: { member: "mem_x", name: "Al\u202eex" } }), { ...tom, viewer: { ...tom.viewer, blocked: true } })
    expect(held).toContain('data-region="warnings"')
    expect(held).not.toMatch(/rescope-accept|rescope-reject/)
    // Already signed, or someone else's proposal: nothing to accept, nothing to reject.
    expect(card(proposal({ signedBy: [shell.identity.account] }))).not.toMatch(/rescope-accept|rescope-reject/)
    expect(card(proposal({ requiredSigners: [{ name: "Tom Barker", as: "owner_acceptance" }] }))).not.toMatch(/rescope-accept|rescope-reject/)
  })

  // A guest's machine needs the guest's acceptance and one insider's
  // admission. The vault shows each signer's account only to that signer
  // (workspace-devices.ts publicProposal), so Admit is offered only where
  // the admission signer's account is the viewer's own, and only with a
  // project the vault judges admission on: one the guest holds an active
  // share on and the signer manages (access.ts rescopeAdmitAuthority).
  const gina = { ...PEOPLE_DEVICE, owner: { kind: "member" as const, member: "mem_guest01", name: "Gina (contractor)" } }
  const guestProposal = (signers: { guest: boolean; admitter: boolean }, proposer = "Alex Rae"): WorkspaceDeviceView => ({
    ...gina,
    pendingRescope: { ...proposal({ proposer: { member: "mem_alex01", name: proposer } }).pendingRescope!, device: gina.device, requiredSigners: [{ ...(signers.guest ? { account: shell.identity.account } : {}), name: "Gina (contractor)", as: "owner_acceptance" }, { ...(signers.admitter ? { account: shell.identity.account } : {}), name: "Noor Eddial", as: "admission" }] },
  })
  const insider = (role: "owner" | "admin" | "member", member: string, projects: WorkspaceProject[] | null = GUEST_SHARED_PROJECTS) => ({ as: peopleShell(role, { member }), data: { ...tom, projects, viewer: { member, role, blocked: false } } })
  const guest = { as: peopleShell("guest", { member: "mem_guest01" }), data: { ...tom, viewer: { member: "mem_guest01", role: "guest" as const, blocked: false } } }
  const share = (project: string, member: string, expiresAt: string | null = null) => ({ id: `shr_${project}`, project, subject: { kind: "member" as const, member }, level: "edit" as const, protected: false, expiresAt })
  const sharedOn = (shares: Record<string, ReturnType<typeof share>[]>, level: "use" | "manage" = "manage"): WorkspaceProject[] => PEOPLE_PROJECTS.map((p) => ({ ...p, access: { ...p.access, level }, shares: shares[p.id] ?? [] }))

  describe("who is offered Admit and Reject", () => {
    for (const [kind, proposer] of [["plain", "Alex Rae"], ["hostile", "Al\u202eex"]] as const) {
      it(`${kind}: the designated insider gets Admit and Reject for the guest's shared project; another owner or admin, whose account is omitted, gets neither`, () => {
        const designated = insider("admin", "mem_noor01")
        const mine = card(guestProposal({ guest: false, admitter: true }, proposer), designated.data, designated.as)
        expect(mine).toContain('data-thumbprint="' + THUMBPRINT + '" data-project="prj_site01"')
        expect(mine).toContain('data-action="rescope-admit" data-proposal="rsp_w"')
        expect(mine).toContain(kind === "hostile" ? 'class="btn quiet" data-action="rescope-admit"' : 'class="btn primary" data-action="rescope-admit"')
        expect(mine).toContain(kind === "hostile" ? 'class="btn danger" data-action="rescope-reject"' : 'class="btn quiet" data-action="rescope-reject"')
        expect(mine).not.toContain("rescope-accept")
        for (const other of [insider("owner", "mem_alex01"), insider("admin", "mem_noor02")]) {
          const theirs = card(guestProposal({ guest: false, admitter: false }, proposer), other.data, other.as)
          expect(theirs, other.data.viewer.role).toContain("Noor Eddial: admits it")
          expect(theirs, other.data.viewer.role).not.toMatch(/rescope-admit|rescope-accept|rescope-reject|data-project=/)
        }
      })

      it(`${kind}: the owning guest keeps Accept and Reject, sends no project, and is never offered Admit`, () => {
        const theirs = card(guestProposal({ guest: true, admitter: false }, proposer), guest.data, guest.as)
        expect(theirs).toContain(kind === "hostile" ? 'class="btn quiet" data-action="rescope-accept"' : 'class="btn primary" data-action="rescope-accept"')
        expect(theirs).toContain('data-action="rescope-reject" data-proposal="rsp_w"')
        expect(theirs).not.toMatch(/rescope-admit|data-project=/)
      })
    }

    it("offers the designated signer neither Admit nor Reject without a project the guest shares and the signer manages", () => {
      const unqualified: [string, ReturnType<typeof insider>][] = [
        ["no project list", insider("admin", "mem_noor01", null)],
        ["no shares read", insider("admin", "mem_noor01", PEOPLE_PROJECTS)],
        ["another member's share", insider("admin", "mem_noor01", sharedOn({ prj_site01: [share("prj_site01", "mem_tom01")] }))],
        ["an expired share", insider("admin", "mem_noor01", sharedOn({ prj_site01: [share("prj_site01", "mem_guest01", "2026-10-27T18:00:00.000Z")] }))],
        ["a member who does not manage it", insider("member", "mem_sam01", sharedOn({ prj_site01: [share("prj_site01", "mem_guest01")] }, "use"))],
      ]
      for (const [why, who] of unqualified) {
        const html = card(guestProposal({ guest: false, admitter: true }), who.data, who.as)
        expect(html, why).toContain("Noor Eddial: admits it")
        expect(html, why).not.toMatch(/rescope-admit|rescope-reject|data-project=/)
      }
      const manager = insider("member", "mem_sam01", sharedOn({ prj_site01: [share("prj_site01", "mem_guest01", "2026-10-29T18:00:00.000Z")] }))
      expect(card(guestProposal({ guest: false, admitter: true }), manager.data, manager.as)).toMatch(/data-project="prj_site01"[\s\S]*data-action="rescope-admit"[\s\S]*data-action="rescope-reject"/)
    })

    it("picks the first qualifying project by slug", () => {
      const both = insider("owner", "mem_alex01", sharedOn({ prj_site01: [share("prj_site01", "mem_guest01")], prj_platform01: [share("prj_platform01", "mem_guest01")] }))
      expect(card(guestProposal({ guest: false, admitter: true }), both.data, both.as)).toContain('data-project="prj_platform01"')
    })
  })

  describe("named enrolment evidence", () => {
    // The names on the machine's acceptance and admission are on the same
    // page (a guest is shown the other member's name), and an old admitting
    // member need not be the proposer or a signer now.
    const warnedFirst = (html: string, button: string) => {
      expect(html).toMatch(/^<section class="card decision warned" data-region="proposal"[^>]*>\s*<div data-region="warnings"><div class="notice error" role="alert">/)
      expect(html).toContain('class="btn danger" data-action="rescope-reject"')
      expect(html).toContain(`class="btn quiet" data-action="${button}"`)
      expect(html).not.toContain("btn primary")
    }

    it("warns on a hidden character in the acceptance name, warning first, Accept quiet", () => {
      warnedFirst(card({ ...proposal({}), acceptance: { name: "Tom\u200bDavies", at: "2026-10-27T18:00:00.000Z" } }), "rescope-accept")
    })

    it("warns on a control character in the admission name, warning first, Accept quiet", () => {
      warnedFirst(card({ ...guestProposal({ guest: true, admitter: false }), admission: { name: "Ad\u0007min", at: "2026-10-27T18:00:00.000Z" } }, guest.data, guest.as), "rescope-accept")
    })

    it("still renders full evidence, which has no name, without a warning", () => {
      const full = { account: "acc_4Hq9Tz2Lm7Vb1Nc8", member: "mem_tom01", digest: "d", ruleRevision: 0, gateGeneration: 0, identityCheck: null, at: "2026-10-27T18:00:00.000Z" }
      const device = { ...proposal({}), acceptance: full, admission: full }
      expect(card(device)).toMatch(/^<section class="card decision" data-region="proposal"/)
      expect(card(device)).toContain('class="btn primary" data-action="rescope-accept"')
      expect(renderDocument(machinePage(shell, device, tom)).value.match(/Signed with a passkey/g)).toHaveLength(2)
    })
  })
})
