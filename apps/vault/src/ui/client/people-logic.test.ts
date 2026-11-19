// The rules the people, team, machine and Connect an agent pages offer
// controls by, and the text they copy.
import { describe, expect, it } from "vitest"
import { InviteTermsSchema, PENDING_RESTRICTION_UNTIL, scopeChangeIsNarrowing, type WorkspaceMemberView } from "@mehen/protocol"
import { type AgentSetup, activationWords, agentSetup, buildInviteTerms, confirmChoiceShown, inviteMadeWords, inviteMessage, onJoinWords, inviteRoles, machineControls, memberActions, MODE_PLAIN, MODES_LABEL, PENDING_UNTIL_WORDS, ROLE_PLACEHOLDER, restrictionUntil, roleChoices, scopeFromForm, scopeLines } from "./people-logic.ts"

const m = (member: string, role: WorkspaceMemberView["role"], status: WorkspaceMemberView["status"] = "active"): WorkspaceMemberView => ({ member, name: member, role, pendingRole: null, status, teams: [], machines: 0, joinedAt: "2026-10-01T00:00:00.000Z" })
const owner = m("mem_o", "owner"), owner2 = m("mem_o2", "owner"), admin = m("mem_a", "admin"), member = m("mem_m", "member"), guest = m("mem_g", "guest")
const everyone = [owner, owner2, admin, member, guest]

describe("member actions", () => {
  it("offers nothing to members and guests, and nothing on yourself", () => {
    for (const viewer of [member, guest]) for (const subject of everyone) expect(memberActions({ member: viewer.member, role: viewer.role, blocked: false }, subject, everyone)).toEqual([])
    expect(memberActions({ member: owner.member, role: "owner", blocked: false }, owner, everyone)).toEqual([])
  })

  it("lets an admin change admins, members and guests but never an owner, nor make one", () => {
    const viewer = { member: admin.member, role: "admin" as const, blocked: false }
    expect(memberActions(viewer, owner, everyone)).toEqual([])
    expect(memberActions(viewer, member, everyone)).toEqual(["role", "suspend", "remove"])
    expect(roleChoices(viewer, member)).toEqual(["admin", "guest"])
    expect(inviteRoles(viewer)).toEqual(["admin", "member", "guest"])
    expect(memberActions(viewer, m("mem_u", "owner", "unconfirmed"), everyone)).toEqual([])
  })

  it("never offers a change to the last active owner", () => {
    const solo = [owner, admin, member]
    expect(memberActions({ member: admin.member, role: "admin", blocked: false }, owner, solo)).toEqual([])
    expect(memberActions({ member: owner2.member, role: "owner", blocked: false }, owner, [owner, owner2])).toEqual(["role", "suspend", "remove"])
    expect(memberActions({ member: owner2.member, role: "owner", blocked: false }, owner, [owner, { ...owner2, status: "suspended" }])).toEqual([])
  })

  it("offers confirm for an unconfirmed person and reinstate for a suspended one", () => {
    const viewer = { member: owner.member, role: "owner" as const, blocked: false }
    expect(memberActions(viewer, m("mem_u", "guest", "unconfirmed"), everyone)).toEqual(["confirm"])
    expect(memberActions(viewer, m("mem_s", "member", "suspended"), everyone)).toEqual(["role", "reinstate", "remove"])
  })

  it("offers nothing while the account is held back", () => {
    const viewer = { member: owner.member, role: "owner" as const, blocked: true }
    for (const subject of everyone) expect(memberActions(viewer, subject, everyone)).toEqual([])
    expect(inviteRoles(viewer)).toEqual([])
  })

  it("words activation exactly", () => {
    expect(activationWords("Tom", "admin")).toBe("Confirming activates Tom as Admin with exactly these terms. Your passkey signs them; if any term changed since the invitation, the vault refuses and nothing is granted.")
  })
})

describe("invitation terms", () => {
  const now = Date.parse("2026-10-27T12:00:00.000Z")
  it("builds an email-bound member and an open guest, within seven days", () => {
    const bound = buildInviteTerms({ role: "member", binding: "open", email: " Tom@northwind.example ", teams: ["tm_1", "tm_1"], shares: [], days: 30, confirmMyself: false }, now)
    expect(bound).toEqual({ ok: true, value: { role: "member", email: "tom@northwind.example", teams: ["tm_1"], shares: [], expiresAt: "2026-11-03T11:50:00.000Z", onJoin: "activate" } })
    const open = buildInviteTerms({ role: "guest", binding: "open", email: "", teams: ["tm_1"], shares: [{ project: "prj_1", level: "edit", protected: true }], days: 2, confirmMyself: false }, now)
    expect(open).toEqual({ ok: true, value: { role: "guest", email: null, teams: [], shares: [{ project: "prj_1", level: "edit", protected: true, expiresAt: null }], expiresAt: "2026-10-29T11:50:00.000Z", onJoin: "confirm" } })
    if (open.ok) expect(InviteTermsSchema.parse(open.value)).toEqual(open.value)
  })

  it("lets an email-bound member, admin or guest straight in unless the inviter ticks to confirm them; an owner or an open link always waits", () => {
    const form = { binding: "email" as const, email: "tom@northwind.example", teams: [], shares: [{ project: "prj_1", level: "use", protected: false }], days: 7 }
    const onJoin = (role: string, confirmMyself: boolean, binding: "email" | "open" = "email") => { const built = buildInviteTerms({ ...form, role, binding, confirmMyself }, now); return built.ok ? built.value.onJoin : built.problems }
    for (const role of ["member", "admin", "guest"]) {
      expect(onJoin(role, false), role).toBe("activate")
      expect(onJoin(role, true), role).toBe("confirm")
    }
    expect(onJoin("owner", false)).toBe("confirm")
    expect(onJoin("guest", false, "open")).toBe("confirm")
    expect([["member", "email"], ["admin", "email"], ["guest", "email"], ["owner", "email"], ["guest", "open"], ["member", "open"]].map(([role, binding]) => confirmChoiceShown(role!, binding as "email" | "open"))).toEqual([true, true, true, false, false, true])
    const terms = { role: "member" as const, email: "tom@northwind.example" }
    expect(onJoinWords({ ...terms, onJoin: "activate" })).toBe("Joins straight away")
    expect(onJoinWords({ ...terms, onJoin: "confirm" })).toBe("You confirm them when they join")
    expect(onJoinWords(terms)).toBe("You confirm them when they join")
    expect(onJoinWords({ role: "owner", email: "tom@northwind.example", onJoin: "activate" })).toBe("You confirm them when they join")
    expect(inviteMadeWords({ ...terms, onJoin: "activate" })).toBe("Send this link to the person you invited. It works once, and only for that email: they join straight away once they prove it.")
    expect(inviteMadeWords({ ...terms, onJoin: "confirm" })).toBe("Send this link to the person you invited. It works once; nobody can use the workspace until an owner or admin confirms them.")
  })

  it("refuses an open link above guest, a guest with no project or with manage", () => {
    expect(buildInviteTerms({ role: "admin", binding: "open", email: "", teams: [], shares: [], days: 7, confirmMyself: false }, now)).toEqual({ ok: false, problems: ["Type the email this invitation is for."] })
    expect(buildInviteTerms({ role: "guest", binding: "open", email: "", teams: [], shares: [], days: 7, confirmMyself: false }, now)).toEqual({ ok: false, problems: ["A guest needs at least one shared project."] })
    expect(buildInviteTerms({ role: "guest", binding: "open", email: "", teams: [], shares: [{ project: "prj_1", level: "manage", protected: false }], days: 7, confirmMyself: false }, now)).toEqual({ ok: false, problems: ["A guest can use or edit a project, not manage it."] })
  })
})

// Words of characters no POSIX shell treats specially outside quotes, one
// space apart, in commands joined by "; " or " | ": a string of this form is
// a list of simple commands, so `sh -n` accepts it exactly as printed. The
// vault's tests run in workerd, which cannot start a shell; the PM report
// records the same boxes run through `sh -n` and `dash -n`.
const WORD = "[A-Za-z0-9_./:=@%+,-]+"
const COMMAND = `${WORD}(?: ${WORD})*`
const PARSES_AS_PRINTED = new RegExp(`^${COMMAND}(?:(?:; | \\| )${COMMAND})*$`)

const boxes = (setup: AgentSetup | null): string[] => (setup === null ? [] : [setup.prompt, setup.install, setup.setup, setup.enrol])

describe("Connect an agent", () => {
  it("copies only the checked slug and origin, and no workspace id or placeholder", () => {
    expect(agentSetup("https://app.mehen.dev", "northwind")).toEqual({
      prompt: "Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace northwind at https://app.mehen.dev. I will approve it in my browser; never ask me for a key, password or secret.",
      install: "curl -fsSL https://mehen.dev/install | sh",
      setup: "mehen setup",
      enrol: "mehen enrol --workspace northwind",
    })
  })

  it("adds a connect code to the prompt and the enrol command, and nothing else", () => {
    expect(agentSetup("https://app.mehen.dev", "northwind", "7XK2M9QP")).toEqual({
      prompt: "Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace northwind at https://app.mehen.dev with connect code 7XK2M9QP. I will approve it in my browser; never ask me for a key, password or secret.",
      install: "curl -fsSL https://mehen.dev/install | sh",
      setup: "mehen setup",
      enrol: "mehen enrol --workspace northwind --connect 7XK2M9QP",
    })
  })

  it("parses every copy box as shell exactly as printed, with and without a code", () => {
    for (const setup of [agentSetup("https://app.mehen.dev", "northwind"), agentSetup("http://localhost:8787", "a-b-c", "23456789"), agentSetup("https://vault.test", "northwind", "ZZZZZZZZ")]) {
      expect(boxes(setup)).toHaveLength(4)
      for (const text of boxes(setup)) {
        expect(text, text).toMatch(PARSES_AS_PRINTED)
        expect(text, text).not.toMatch(/tn_|<|>|--name/)
      }
    }
    // The grammar is strict enough to refuse the old box.
    expect("mehen enrol --workspace northwind --name <machine-name>").not.toMatch(PARSES_AS_PRINTED)
  })

  it("offers nothing to copy when a slug, origin or code is not what the grammar allows", () => {
    for (const slug of ["Northwind", "a\"; rm -rf ~", "x\ny", "legacy-abc", "https://evil.example", "tn_8kQw2Lm4Zp7Rt5Vx"]) expect(agentSetup("https://app.mehen.dev", slug)).toBeNull()
    expect(agentSetup("https://app.mehen.dev/path", "alex")).toBeNull()
    expect(agentSetup("https://app.mehen.dev; curl evil", "alex")).toBeNull()
    for (const code of ["", "7xk2m9qp", "7XK2M9Q", "7XK2M9QPX", "7XK2-M9QP", "7XK2M9Q0", "7XK2M9QI", "$(id)ABCD", "7XK2M9Q;"]) expect(agentSetup("https://app.mehen.dev", "alex", code), code).toBeNull()
  })
})

describe("the invitation message", () => {
  const link = "https://app.mehen.dev/signup#k7Qm2vXr9pLw4sNt8bHd3fGj"
  const BOUND = { role: "member" as const, email: "tom@northwind.example" }
  it("is the onboarding copy, with the Google step only for an email-bound invitation", () => {
    expect(inviteMessage({ name: "Northwind", slug: "northwind" }, link, { ...BOUND, onJoin: "confirm" })).toBe(`You are invited to Northwind on Mehen, where our agents use credentials without ever seeing them. Open this link, verify your work Google account, create a passkey and save your recovery codes; it takes about three minutes. I confirm you once you have joined, then you connect your agent. ${link}`)
    expect(inviteMessage({ name: "Northwind", slug: "northwind" }, link, { role: "guest", email: null, onJoin: "confirm" })).not.toContain("Google")
  })

  it("says the person connects their agent straight after joining when the invitation lets them in", () => {
    expect(inviteMessage({ name: "Northwind", slug: "northwind" }, link, { ...BOUND, onJoin: "activate" })).toBe(`You are invited to Northwind on Mehen, where our agents use credentials without ever seeing them. Open this link, verify your work Google account, create a passkey and save your recovery codes; it takes about three minutes. Then you connect your agent. ${link}`)
  })

  it("names the workspace by its short name when its name is not plain words", () => {
    for (const name of ["Tom\"; <b>x</b>", "Lle\u202everage", "Bell\u0007", "line\nbreak"]) {
      const text = inviteMessage({ name, slug: "hostile-name" }, link, BOUND)
      expect(text).toContain("invited to hostile-name on Mehen")
      expect(text).not.toContain(name)
    }
  })
})

describe("the role picker and scope words", () => {
  it("has a placeholder to start on, and never offers the current role", () => {
    expect(ROLE_PLACEHOLDER).toBe("Change role to ...")
    expect(roleChoices({ member: owner.member, role: "owner", blocked: false }, admin)).toEqual(["owner", "member", "guest"])
  })

  it("says how a machine may use credentials in plain words, never the mode names", () => {
    const ways = (modes: ("relay" | "sign" | "mint" | "placeholder" | "fill" | "lease")[]) => scopeLines({ tags: [], projects: [], maxEnvironment: "unprotected", modes, privateCredentials: false }, (id) => id).find((l) => l.label === MODES_LABEL)?.value
    expect(ways(["relay", "sign", "mint", "placeholder"])).toBe("Through the vault only, signing, short-lived tokens and stand-in values")
    expect(ways(["lease", "relay"])).toBe("Through the vault only and the real value on this machine")
    expect(ways(["relay"])).toBe("Through the vault only")
    expect(ways(["lease", "fill", "relay"])).toBe("Through the vault only, typing into web pages and the real value on this machine")
    expect(MODE_PLAIN.fill).toBe("typing into web pages")
  })
})

describe("restriction ends and machine scope", () => {
  it("says until recovery completes for null and the sentinel, never a year", () => {
    const format = (v: string) => v.slice(0, 10)
    expect(restrictionUntil(null, format)).toBe(PENDING_UNTIL_WORDS)
    expect(restrictionUntil(PENDING_RESTRICTION_UNTIL, format)).toBe(PENDING_UNTIL_WORDS)
    expect(restrictionUntil("2026-10-28T09:20:00.000Z", format)).toBe("until 2026-10-28")
  })

  it("lets owners, admins and the machine's own person change it; a team's only owners and admins; nothing revoked", () => {
    const tom = { member: "mem_t", role: "member" as const, blocked: false }
    expect(machineControls(tom, { kind: "member", member: "mem_t", name: "Tom" }, false)).toEqual({ revoke: true, narrow: true, propose: true })
    expect(machineControls(tom, { kind: "member", member: "mem_x", name: "X" }, false)).toEqual({ revoke: false, narrow: false, propose: false })
    expect(machineControls(tom, { kind: "team", team: "tm_1", name: "T" }, false)).toEqual({ revoke: false, narrow: false, propose: false })
    expect(machineControls({ ...tom, role: "admin" }, { kind: "team", team: "tm_1", name: "T" }, false)).toEqual({ revoke: true, narrow: true, propose: true })
    expect(machineControls({ ...tom, blocked: true }, { kind: "member", member: "mem_t", name: "Tom" }, false)).toEqual({ revoke: true, narrow: true, propose: false })
    expect(machineControls(tom, { kind: "member", member: "mem_t", name: "Tom" }, true)).toEqual({ revoke: false, narrow: false, propose: false })
  })

  it("builds the asked scope; never a private tick on a team's machine; narrowing as the protocol decides", () => {
    const before = { tags: ["ai"], projects: [], maxEnvironment: "protected" as const, modes: ["relay", "sign"] as ("relay" | "sign")[], privateCredentials: true }
    const narrowed = scopeFromForm(before, { kind: "member", member: "mem_t", name: "Tom" }, { modes: ["relay"], maxEnvironment: "unprotected", privateCredentials: false, serviceRuns: false, projects: ["prj_1"] })
    expect(narrowed).toEqual({ ok: true, value: { tags: ["ai"], projects: ["prj_1"], maxEnvironment: "unprotected", modes: ["relay"], privateCredentials: false } })
    if (narrowed.ok) expect(scopeChangeIsNarrowing(before, narrowed.value)).toBe(true)
    const team = scopeFromForm({ ...before, privateCredentials: false }, { kind: "team", team: "tm_1", name: "T" }, { modes: ["relay", "lease"], maxEnvironment: "protected", privateCredentials: true, serviceRuns: false, projects: [] })
    expect(team.ok && team.value.privateCredentials).toBe(false)
    if (team.ok) expect(scopeChangeIsNarrowing({ ...before, privateCredentials: false }, team.value)).toBe(false)
    expect(scopeFromForm(before, { kind: "member", member: "mem_t", name: "Tom" }, { modes: [], maxEnvironment: "unprotected", privateCredentials: false, serviceRuns: false, projects: [] }).ok).toBe(false)
  })

  it("asks for typing into web pages beside another way, never alone, as the vault refuses it", () => {
    const before = { tags: [], projects: [], maxEnvironment: "unprotected" as const, modes: ["relay"] as "relay"[], privateCredentials: false }
    const tom = { kind: "member" as const, member: "mem_t", name: "Tom" }
    const form = { maxEnvironment: "unprotected", privateCredentials: false, serviceRuns: false, projects: [] }
    const widened = scopeFromForm(before, tom, { ...form, modes: ["fill", "relay"] })
    expect(widened).toEqual({ ok: true, value: { ...before, modes: ["relay", "fill"] } })
    if (widened.ok) expect(scopeChangeIsNarrowing(before, widened.value)).toBe(false)
    expect(scopeFromForm(before, tom, { ...form, modes: ["fill"] })).toEqual({ ok: false, problems: ["A machine needs at least one other way to use credentials besides typing into web pages."] })
  })

  it("asks for service runs only when ticked, as a widening, and taking them away narrows", () => {
    const before = { tags: [], projects: [], maxEnvironment: "unprotected" as const, modes: ["relay"] as "relay"[], privateCredentials: false }
    const form = { modes: ["relay"], maxEnvironment: "unprotected", privateCredentials: false, projects: [] }
    const tom = { kind: "member" as const, member: "mem_t", name: "Tom" }
    expect(scopeFromForm(before, tom, { ...form, serviceRuns: false })).toEqual({ ok: true, value: before })
    const granted = scopeFromForm(before, tom, { ...form, serviceRuns: true })
    expect(granted).toEqual({ ok: true, value: { ...before, serviceRuns: true } })
    if (granted.ok) expect(scopeChangeIsNarrowing(before, granted.value)).toBe(false)
    const removed = scopeFromForm({ ...before, serviceRuns: true }, tom, { ...form, serviceRuns: false })
    expect(removed).toEqual({ ok: true, value: { ...before, serviceRuns: false } })
    if (removed.ok) expect(scopeChangeIsNarrowing({ ...before, serviceRuns: true }, removed.value)).toBe(true)
    expect(scopeLines({ ...before, serviceRuns: true }, (id) => id).at(-1)).toEqual({ label: "Services", value: "Yes: it may start service runs (mehen run --service), which renew with no maximum life" })
    expect(scopeLines(before, (id) => id).some((l) => l.label === "Services")).toBe(false)
  })
})
