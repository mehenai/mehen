// The people pages' journey through the real Worker, making exactly the
// calls the browser code makes (ui/client/pages/people.ts and
// account-setup.ts): the same paths, bodies, Mehen-Workspace header and
// step-up starts, with each action taken from the page's own boot payload
// or the vault's planning reply, never from the test's own knowledge.
// Invite, sign up, set up recovery, join, wait, be confirmed, land on
// Connect an agent, then enrol a machine and have it admitted.
import { describe, expect, it } from "vitest"
import type { WorkspaceRef, WorkspaceStepUpAction } from "@mehen/protocol"
import { buildInviteTerms } from "../../src/ui/client/people-logic.ts"
import { body, refusal, workJourney, type Person } from "./workspace-journey.ts"
import { assertion, registration, softwarePasskey } from "./passkeys.ts"
import { sha256Text } from "../../src/directory/session.ts"

const HTML = { accept: "text/html" }

function bootOf(page: string): Record<string, unknown> {
  const raw = /data-boot="([^"]*)"/.exec(page)?.[1]
  if (raw === undefined) throw new Error("no boot payload")
  return JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&#96;", "`").replaceAll("&amp;", "&")) as Record<string, unknown>
}

function copied(page: string): string[] {
  return [...page.matchAll(/<div class="copybox"><code>([^<]*)<\/code>/g)].map((x) => x[1] as string)
}

async function uiJourney() {
  const f = await workJourney()
  // workspaceApi: /api/w/<slug><path> with the tab's workspace id.
  const ui = (person: Person, workspace: WorkspaceRef, path: string, input?: unknown) => f.request(`/api/w/${workspace.slug}${path}`, person, input, { "Mehen-Workspace": workspace.id })
  // workspaceStepUp, then the change with its proof.
  const uiSigned = async (person: Person, workspace: WorkspaceRef, action: WorkspaceStepUpAction, path: string, input: Record<string, unknown>) => {
    const { nonce, options } = await body<{ nonce: string; options: { challenge: string } }>(await ui(person, workspace, "/stepup/start", { action }))
    return ui(person, workspace, path, { ...input, stepUp: { nonce, assertion: await assertion(person.passkey, options.challenge, ++person.counter) } })
  }
  // accountStepUp.
  const accountSigned = async (person: Person, action: WorkspaceStepUpAction, path: string, input: Record<string, unknown>) => {
    const { nonce, options } = await body<{ nonce: string; options: { challenge: string } }>(await f.request("/api/account/stepup/start", person, { action }))
    return f.request(path, person, { ...input, stepUp: { nonce, assertion: await assertion(person.passkey, options.challenge, ++person.counter) } })
  }
  const html = async (person: Person | undefined, path: string) => {
    const response = await f.request(path, person, undefined, HTML)
    expect(response.status, path).toBe(200)
    return response.text()
  }
  return { ...f, ui, uiSigned, accountSigned, html }
}

describe("people pages through the Worker", () => {
  it("people journey: invite, sign up, recovery, join, confirm, Connect an agent, enrol and admit", async () => {
    const f = await uiJourney()
    const people = await f.html(f.alex, "/w/northwind/people")
    expect(bootOf(people)).toMatchObject({ page: "people" })
    expect(people).toContain('data-form="invite"')

    // The invite form's terms, signed and sent as the page does.
    const built = buildInviteTerms({ role: "guest", binding: "open", email: "", teams: [], shares: [{ project: f.project.id, level: "edit", protected: false }], days: 7, confirmMyself: false }, Date.now())
    if (!built.ok) throw new Error(built.problems.join(" "))
    const made = await body<{ url: string }>(await f.uiSigned(f.alex, f.work, { type: "member.invite", terms: built.value }, "/invites", { terms: built.value, email: false }), 201)
    const code = made.url.split("#")[1]!
    expect(made.url).toBe(`https://vault.test/signup#${code}`)

    // A new account from the invitation, as /signup's client does.
    const signupPage = await f.html(undefined, "/signup")
    expect(bootOf(signupPage)).toEqual({ page: "workspace-signup", signedIn: false, recoveryReady: false })
    const passkey = await softwarePasskey()
    const { options } = await body<{ options: { challenge: string } }>(await f.request("/api/auth/signup/options", undefined, { invite: code, name: "Gina" }))
    const signed = await f.request("/api/auth/signup/verify", undefined, { invite: code, name: "Gina", response: await registration(passkey, options.challenge) })
    const gina: Person = { account: (await body<{ account: string }>(signed.clone())).account, cookie: signed.headers.get("set-cookie")!.split(";")[0]!, passkey, counter: 0, codes: [] }
    expect(bootOf(await f.html(gina, "/signup"))).toEqual({ page: "workspace-signup", signedIn: true, recoveryReady: false })
    // Joining before recovery is refused, as the vault requires.
    expect((await f.request("/api/account/invites/join", gina, { code })).status).toBe(403)

    // The recovery step: codes made, one typed back.
    const sheet = await body<{ batch: string; codes: string[]; confirmPosition: number }>(await f.accountSigned(gina, { type: "recovery.generate" }, "/api/account/recovery/generate", {}))
    expect(await body(await f.request("/api/account/recovery/confirm", gina, { batch: sheet.batch, code: sheet.codes[sheet.confirmPosition - 1] }))).toEqual({})
    expect(bootOf(await f.html(gina, "/signup"))).toEqual({ page: "workspace-signup", signedIn: true, recoveryReady: true })

    // Join, then wait: the account read shows the membership unconfirmed and
    // onboarding refuses until it is confirmed.
    const joined = await body<{ member: string; state: string }>(await f.request("/api/account/invites/join", gina, { code }))
    expect(joined.state).toBe("pending_confirmation")
    const waiting = await body<{ memberships: { member: string; status: string; workspace: WorkspaceRef }[] }>(await f.request("/api/account", gina))
    expect(waiting.memberships.find((m) => m.member === joined.member)?.status).toBe("unconfirmed")
    await refusal(await f.request(`/api/account/onboarding/${f.work.id}`, gina), 403, { error: "forbidden", message: "An owner or admin must confirm this membership before you connect an agent." })

    // Confirmation: the people page offers it, the vault returns the exact
    // action, and the page holds the very terms its digest names.
    const pending = await f.html(f.alex, "/w/northwind/people")
    expect(pending).toContain(`data-action="member-confirm" data-member="${joined.member}"`)
    expect(pending).toContain("Confirming activates Gina as Guest with exactly these terms.")
    const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.ui(f.alex, f.work, `/members/${joined.member}/action`, { change: "confirm" }))
    if (action.type !== "member.confirm") throw new Error("wrong action")
    expect(pending).toContain(`data-terms-digest="${action.termsDigest}"`)
    expect(await body(await f.uiSigned(f.alex, f.work, action, `/members/${joined.member}/confirm`, {}))).toMatchObject({ member: joined.member, status: "active", role: "guest" })

    // Confirmed: the waiting step's poll finds it active and onboarding
    // sends Gina straight to Connect an agent, at the canonical slug, so the
    // page answers at once with no redirect. The page itself writes nothing;
    // its client asks for one connect code on load, and a reload's code
    // replaces it, so never two live codes.
    const active = await body<{ memberships: { member: string; status: string; workspace: WorkspaceRef }[] }>(await f.request("/api/account", gina))
    const mine = active.memberships.find((m) => m.member === joined.member)!
    expect(mine.status).toBe("active")
    const { next } = await body<{ next: string }>(await f.request(`/api/account/onboarding/${mine.workspace.id}`, gina))
    expect(next).toBe("https://vault.test/w/northwind/connect-agent")
    const connect = await f.html(gina, new URL(next).pathname)
    expect(bootOf(connect)).toMatchObject({ page: "connect-agent" })
    const codes = () => f.db.prepare("SELECT code_hash FROM enrol_connect_codes WHERE account=?").bind(gina.account).all<{ code_hash: string }>().then((r) => r.results)
    expect(await codes()).toEqual([])
    await body(await f.ui(gina, f.work, "/connect-code", {}))
    const reloaded = await body<{ code: string }>(await f.ui(gina, f.work, "/connect-code", {}))
    expect(await codes()).toHaveLength(1)
    expect((await codes())[0]!.code_hash).toBe(await sha256Text(reloaded.code))
    expect(copied(connect)).toEqual([
      "Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace northwind at https://vault.test. I will approve it in my browser; never ask me for a key, password or secret.",
      "curl -fsSL https://mehen.dev/install | sh",
      "mehen setup",
      "mehen enrol --workspace northwind",
    ])
    for (const text of copied(connect)) expect(text).not.toContain("Northwind")

    // As a guest Gina sees no other people.
    const guestPeople = await f.html(gina, "/w/northwind/people")
    expect(guestPeople).toContain("You are a guest here.")
    expect(guestPeople).not.toMatch(/Alex|data-person=/)

    // Her machine: the enrolment page, the typed group, the planning
    // route's action, the accept; then Alex admits from his page's boot.
    const start = await f.startMachine(f.work)
    const enrolPage = await f.html(gina, `/w/northwind/e/${start.started.code}`)
    const boot = bootOf(enrolPage)
    expect(boot).toMatchObject({ page: "workspace-enrol", ref: start.started.code, role: "guest" })
    expect(enrolPage).not.toContain(start.thumbprint)
    expect(enrolPage).toContain("Accept as my own machine")
    const privateCredentials = /data-input="enrol-private" checked/.test(enrolPage)
    expect(privateCredentials).toBe(false)
    const planned = await body<{ action: WorkspaceStepUpAction }>(await f.ui(gina, f.work, `/enrolments/${start.started.code}/action`, { kind: "accept", group: start.group, privateCredentials }))
    expect(await body(await f.uiSigned(gina, f.work, planned.action, `/enrolments/${start.started.code}/accept`, { group: start.group, privateCredentials }))).toMatchObject({ state: "pending_admission" })
    expect(await f.html(gina, `/w/northwind/e/${start.started.code}`)).toContain("Your machine waits for admission.")
    const admitPage = await f.html(f.alex, `/w/northwind/e/${start.started.code}`)
    expect(admitPage).toContain("Admit Gina&#39;s machine")
    expect(admitPage).not.toContain('data-action="enrol-accept"')
    const admitBoot = bootOf(admitPage)
    const admit: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: String(admitBoot.enrolment), digest: String(admitBoot.digest), owner: admitBoot.owner as { kind: "member"; member: string; name: string }, admissionRole: admitBoot.role as "owner" }
    expect(await body(await f.uiSigned(f.alex, f.work, admit, `/enrolments/${start.started.code}/admit`, { group: start.group }))).toMatchObject({ state: "active" })

    // The machine's page, as the new-machine notice opens it.
    const { devices } = await body<{ devices: { device: string; name: string }[] }>(await f.ui(f.alex, f.work, "/devices"))
    const device = devices.find((d) => d.name === "integration-machine")!
    const machinePage = await f.html(f.alex, `/w/northwind/devices/${device.device}`)
    expect(machinePage).toContain('data-action="device-revoke"')
    expect(machinePage).toContain("Gina")
    expect(machinePage).toContain('data-region="start"')
    const ginaMachine = await f.html(gina, `/w/northwind/devices/${device.device}`)
    expect(ginaMachine).toContain('data-action="device-revoke"')
  })

  it("machine page: narrowing applies at once and revoking ends it, through the page's own planning calls", async () => {
    const f = await uiJourney()
    const machine = await f.machine(f.alex, f.work)
    const page = await f.html(f.alex, `/w/northwind/devices/${machine.device}`)
    const boot = bootOf(page) as { scope: import("@mehen/protocol").WorkspaceDeviceScope; device: string }
    const after = { ...boot.scope, modes: ["relay" as const], privateCredentials: false }
    const narrow = await body<{ action: WorkspaceStepUpAction }>(await f.ui(f.alex, f.work, `/devices/${boot.device}/action`, { change: { kind: "rescope", before: boot.scope, after } }))
    expect(await body(await f.uiSigned(f.alex, f.work, narrow.action, `/devices/${boot.device}/rescope`, { before: boot.scope, after }))).toEqual({ state: "committed", scope: after })
    const revoke = await body<{ action: WorkspaceStepUpAction }>(await f.ui(f.alex, f.work, `/devices/${boot.device}/action`, { change: { kind: "revoke" } }))
    expect((await f.uiSigned(f.alex, f.work, revoke.action, `/devices/${boot.device}/revoke`, {})).status).toBe(200)
    const after2 = await f.html(f.alex, `/w/northwind/devices/${boot.device}`)
    expect(after2).not.toContain('data-action="device-revoke"')
    expect(after2).toContain("It can no longer act.")
  })

  it("teams page and workspace creation render for an owner; the account page falls back to the directory's status", async () => {
    const f = await uiJourney()
    expect(bootOf(await f.html(undefined, "/recover"))).toEqual({ page: "recover", workspaces: true })
    const teams = await f.html(f.alex, "/w/northwind/teams")
    expect(teams).toContain('data-form="team-create"')
    const created = await f.accountSigned(f.alex, { type: "workspace.create", name: "Client", slug: "client-work" }, "/api/workspaces", { name: "Client", slug: "client-work" })
    expect(await body<WorkspaceRef>(created, 201)).toMatchObject({ slug: "client-work", name: "Client" })
    expect(await f.html(f.alex, "/workspaces/new")).toContain('data-form="workspace-create"')
    // Alex was allowed to create by the operator: the picker offers it.
    expect(await f.html(f.alex, "/workspaces")).toContain('href="/workspaces/new"')
    // With one workspace out of reach, /api/account cannot answer; the
    // account page shows the directory's own status instead of failing.
    f.faults.lostReply = "access.membership"
    const account = await f.request("/account", f.alex, undefined, HTML)
    expect(account.status).toBe(502)
    const text = await account.text()
    expect(text).toContain("Workspace security metadata is temporarily unavailable.")
    expect(text).toContain("A workspace could not answer just now.")
  })
})
