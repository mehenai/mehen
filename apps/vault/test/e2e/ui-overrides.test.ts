// "Use my own" through the real Worker, driven the way the project page
// drives it: the page shows the control only on an exact, unprotected
// environment row, the browser picks its own credential by slug, the vault's
// action carries the stable id, the passkey signs it, the run uses the
// override, and clearing it puts the shared source back. A private-override
// run writes its audit event's private owner index, read back by the owner
// and hidden from another member. Refusals: a guest, a protected
// environment and someone else's private credential.
import { expect, it } from "vitest"
import { WorkspaceAuditPageSchema, type WorkspaceAuditPage, type WorkspaceRunCreated, type WorkspaceStepUpAction } from "@mehen/protocol"
import { setUpstreamFetch } from "../../src/relay/upstream.ts"
import { overrideChange, overrideOffered, projectCreate } from "../../src/ui/client/workspace-logic.ts"
import { body, journey, refusal, type Person } from "./workspace-journey.ts"
import { WS, page, projectSigned, uiSigned } from "./ui-projects-journey.ts"

// The work workspace and its platform project, keeping the journey's own
// helpers (workJourney replaces its project helper with the project).
async function workspaceJourney() {
  const f = await journey()
  await f.recoverySetup(f.alex)
  const work = await f.createWorkspace(f.alex, WS, "Northwind")
  const platform = await f.project(f.alex, work)
  return { ...f, work, platform }
}
type Journey = Awaited<ReturnType<typeof workspaceJourney>>


const NOT_FOUND = { error: "not_found", message: "No such object." }

async function whole(response: Response) {
  return { status: response.status, headers: [...response.headers].sort(), text: await response.text() }
}

// A project with TOKEN pointed at a workspace credential in dev and set in prod,
// Alex's own private credential, and a machine of Alex's that may reach it.
async function overridesJourney() {
  const f = await workspaceJourney()
  const alexMember = await f.member(f.alex, f.work)
  const shared = await f.credential(f.alex, f.work, "shared-key", { kind: "workspace" })
  const personal = await f.credential(f.alex, f.work, "personal-key", { kind: "member", member: alexMember })
  await body(await f.projectMutation(f.alex, f.work, "variable", { project: f.platform.id, env: "dev", name: "TOKEN", before: null, item: "shared-key", field: "key" }, `/projects/${f.platform.id}/vars/TOKEN`))
  // prod has its own TOKEN row (a plain value), so only its protection keeps Use my own away.
  await body(await f.projectMutation(f.alex, f.work, "variable", { project: f.platform.id, env: "prod", name: "TOKEN", before: null, plain: "https://prod.example.test" }, `/projects/${f.platform.id}/vars/TOKEN`))
  const projectPage = (person: Person) => page(f, `/w/${WS}/projects/${f.platform.id}`, person)
  const runInput = { project: f.platform.id, env: "dev", envSource: "flag", remote: null, worktree: "/fixture", head: null, vars: ["TOKEN"], command: "test", argv: ["test"] }
  return { ...f, alexMember, shared, personal, projectPage, runInput }
}

async function member(f: Journey, name: string) {
  const person = await f.guest(f.alex, f.work, f.platform.id, name)
  await body(await f.memberChange(f.alex, f.work, person.member!, "role", "member"))
  return person
}

async function audit(f: Journey, person: Person, query: string): Promise<WorkspaceAuditPage> {
  return WorkspaceAuditPageSchema.parse(await body(await f.request(`/api/w/${WS}/audit${query}`, person)))
}

it("Use my own: the page's control, a stable-id signature, a run on the override with its private owner indexed, then the shared source again", async () => {
  const f = await overridesJourney()
  // The control: dev has the exact TOKEN row and is unprotected; prod is
  // protected; staging has no TOKEN row.
  const shown = (await f.projectPage(f.alex)).text
  expect(shown).toContain(`data-override="dev/TOKEN"`)
  expect(shown).not.toContain(`data-override="prod/TOKEN"`)
  expect(shown).not.toContain(`data-override="staging/`)
  const ownForm = shown.slice(shown.indexOf('data-form="own" data-env="dev"'), shown.indexOf("</form>", shown.indexOf('data-form="own" data-env="dev"')))
  expect(ownForm).toContain('value="personal-key"')
  expect(ownForm).not.toContain('value="shared-key"')
  expect(shown).not.toContain("Your runs use your own")

  // The browser chooses by slug; the vault's action names the stable id.
  const change = overrideChange(f.platform.id, "dev", "TOKEN", { kind: "item", item: "personal-key", field: "key" })
  const prepared = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}${change.path}/action`, f.alex, change.body))
  expect(prepared).toEqual({ type: "override.set", project: f.platform.id, environment: "dev", variable: "TOKEN", source: { kind: "item", item: f.personal.id, field: "key" } })
  expect(change.matches(prepared)).toBe(true)
  const set = await body<{ overrides: unknown[] }>(await uiSigned(f, f.alex, f.work, { path: `${change.path}/action`, body: change.body }, change.matches, { path: change.path, body: change.body }))
  expect(set).toEqual({ overrides: [{ environment: "dev", variable: "TOKEN", source: { kind: "item", item: "personal-key", field: "key" }, updatedAt: expect.any(String) }] })
  expect(await f.sql(f.work, "SELECT item,field,plain FROM overrides")).toEqual([{ item: f.personal.id, field: "key", plain: null }])
  const after = (await f.projectPage(f.alex)).text
  expect(after).toContain("Your runs use your own <code>personal-key</code> instead.")
  expect(after).toContain('data-action="clear-own" data-env="dev" data-var="TOKEN"')

  // The run uses the override, and the relay injects the private secret.
  const machine = await f.machine(f.alex, f.work)
  const beforeRun = (await f.sql<{ seq: number }>(f.work, "SELECT COALESCE(MAX(seq),0) AS seq FROM audit"))[0]?.seq ?? 0
  const run = await body<WorkspaceRunCreated>(await f.deviceCall(machine, "/v1/runs", f.runInput), 201)
  expect(run.overrides).toEqual(["TOKEN"])
  const token = run.vars[0]
  if (token?.delivery !== "placeholder") throw new Error("Expected the override's placeholder")
  expect(token.item).toBe("personal-key")
  let sends = 0
  setUpstreamFetch(async (request) => { sends++; expect(request.headers.get("authorization")).toBe("Bearer sk-integration-not-a-real-secret"); return new Response("override-ok") })
  try {
    const relayed = await f.deviceCall(machine, "/v1/relay", { run: run.run, method: "GET", url: "https://api.openai.com/v1/models", headers: [["authorization", `Bearer ${token.value}`]] })
    expect(relayed.status).toBe(200)
    expect(await relayed.text()).toBe("override-ok")
  } finally { setUpstreamFetch(null) }
  expect(sends).toBe(1)

  // The private owner index: every private event the run wrote about Alex's
  // credential names Alex, and the hashed bytes stay minimal.
  const written = await f.sql<{ seq: number; detail: string; member: string | null }>(f.work, "SELECT a.seq,a.detail,o.member FROM audit a LEFT JOIN audit_private_owners o ON o.seq=a.seq WHERE a.seq>? AND a.target=? ORDER BY a.seq", beforeRun, f.personal.id)
  expect(written.length).toBeGreaterThan(0)
  for (const row of written) {
    expect(row.member, String(row.seq)).toBe(f.alexMember)
    expect(row.detail).not.toContain("sk-integration")
    expect(row.detail).not.toContain("api.openai.com")
  }
  const seqs = written.map((r) => r.seq)
  // The owner reads them; another member does not, and their filtered view
  // of this credential is the view of a credential that does not exist.
  const ownerView = await audit(f, f.alex, "?item=personal-key")
  for (const seq of seqs) expect(ownerView.events.map((e) => e.seq), String(seq)).toContain(seq)
  const tom = await member(f, "Tom")
  const tomAll = await audit(f, tom, "")
  for (const seq of seqs) expect(tomAll.events.map((e) => e.seq), String(seq)).not.toContain(seq)
  expect(JSON.stringify(tomAll.events)).not.toContain(f.personal.id)
  expect(await audit(f, tom, "?item=personal-key")).toEqual(await audit(f, tom, "?item=absent-key"))

  // Clear it the way the page's Stop using my own does; the next run uses
  // the shared source.
  const clear = overrideChange(f.platform.id, "dev", "TOKEN", null)
  expect(await body(await uiSigned(f, f.alex, f.work, { path: `${clear.path}/action`, body: clear.body }, clear.matches, { path: clear.path, body: clear.body }))).toEqual({ overrides: [] })
  expect((await f.projectPage(f.alex)).text).not.toContain("Your runs use your own")
  const sharedRun = await body<WorkspaceRunCreated>(await f.deviceCall(machine, "/v1/runs", f.runInput), 201)
  expect(sharedRun.overrides).toEqual([])
  expect(sharedRun.vars).toEqual([expect.objectContaining({ name: "TOKEN", delivery: "placeholder", item: "shared-key" })])
})

it("Use my own refuses a guest's reach beyond their own sources, the protected environment and another member's private credential", async () => {
  const f = await overridesJourney()
  const tom = await member(f, "Tom")
  const tomPrivate = await f.credential(tom, f.work, "tom-key", { kind: "member", member: tom.member! })
  const gina = await f.guest(f.alex, f.work, f.platform.id, "Gina")
  // Alex's own override exists, so its absence from others' views means something.
  const own = overrideChange(f.platform.id, "dev", "TOKEN", { kind: "item", item: "personal-key", field: "key" })
  await body(await uiSigned(f, f.alex, f.work, { path: `${own.path}/action`, body: own.body }, own.matches, { path: own.path, body: own.body }))
  // A project that is not shared with the guest.
  const create = projectCreate("hidden", "", [{ name: "dev", protected: false, fourEyes: false }, { name: "prod", protected: true, fourEyes: false }], "dev")
  if (!create.ok) throw new Error(create.problems.join(" "))
  const hidden = await body<{ id: string }>(await projectSigned(f, f.alex, f.work, create.value), 201)
  await body(await f.projectMutation(f.alex, f.work, "variable", { project: hidden.id, env: "dev", name: "TOKEN", before: null, item: "shared-key", field: "key" }, `/projects/${hidden.id}/vars/TOKEN`))
  const before = await f.snapshot(f.work)
  const prepare = (person: Person, project: string, input: unknown) => f.request(`/api/w/${WS}/projects/${project}/overrides/action`, person, input)
  const item = (slug: string) => ({ environment: "dev", variable: "TOKEN", source: { kind: "item", item: slug, field: "key" } })

  // A guest: never sees Alex's override or his credential, cannot name it,
  // and a project not shared with them answers as one that does not exist.
  const ginaPage = (await f.projectPage(gina)).text
  expect(ginaPage).not.toContain("personal-key")
  expect(ginaPage).not.toContain("Your runs use your own")
  expect(await body(await f.request(`/api/w/${WS}/projects/${f.platform.id}/overrides`, gina))).toEqual({ overrides: [] })
  const ginaAbsent = await whole(await prepare(gina, f.platform.id, item("absent-key")))
  expect(ginaAbsent.status).toBe(404)
  expect(await whole(await prepare(gina, f.platform.id, item("personal-key")))).toEqual(ginaAbsent)
  const plain = { environment: "dev", variable: "TOKEN", source: { kind: "plain", value: "https://example.test" } }
  expect(await whole(await prepare(gina, hidden.id, plain))).toEqual(await whole(await prepare(gina, "prj_absent000000", plain)))
  expect((await page(f, `/w/${WS}/projects/${hidden.id}`, gina)).text).not.toContain('data-override="')

  // The protected environment: no control on the page, and the vault refuses.
  const alexPage = (await f.projectPage(f.alex)).text
  expect(alexPage).not.toContain('data-override="prod/TOKEN"')
  const project = await body<{ environments: { name: string; protected: boolean }[]; vars: { env: string; name: string }[] }>(await f.request(`/api/w/${WS}/projects/${f.platform.id}`, f.alex))
  expect(overrideOffered(project, "prod", "TOKEN")).toBe(false)
  await refusal(await prepare(f.alex, f.platform.id, { ...item("personal-key"), environment: "prod" }), 403, { error: "forbidden", message: "You are not allowed to do that." })

  // Someone else's private credential, both ways round, answers exactly as
  // an absent one; a signature over the other member's stable id is refused.
  const tomAbsent = await whole(await prepare(tom, f.platform.id, item("absent-key")))
  expect(tomAbsent.status).toBe(404)
  expect(await whole(await prepare(tom, f.platform.id, item("personal-key")))).toEqual(tomAbsent)
  expect(await whole(await prepare(f.alex, f.platform.id, item("tom-key")))).toEqual(await whole(await prepare(f.alex, f.platform.id, item("absent-key"))))
  const forged: WorkspaceStepUpAction = { type: "override.set", project: f.platform.id, environment: "dev", variable: "TOKEN", source: { kind: "item", item: f.personal.id, field: "key" } }
  await refusal(await f.signed(`/api/w/${WS}/projects/${f.platform.id}/overrides`, tom, item("personal-key"), forged, WS), 404, NOT_FOUND)
  expect(JSON.stringify(await body(await f.request(`/api/w/${WS}/projects/${f.platform.id}/overrides`, tom)))).not.toContain("personal-key")
  expect(tomPrivate.id).not.toBe(f.personal.id)

  expect(await f.snapshot(f.work)).toEqual(before)
})

it("a plain Use my own value is never printed back: the page names it only as your own plain value, boot state included", async () => {
  const f = await overridesJourney()
  const SENTINEL = "PLAIN-OVERRIDE-MUST-NOT-BE-RENDERED"
  const change = overrideChange(f.platform.id, "dev", "TOKEN", { kind: "plain", value: SENTINEL })
  const set = await body<{ overrides: { source: { kind: string } }[] }>(await uiSigned(f, f.alex, f.work, { path: `${change.path}/action`, body: change.body }, change.matches, { path: change.path, body: change.body }))
  // The owner's own list still carries it; only the page never shows it.
  expect(set.overrides).toEqual([expect.objectContaining({ source: { kind: "plain", value: SENTINEL } })])
  const shown = await f.projectPage(f.alex)
  expect(shown.status).toBe(200)
  expect(shown.text).toContain('<p class="small" data-own-source="plain">Your runs use your own plain value instead.')
  expect(shown.text).toContain('data-action="clear-own" data-env="dev" data-var="TOKEN"')
  expect(shown.text).not.toContain(SENTINEL)
  const boot = shown.text.match(/data-boot="([^"]*)"/)?.[1] ?? ""
  expect(boot).not.toBe("")
  expect(boot).not.toContain(SENTINEL)
})
