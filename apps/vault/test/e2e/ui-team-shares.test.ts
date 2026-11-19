// Team share subjects on the project page, through the real Worker: an
// owner's share form offers every team by name and slug (duplicates told
// apart, a hostile name inert), a team share is made with the page's own
// share logic and read back under the team's name, and neither a guest nor
// a member who does not manage the project is shown any team. A member who
// manages the project narrows a machine-holding team's ending share through
// the page's form logic, keeping or shortening its end, and clearing the end
// is refused as the widening it is.
import { expect, it } from "vitest"
import { createProof, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, jwkThumbprint, webCryptoSigner, type ShareSubject, type TeamView, type WorkspaceStepUpAction } from "@mehen/protocol"
import { type ShareTerms, shareChange, shareEndChangeWords, shareEndDay, shareFormTerms } from "../../src/ui/client/workspace-logic.ts"
import { SHARE_NO_LONGER_ENDS_WORDS } from "../../src/ui/wording.ts"
import { newDeviceKey, publicJwk } from "../devices.ts"
import { ORIGIN } from "../helpers.ts"
import { body, journey, type Person } from "./workspace-journey.ts"
import { WS, page, projectSigned } from "./ui-projects-journey.ts"

// The work workspace and its platform project, keeping the journey's own
// helpers (workJourney replaces its project helper with the project).
async function workspaceJourney() {
  const f = await journey()
  await f.recoverySetup(f.alex)
  const work = await f.createWorkspace(f.alex, WS, "Northwind")
  const platform = await f.project(f.alex, work)
  return { ...f, work, platform }
}

const HOSTILE = "Ops\u202e\" <b>admin</b>\u0007"

async function teamsJourney() {
  const f = await workspaceJourney()
  const createTeam = async (name: string, slug: string) => {
    const { action } = await body<{ action: WorkspaceStepUpAction }>(await f.request(`/api/w/${WS}/teams/action`, f.alex, { kind: "create", name, slug }))
    if (action.type !== "team.update") throw new Error("Expected a team action")
    return body<TeamView>(await f.signed(`/api/w/${WS}/teams`, f.alex, { team: action.team, name, slug }, action, WS), 201)
  }
  const platform = await createTeam("Platform", "platform")
  const platformOps = await createTeam("Platform", "platform-ops")
  const hostile = await createTeam(HOSTILE, "ops-crew")
  const projectPage = async (person: Person) => (await page(f, `/w/${WS}/projects/${f.platform.id}`, person)).text
  return { ...f, teams: [platform, platformOps, hostile], projectPage }
}

it("team shares: the owner's form offers every team apart by slug, the team share is made and named, and the hostile name is inert", async () => {
  const f = await teamsJourney()
  const [platform, platformOps] = f.teams as [TeamView, TeamView, TeamView]
  const html = await f.projectPage(f.alex)
  const form = html.slice(html.indexOf('data-form="share"'), html.indexOf("</form>", html.indexOf('data-form="share"')))
  for (const team of f.teams) expect(form, team.slug).toContain(`value="${team.id}" data-kind="team"`)
  expect(form).toContain("Platform (team platform)")
  expect(form).toContain("Platform (team platform-ops)")
  expect(html).not.toContain("<b>admin</b>")
  expect(html).not.toContain("\u202e")
  expect(html).not.toContain("\u0007")

  // The page's share logic, for a team subject, through the existing route.
  const subject = { kind: "team" as const, team: platformOps.id }
  const after = { level: "use" as const, protected: false, expiresAt: null }
  await body(await projectSigned(f, f.alex, f.work, shareChange(f.platform.id, subject, null, after)))
  expect(await f.sql(f.work, "SELECT subject_kind,subject_id FROM project_shares WHERE subject_kind='team'")).toEqual([{ subject_kind: "team", subject_id: platformOps.id }])
  const shared = await f.projectPage(f.alex)
  const list = shared.slice(shared.indexOf('class="share-list"'), shared.indexOf("</ul>", shared.indexOf('class="share-list"')))
  expect(list).toContain("team Platform (platform-ops)")
  expect(list).not.toContain(`team Platform (platform)<`)
  // Unsharing names the same subject the page shows.
  expect(shared).toContain(`data-subject="{&quot;kind&quot;:&quot;team&quot;,&quot;team&quot;:&quot;${platformOps.id}&quot;}"`)
  expect(platform.id).not.toBe(platformOps.id)
})

it("team shares: a guest and a member who does not manage the project see no team at all", async () => {
  const f = await teamsJourney()
  await body(await projectSigned(f, f.alex, f.work, shareChange(f.platform.id, { kind: "team", team: f.teams[0]!.id }, null, { level: "use", protected: false, expiresAt: null })))
  const gina = await f.guest(f.alex, f.work, f.platform.id, "Gina")
  const tom = await f.guest(f.alex, f.work, f.platform.id, "Tom")
  await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "member"))
  for (const [who, person] of [["guest", gina], ["member", tom]] as const) {
    const html = await f.projectPage(person)
    expect(html, who).toContain('data-region="shares"')
    expect(html, who).not.toContain('data-form="share"')
    expect(html, who).not.toContain('data-kind="team"')
    for (const team of f.teams) {
      expect(html, `${who} ${team.slug}`).not.toContain(team.id)
      expect(html, `${who} ${team.slug}`).not.toContain(`(team ${team.slug})`)
    }
    expect(html, who).not.toContain("Platform")
  }
  // The guest's own read of the teams is refused outright.
  expect((await f.request(`/api/w/${WS}/teams`, gina)).status).toBe(403)
})

// The page's boot payload, as the browser code reads it.
function bootOf(text: string): { shares: { subject: ShareSubject; level: ShareTerms["level"]; protected: boolean; expiresAt: string | null }[] } {
  const raw = /data-boot="([^"]*)"/.exec(text)?.[1]
  if (raw === undefined) throw new Error("no boot payload")
  return JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&#96;", "`").replaceAll("&amp;", "&"))
}

it("team shares: a member manager narrows a machine-holding team's ending share through the form, and clearing its end is refused", async () => {
  const f = await teamsJourney()
  const team = f.teams[0]!
  const subject = { kind: "team" as const, team: team.id }
  // A workspace credential an unprotected environment uses, and a machine
  // the team owns: a wider share would delegate the credential to it.
  await f.credential(f.alex, f.work, "shared-key", { kind: "workspace" })
  await body(await f.projectMutation(f.alex, f.work, "variable", { project: f.platform.id, name: "TOKEN", env: "dev", item: "shared-key", field: "key", before: null }, `/projects/${f.platform.id}/vars/TOKEN`))
  const keys = await newDeviceKey(), jwk = await publicJwk(keys)
  const input = { workspace: WS, owner: { kind: "team", team: team.id }, name: "bot-runner", backend: "software", jwk }
  const proof = await createProof(webCryptoSigner("new", keys.privateKey), { method: "POST", url: `${ORIGIN}/v1/enrol`, body: JSON.stringify(input) }, { tenant: "enrol" })
  const started = await body<{ enrolment: string; code: string }>(await f.request("/v1/enrol", undefined, input, { "Mehen-Proof": proof }), 201)
  const view = await body<{ digest: string }>(await f.request(`/api/w/${WS}/enrolments/${started.code}`, f.alex))
  const group = fingerprintGroups(fingerprintOf(await jwkThumbprint(jwk)))[await fingerprintGroupIndex(started.code)]!
  const admit: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: started.enrolment, digest: view.digest, owner: { kind: "team", team: team.id, name: team.name }, admissionRole: "owner" }
  expect(await body(await f.signed(`/api/w/${WS}/enrolments/${started.code}/admit`, f.alex, { group }, admit, WS))).toMatchObject({ state: "active" })
  // The owner shares Edit with the team, ending in a week.
  const ends = new Date(Date.now() + 7 * 86_400_000).toISOString()
  await body(await projectSigned(f, f.alex, f.work, shareChange(f.platform.id, subject, null, { level: "edit", protected: false, expiresAt: ends })))
  // Tom: a member who manages the project through a direct share.
  const tom = await f.guest(f.alex, f.work, f.platform.id, "Tom")
  await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "member"))
  await body(await projectSigned(f, f.alex, f.work, shareChange(f.platform.id, { kind: "member", member: tom.member! }, { level: "edit", protected: true, expiresAt: null }, { level: "manage", protected: true, expiresAt: null })))

  // What Tom's page starts the form from, for the team.
  const shown = async () => {
    const text = await f.projectPage(tom)
    expect(text).toContain('data-input="ends"')
    const old = bootOf(text).shares.find((s) => s.subject.kind === "team" && s.subject.team === team.id)
    if (old === undefined) throw new Error("no team share on the page")
    return { level: old.level, protected: old.protected, expiresAt: old.expiresAt }
  }
  const before = await shown()
  expect(before).toEqual({ level: "edit", protected: false, expiresAt: ends })

  // Clearing the end is said before the passkey, and the vault refuses it
  // at preparation as a widening.
  const cleared = shareFormTerms(before, { level: "use", protected: false, ends: "" }, Date.now())
  if (!cleared.ok) throw new Error(cleared.problems.join(" "))
  expect(shareEndChangeWords(before, cleared.value)).toBe(SHARE_NO_LONGER_ENDS_WORDS)
  const widened = shareChange(f.platform.id, subject, before, cleared.value)
  const refused = await f.request(`/api/w/${WS}/projects/action`, tom, { change: widened.change, input: widened.input })
  expect(refused.status).toBe(403)
  expect(await refused.text()).toContain(`Only an owner or admin can share ${f.platform.slug} with a team that has a machine`)

  // Lowering the level with the end as the form started is accepted, the
  // end kept to the millisecond.
  const lowered = shareFormTerms(before, { level: "use", protected: false, ends: shareEndDay(before.expiresAt) }, Date.now())
  if (!lowered.ok) throw new Error(lowered.problems.join(" "))
  expect(lowered.value).toEqual({ level: "use", protected: false, expiresAt: ends })
  expect(shareEndChangeWords(before, lowered.value)).toBeNull()
  await body(await projectSigned(f, tom, f.work, shareChange(f.platform.id, subject, before, lowered.value)))
  const lowerShown = await shown()
  expect(lowerShown).toEqual({ level: "use", protected: false, expiresAt: ends })

  // Ending it two days sooner is accepted too, at 23:59 UTC that day.
  const sooner = new Date(Date.parse(ends) - 2 * 86_400_000).toISOString().slice(0, 10)
  const shortened = shareFormTerms(lowerShown, { level: "use", protected: false, ends: sooner }, Date.now())
  if (!shortened.ok) throw new Error(shortened.problems.join(" "))
  expect(shareEndChangeWords(lowerShown, shortened.value)).toBeNull()
  await body(await projectSigned(f, tom, f.work, shareChange(f.platform.id, subject, lowerShown, shortened.value)))
  expect(await shown()).toEqual({ level: "use", protected: false, expiresAt: `${sooner}T23:59:59.999Z` })
})
