// Teams through the real Worker: the thin /teams forwarder, its planning
// route and every refusal, with the team's state read back from the DO.
import { describe, expect, it } from "vitest"
import type { TeamView, WorkspaceStepUpAction } from "@mehen/protocol"
import { body, refusal, workJourney } from "./workspace-journey.ts"

const NOT_ALLOWED = { error: "forbidden", message: "You are not allowed to do that." }
const PASSKEY_REFUSAL = { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." }

async function teamsJourney() {
  const f = await workJourney()
  // A member: an open guest, confirmed, then promoted (bound member invites
  // need the Google proof, which this release refuses).
  const tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
  expect(await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "member"))).toMatchObject({ role: "member", status: "active" })
  const guest = await f.guest(f.alex, f.work, f.project.id, "Gina")
  const plan = async (person: typeof tom, input: Record<string, unknown>) => body<{ action: WorkspaceStepUpAction }>(await f.request("/api/w/northwind/teams/action", person, input))
  const create = async (person: typeof tom, name: string, slug: string) => {
    const { action } = await plan(person, { kind: "create", name, slug })
    if (action.type !== "team.update") throw new Error("wrong action")
    return { action, response: await f.signed("/api/w/northwind/teams", person, { team: action.team, name, slug }, action, "northwind") }
  }
  const teamRows = () => f.sql<{ id: string; slug: string; name: string }>(f.work, "SELECT id,slug,name FROM teams ORDER BY slug")
  return { ...f, tom, guest, plan, create, teamRows }
}

describe("teams through the Worker", () => {
  it("teams: create, add a member, share a project to the team, read it back", async () => {
    const f = await teamsJourney()
    const { action, response } = await f.create(f.alex, "Platform", "platform")
    const created = await body<TeamView>(response, 201)
    expect(created).toEqual({ id: action.type === "team.update" ? action.team : "", slug: "platform", name: "Platform", members: [], shares: [], machines: 0 })
    expect(created.id).toMatch(/^tm_/)
    const add = await f.plan(f.alex, { kind: "members", team: created.id, member: f.tom.member, change: "add" })
    expect(add.action).toEqual({ type: "team.members", team: created.id, member: f.tom.member, change: "add" })
    const joined = await body<TeamView>(await f.signed(`/api/w/northwind/teams/${created.id}/members`, f.alex, { member: f.tom.member, change: "add" }, add.action, "northwind"))
    expect(joined.members).toEqual([{ member: f.tom.member, name: "Tom", role: "member" }])
    const share = { project: f.project.id, subject: { kind: "team", team: created.id }, before: null, after: { level: "use", protected: false, expiresAt: null } }
    await body(await f.projectMutation(f.alex, f.work, "share", share, `/projects/${f.project.id}/shares`))
    const { teams } = await body<{ teams: TeamView[] }>(await f.request("/api/w/northwind/teams", f.tom))
    expect(teams).toHaveLength(1)
    expect(teams[0]).toMatchObject({ id: created.id, members: [{ member: f.tom.member, name: "Tom", role: "member" }], shares: [{ project: f.project.id, subject: { kind: "team", team: created.id }, level: "use", protected: false, expiresAt: null }] })
    const members = await body<{ member: string; teams: string[] }[]>(await f.request("/api/w/northwind/members", f.alex))
    expect(members.find((m) => m.member === f.tom.member)?.teams).toEqual([created.id])
    const renamed = await f.plan(f.alex, { kind: "rename", team: created.id, name: "Platform team", slug: "platform-team" })
    expect(await body(await f.signed(`/api/w/northwind/teams/${created.id}/update`, f.alex, { change: "rename", name: "Platform team", slug: "platform-team" }, renamed.action, "northwind"))).toMatchObject({ slug: "platform-team", name: "Platform team" })
    const deleted = await f.plan(f.alex, { kind: "delete", team: created.id })
    expect(await body(await f.signed(`/api/w/northwind/teams/${created.id}/update`, f.alex, { change: "delete" }, deleted.action, "northwind"))).toEqual({ deleted: true, team: created.id })
    expect(await f.teamRows()).toEqual([])
  })

  it("teams: a guest cannot read, plan or change teams, and nothing changes", async () => {
    const f = await teamsJourney()
    const created = await body<TeamView>((await f.create(f.alex, "Platform", "platform")).response, 201)
    const before = await f.snapshot(f.work)
    await refusal(await f.request("/api/w/northwind/teams", f.guest), 403, NOT_ALLOWED)
    await refusal(await f.request("/api/w/northwind/teams/action", f.guest, { kind: "create", name: "Mine", slug: "mine" }), 403, NOT_ALLOWED)
    await refusal(await f.request("/api/w/northwind/teams/action", f.guest, { kind: "members", team: created.id, member: f.guest.member, change: "add" }), 403, NOT_ALLOWED)
    const forged: WorkspaceStepUpAction = { type: "team.members", team: created.id, member: f.guest.member!, change: "add" }
    await refusal(await f.signed(`/api/w/northwind/teams/${created.id}/members`, f.guest, { member: f.guest.member, change: "add" }, forged, "northwind"), 403, NOT_ALLOWED)
    expect(await f.snapshot(f.work)).toEqual(before)
  })

  it("teams: a member reads teams but cannot create, rename or add, and an owner cannot add a guest", async () => {
    const f = await teamsJourney()
    const created = await body<TeamView>((await f.create(f.alex, "Platform", "platform")).response, 201)
    expect(await body(await f.request("/api/w/northwind/teams", f.tom))).toEqual({ teams: [created] })
    const before = await f.snapshot(f.work)
    await refusal((await f.create(f.tom, "Rogue", "rogue")).response, 403, NOT_ALLOWED)
    const rename: WorkspaceStepUpAction = { type: "team.update", team: created.id, change: "rename", name: "Mine", slug: "mine" }
    await refusal(await f.signed(`/api/w/northwind/teams/${created.id}/update`, f.tom, { change: "rename", name: "Mine", slug: "mine" }, rename, "northwind"), 403, NOT_ALLOWED)
    const self: WorkspaceStepUpAction = { type: "team.members", team: created.id, member: f.tom.member!, change: "add" }
    await refusal(await f.signed(`/api/w/northwind/teams/${created.id}/members`, f.tom, { member: f.tom.member, change: "add" }, self, "northwind"), 403, NOT_ALLOWED)
    const guestAdd = await f.plan(f.alex, { kind: "members", team: created.id, member: f.guest.member, change: "add" })
    await refusal(await f.signed(`/api/w/northwind/teams/${created.id}/members`, f.alex, { member: f.guest.member, change: "add" }, guestAdd.action, "northwind"), 403, NOT_ALLOWED)
    expect(await f.snapshot(f.work)).toEqual(before)
  })

  it("teams: a stale or different signed action is refused before any change", async () => {
    const f = await teamsJourney()
    const created = await body<TeamView>((await f.create(f.alex, "Platform", "platform")).response, 201)
    const before = await f.snapshot(f.work)
    const signedRename = await f.plan(f.alex, { kind: "rename", team: created.id, name: "Old idea", slug: "old-idea" })
    await refusal(await f.signed(`/api/w/northwind/teams/${created.id}/update`, f.alex, { change: "rename", name: "New idea", slug: "new-idea" }, signedRename.action, "northwind"), 403, PASSKEY_REFUSAL)
    await refusal(await f.signed(`/api/w/northwind/teams/${created.id}/update`, f.alex, { change: "delete" }, signedRename.action, "northwind"), 403, PASSKEY_REFUSAL)
    const add = await f.plan(f.alex, { kind: "members", team: created.id, member: f.tom.member, change: "add" })
    await refusal(await f.signed(`/api/w/northwind/teams/${created.id}/members`, f.alex, { member: f.tom.member, change: "remove" }, add.action, "northwind"), 403, PASSKEY_REFUSAL)
    const { action } = await f.plan(f.alex, { kind: "create", name: "Second", slug: "second" })
    await refusal(await f.signed("/api/w/northwind/teams", f.alex, { team: created.id, name: "Second", slug: "second" }, action, "northwind"), 403, PASSKEY_REFUSAL)
    await refusal(await f.request(`/api/w/northwind/teams/${created.id}/update`, f.alex, { change: "delete" }), 403, PASSKEY_REFUSAL)
    expect(await f.snapshot(f.work)).toEqual(before)
    await refusal(await f.request("/api/w/northwind/teams/action", f.alex, { kind: "delete", team: "tm_NotATeam" }), 404, { error: "not_found", message: "No such available team." })
  })
})
