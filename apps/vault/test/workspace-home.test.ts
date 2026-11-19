// The workspace home through worker.fetch: this workspace's Needs you rows first, then the Get
// started card in the viewer's variant (owners and admins four steps,
// members two, guests one with the admission sentence), each step done from
// what the viewer's own reads show, and the lists in counts. No overview
// read, no Recently card, no count the viewer may not read.
import { describe, expect, it } from "vitest"
import { HOME_READS } from "../src/routes/ui.ts"
import { body, workJourney, type Person } from "./e2e/workspace-journey.ts"

type Journey = Awaited<ReturnType<typeof workJourney>>
const HTML = { accept: "text/html" }

async function home(f: Journey, person: Person, slug = "northwind"): Promise<string> {
  const response = await f.request(`/w/${slug}/`, person, undefined, HTML)
  expect(response.status).toBe(200)
  return response.text()
}

// The steps in the Get started card, each with whether it is done.
function steps(page: string): [string, boolean][] {
  const card = /data-region="get-started"[\s\S]*?<\/section>/.exec(page)?.[0] ?? ""
  return [...card.matchAll(/<li class="get-started-item( done)?">[\s\S]*?<a href="[^"]*">([^<]+)<\/a>/g)].map((m) => [m[2] ?? "", m[1] !== undefined])
}

async function people(f: Journey) {
  const mia = await f.guest(f.alex, f.work, f.project.id, "Mia")
  await body(await f.memberChange(f.alex, f.work, mia.member!, "role", "member"))
  const tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
  return { mia, tom }
}

describe("the workspace home", () => {
  it("reads only the inbox and the lists, with no overview and no Recently", () => {
    expect([...HOME_READS]).toEqual(["", "/inbox", "/devices", "/items", "/projects"])
  })

  it("gives an owner four steps, done from the owner's own reads, and drops the card once all are done", async () => {
    const f = await workJourney()
    const fresh = await home(f, f.alex, "alex")
    expect(steps(fresh)).toEqual([["Connect an agent", false], ["Add a credential", false], ["Invite a colleague", false], ["Create a project", false]])
    expect(fresh).toContain("Four short steps. This card goes away when they are done.")
    expect(fresh).toContain("Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace alex at https://vault.test.")
    expect(fresh).toContain('data-region="get-started" data-workspace="' + f.personal.id + '"')
    expect(fresh).not.toMatch(/Recently|\/overview|\/audit\?limit/)
    // In Northwind the project exists; then a machine, a credential and an invitation.
    expect(steps(await home(f, f.alex))).toEqual([["Connect an agent", false], ["Add a credential", false], ["Invite a colleague", false], ["Create a project", true]])
    await f.machine(f.alex, f.work)
    await f.credential(f.alex, f.work, "home-key", { kind: "workspace" })
    expect(steps(await home(f, f.alex))).toEqual([["Connect an agent", true], ["Add a credential", true], ["Invite a colleague", false], ["Create a project", true]])
    await f.invite(f.alex, f.work, { role: "member", email: "sam@northwind.example", teams: [], shares: [], expiresAt: new Date(Date.now() + 86_400_000).toISOString() })
    const done = await home(f, f.alex)
    expect(done).not.toContain('data-region="get-started"')
    expect(done).toMatch(/<b>1<\/b><span>Credentials<\/span>/)
    expect(done).toMatch(/<b>1<\/b><span>Machines<\/span><span class="stat-note">1 yours<\/span>/)
    expect(done).toMatch(/<b>1<\/b><span>Projects<\/span>/)
    expect(done).toMatch(/<b>1<\/b><span>People<\/span>/)
  })

  it("gives a member two steps and a guest one with who admits its machine, and no People count to a guest", async () => {
    const f = await workJourney()
    const { mia, tom } = await people(f)
    await f.credential(f.alex, f.work, "alex-own", { kind: "member", member: await f.member(f.alex, f.work) })
    const member = await home(f, mia)
    expect(steps(member)).toEqual([["Connect an agent", false], ["Add a credential", false]])
    expect(member).toContain("Two short steps.")
    expect(member).toMatch(/<b>3<\/b><span>People<\/span>/)
    const guest = await home(f, tom)
    expect(steps(guest)).toEqual([["Connect an agent", false]])
    expect(guest).toContain("One step.")
    expect(guest).toContain("An owner, an admin or a manager of the shared project admits a guest&#39;s machine before it can use anything.")
    expect(guest).not.toMatch(/<\/b><span>People<\/span>/)
    // Another member's machine never marks the viewer's own step done.
    await f.machine(f.alex, f.work)
    expect(steps(await home(f, mia))[0]).toEqual(["Connect an agent", false])
    await f.machine(mia, f.work)
    expect(steps(await home(f, mia))[0]).toEqual(["Connect an agent", true])
  })

  it("shows this workspace's rows first with See all, and never another workspace's", async () => {
    const f = await workJourney()
    const empty = await home(f, f.alex)
    expect(empty).toContain("Nothing needs you here")
    const start = await f.startMachine(f.work)
    const page = await home(f, f.alex)
    expect(page).toContain(`href="/w/northwind/e/${start.started.enrolment}">Accept</a>`)
    expect(page).toContain('href="/w/northwind/pending">See all')
    expect(page).not.toContain(start.thumbprint)
    expect(page).not.toContain(start.started.code)
    expect(await home(f, f.alex, "alex")).not.toContain(start.started.enrolment)
    // The account-wide count is never drawn by the server.
    expect(page).toContain('<b class="count" data-region="pending-count" data-fill hidden></b>')
    expect(page).toContain('href="/needs-you"')
  })
})
