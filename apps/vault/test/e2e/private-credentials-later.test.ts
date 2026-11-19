// A member's machine accepted without private credentials (the enrol page
// ticks them for a member's own machine, and the member unticked it) can have
// them turned on later from its machine page, which the enrol page and the
// CLI's private-home refusal both point to: the
// page offers the tick to the machine's owner, the change becomes a proposal
// the same person accepts on the same page, and the machine may then ask in
// its owner's private home.
import { describe, expect, it } from "vitest"
import type { WorkspaceDeviceScope, WorkspaceStepUpAction } from "@mehen/protocol"
import { PRIVATE_OFF_WORDS } from "../../src/ui/pages/workspace-enrol.ts"
import { body, workJourney } from "./workspace-journey.ts"

const HTML = { accept: "text/html" }

function bootOf(page: string): Record<string, unknown> {
  const raw = /data-boot="([^"]*)"/.exec(page)?.[1]
  if (raw === undefined) throw new Error("no boot payload")
  return JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&#96;", "`").replaceAll("&amp;", "&")) as Record<string, unknown>
}

describe("turning private credentials on later for a member's own machine", () => {
  it("the machine page offers the tick to its owner, who proposes and accepts it there, and the machine may then ask privately", async () => {
    const f = await workJourney()
    const html = async (person: Parameters<typeof f.request>[1], path: string) => {
      const response = await f.request(path, person, undefined, HTML)
      expect(response.status, path).toBe(200)
      return response.text()
    }
    // A plain member: a member invitation is email-bound and needs Google,
    // so the journey's open guest invitation, confirmed, then made a member.
    const tom = await f.guest(f.alex, f.work, f.project.id, "Tom")
    expect(await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "member"))).toMatchObject({ role: "member", status: "active" })
    // The enrol page ticks it for a member's own machine and says where to turn it on if left off.
    const start = await f.startMachine(f.work)
    const enrolPage = await html(tom, `/w/northwind/e/${start.started.code}`)
    expect(enrolPage).toContain('data-input="enrol-private" checked>')
    expect(enrolPage).toContain("(on by default for your own machine)")
    expect(enrolPage).toContain("You can turn it on later from the machine&#39;s page.")
    expect(PRIVATE_OFF_WORDS).toContain("You can turn it on later from the machine's page.")
    // Tom unticks it and accepts the machine without private credentials.
    await body(await f.acceptMachine(tom, f.work, start, false))
    const [device] = await f.sql<{ id: string }>(f.work, "SELECT id FROM devices WHERE enrolment=?", start.started.enrolment)
    const machine = { keys: start.keys, device: device!.id, workspace: f.work }
    const ask = { kind: "api-key", slug: "tom-openai", provider: "openai", reason: "The agent needs OpenAI.", home: "private" }
    expect((await f.deviceCall(machine, "/v1/intakes", ask)).status).toBeGreaterThanOrEqual(400)
    // The machine's page offers its owner the tick, enabled, in the change form.
    const path = `/w/northwind/devices/${device!.id}`
    const page = await html(tom, path)
    const boot = bootOf(page) as { scope: WorkspaceDeviceScope; propose: boolean }
    expect(boot.propose).toBe(true)
    expect(boot.scope.privateCredentials).toBe(false)
    expect(page).toContain("<span>Change what it may use</span>")
    expect(page).toContain(`<input type="checkbox" data-input="scope-private"><span>It may use my private credentials</span>`)
    expect(page).not.toContain("Tom's private credentials")
    // Anyone else who may change it reads whose private credentials they are.
    const alexView = await html(f.alex, path)
    expect(alexView).toContain(`<input type="checkbox" data-input="scope-private"><span>It may use Tom's private credentials</span>`)
    expect(alexView).not.toContain("my private credentials")
    expect(page).toContain("Tom must accept it on their own machine.")
    expect(page).toContain("<span>Sign the change with passkey</span>")
    // Ticking it is wider, so it is a proposal Tom then accepts on the same page.
    const wider = { ...boot.scope, privateCredentials: true }
    const base = `/api/w/northwind/devices/${device!.id}`
    const planned = await body<{ action: WorkspaceStepUpAction }>(await f.request(`${base}/action`, tom, { change: { kind: "rescope_propose", before: boot.scope, after: wider } }))
    const proposal = await body<{ id: string; state: string }>(await f.signed(`${base}/rescope`, tom, { before: boot.scope, after: wider }, planned.action, f.work.slug))
    expect(proposal.state).toBe("open")
    const offered = await html(tom, path)
    expect(offered).toContain("A wider scope is waiting")
    expect(offered).toContain(`data-action="rescope-accept" data-proposal="${proposal.id}"`)
    expect(offered).toContain("<span>Accept this scope on my own machine</span>")
    const accept = await body<{ action: WorkspaceStepUpAction }>(await f.request(`${base}/action`, tom, { change: { kind: "rescope_accept", proposal: proposal.id } }))
    expect(await body(await f.signed(`${base}/rescope-accept`, tom, { proposal: proposal.id }, accept.action, f.work.slug))).toMatchObject({ state: "committed" })
    expect(await body<{ scope: WorkspaceDeviceScope }>(await f.deviceCall(machine, "/v1/me"))).toMatchObject({ scope: { privateCredentials: true } })
    expect(await body(await f.deviceCall(machine, "/v1/intakes", ask), 201)).toMatchObject({ intake: expect.stringMatching(/^int_/) })
    expect(await html(tom, path)).toMatch(/Yes: it may use its owner(&#39;|')s private credentials/)
  })
})
