// A run refused project_unshared over HTTP: the refusal links to
// the project's page, and the owner's Needs you gets one share request with
// a Share action that opens its Shared with form with the machine's owner
// chosen, however often the machine retries.
import { describe, expect, it } from "vitest"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import { body } from "./workspace-journey.ts"
import { WS, page, setup } from "./ui-projects-journey.ts"

describe("a run refused because the project is not shared", () => {
  it("links to the project and puts one share request in the owner's Needs you, which opens the share form", async () => {
    const f = await setup()
    const api = await f.project(f.alex, f.work, "api")
    const tom = await f.guest(f.alex, f.work, f.platform.id, "Tom")
    // A guest's machine is admitted by an owner before it may call.
    const start = await f.startMachine(f.work)
    await body(await f.acceptMachine(tom, f.work, start))
    const base = `/api/w/${WS}/enrolments/${start.started.code}`
    const view = await body<{ digest: string }>(await f.request(base, f.alex))
    const admit: WorkspaceStepUpAction = { type: "enrol.approve", enrolment: start.started.enrolment, digest: view.digest, owner: { kind: "member", member: tom.member!, name: "Tom" }, admissionRole: "owner" }
    await body(await f.signed(`${base}/admit`, f.alex, { group: start.group }, admit, WS))
    const active = await body<{ device: string }>(await f.deviceCall({ keys: start.keys, device: start.started.enrolment, workspace: f.work }, `/v1/enrol/${start.started.enrolment}`, undefined, "enrol"))
    const machine = { keys: start.keys, device: active.device, workspace: f.work }
    const run = { project: api.id, env: "dev", envSource: "flag", remote: null, worktree: "/share-request", head: null, vars: [], command: "true", argv: ["true"] }
    const link = `/w/${WS}/projects/${api.id}?share=${tom.member}`
    const refused = await body<{ error: string; next: { url: string } }>(await f.deviceCall(machine, "/v1/runs", run), 403)
    expect(refused).toMatchObject({ error: "project_unshared", next: { url: `https://vault.test/w/${WS}/projects/${api.id}` } })
    expect(await body(await f.deviceCall(machine, "/v1/runs", run), 403)).toEqual(refused)
    const rows = await f.sql<{ account: string }>(f.work, "SELECT account FROM notice_outbox WHERE payload LIKE '%project_share_requested%'")
    expect(rows).toEqual([{ account: f.alex.account }])
    const needs = (await page(f, "/needs-you", f.alex)).text
    expect(needs).toContain("could not start a run in api: the project is not shared with Tom")
    expect(needs).toContain(`<a class="btn primary sm" href="${link}" data-action="share-request">Share</a>`)
    const form = (await page(f, link, f.alex)).text
    expect(form).toMatch(new RegExp(`<option value="${tom.member}"[^>]* selected>`))
  })
})
