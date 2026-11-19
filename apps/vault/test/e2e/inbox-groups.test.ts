// Grouped asks through the real Worker (batch approvals, design 4): a
// review group's row links to /w/<slug>/g/<id>, Review together, which
// lists that group's asks and links each to its own page. An unknown group
// reads as an empty one; the page is behind APPROVAL_BATCHES. A machine's approval_required names the group only to
// a mehen that reads it, judged from its User-Agent.
import { describe, expect, it } from "vitest"
import { env } from "cloudflare:workers"
import { runInDurableObject } from "cloudflare:test"
import { createProof, webCryptoSigner, type WorkspacePendingAsk } from "@mehen/protocol"
import type { InboxItem, WorkspaceInboxResponse } from "@mehen/protocol/inbox"
import { type Machine, body } from "./workspace-journey.ts"
import { WS, addCredential, page, setup } from "./ui-projects-journey.ts"
import { type ReviewRowBoot, reviewBatchMatches, reviewBindingMismatches, reviewChoices } from "../../src/ui/client/workspace-logic.ts"
import { nativeSession } from "./oidc-journey.ts"

type Journey = Awaited<ReturnType<typeof setup>>
// APPROVAL_BATCHES for the Worker's routes and the workspace's vault alike.
async function switchBatches(f: Journey, value: string) {
  f.env.APPROVAL_BATCHES = value
  await runInDurableObject(env.TENANT_VAULT.getByName(f.work.id), (instance) => { instance.context.env = { ...instance.context.env, APPROVAL_BATCHES: value } })
}
const askIds = (items: InboxItem[]) => items.flatMap((item) => item.kind === "ask" && item.ask.view === "detail" ? [item.ask.detail.id] : []).sort()

async function asks(f: Journey) {
  await addCredential(f, f.alex, f.work, "openai-dev", { kind: "workspace" })
  const machine = await f.machine(f.alex, f.work), other = await f.machine(f.alex, f.work)
  const ask = async (on: typeof machine, file: string) => (await body<{ approval: string }>(await f.deviceCall(on, "/v1/relay", { item: "openai-dev", method: "DELETE", url: `https://api.openai.com/v1/files/${file}`, headers: [] }), 409)).approval
  const grouped = [await ask(machine, "file-one"), await ask(machine, "file-two")].sort()
  const alone = await ask(other, "file-three")
  const [row] = await f.sql<{ review_group: string }>(f.work, "SELECT review_group FROM approvals WHERE id=?", grouped[0]!)
  return { grouped, alone, group: row!.review_group }
}

describe("a review group's page, Review together", () => {
  it("links the group row to /g/<id>, which lists that group's asks with their own pages' links, and an unknown group as an empty one", async () => {
    const f = await setup()
    const { grouped, alone, group } = await asks(f)
    const inbox = await body<WorkspaceInboxResponse>(await f.request(`/api/w/${WS}/inbox`, f.alex))
    expect(inbox.items.map((item) => item.kind === "group" ? [item.href, item.group.count] : askIds([item]))).toEqual(expect.arrayContaining([[`/w/${WS}/g/${group}`, 2], [alone]]))
    const filtered = await body<WorkspaceInboxResponse>(await f.request(`/api/w/${WS}/inbox?group=${group}`, f.alex))
    expect(askIds(filtered.items)).toEqual(grouped)
    expect(filtered.items.every((item) => item.kind === "ask")).toBe(true)
    expect(filtered.notices).toEqual([])
    const unknown = await body<WorkspaceInboxResponse>(await f.request(`/api/w/${WS}/inbox?group=grp_AAAAAAAAAAAAAAAAAAAAAA`, f.alex))
    expect(unknown).toEqual({ ...filtered, workspace: { ...filtered.workspace, count: 0 }, items: [] })
    const shown = await page(f, `/w/${WS}/g/${group}`, f.alex)
    expect(shown.status).toBe(200)
    for (const id of grouped) expect(shown.text).toContain(`/w/${WS}/a/${id}`)
    expect(shown.text).not.toContain(alone)
    expect((await page(f, `/w/${WS}/g/grp_AAAAAAAAAAAAAAAAAAAAAA`, f.alex)).status).toBe(200)
    expect((await page(f, `/w/${WS}/g/not-a-group`, f.alex)).status).toBe(404)
  })

  it("boots each row with what its digest recomputes from, and the vault's batch action is exactly what the page's script expects", async () => {
    const f = await setup()
    const { grouped, group } = await asks(f)
    const shown = await page(f, `/w/${WS}/g/${group}`, f.alex)
    const raw = /data-boot="([^"]+)"/.exec(shown.text)?.[1] ?? "{}"
    const boot = JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&amp;", "&")) as { page: string; group: string; etag: string | null; rows: ReviewRowBoot[] }
    expect(boot.page).toBe("ws-review")
    expect(boot.group).toBe(group)
    // The group's validator as drawn: the script's first poll is a 304 while nothing changed.
    const read = await f.request(`/api/w/${WS}/approvals/groups/${group}`, f.alex)
    expect(boot.etag).toBe(read.headers.get("etag"))
    expect((await f.request(`/api/w/${WS}/approvals/groups/${group}`, f.alex, undefined, { "if-none-match": boot.etag ?? "" })).status).toBe(304)
    expect(boot.rows.map((r) => r.approval).sort()).toEqual(grouped)
    expect(await reviewBindingMismatches(boot.rows)).toEqual([])
    for (const decision of ["approve", "deny"] as const) {
      const choices = reviewChoices(boot.rows, new Set(grouped), decision)
      expect(choices.map((c) => c.approval), decision).toEqual(grouped)
      const action = await body<unknown>(await f.request(`/api/w/${WS}/approval-batch/action`, f.alex, { entries: choices.map((c) => ({ id: c.approval, decision: c.decision })) }))
      expect(reviewBatchMatches(boot.rows, choices, action), decision).toBe(true)
    }
  })

  it("says nothing waits in the group, with how many were decided in the last hour, never speaking for the whole workspace", async () => {
    const f = await setup()
    const { grouped, alone, group } = await asks(f)
    for (const id of grouped) await f.sql(f.work, "UPDATE approvals SET status='denied', decided_at=? WHERE id=?", Date.now(), id)
    expect((await page(f, `/w/${WS}/g/${group}`, f.alex)).text).toContain("Nothing waiting here. 2 decided in the last hour.")
    for (const path of [`/w/${WS}/g/${group}`, `/w/${WS}/g/grp_AAAAAAAAAAAAAAAAAAAAAA`]) {
      const shown = await page(f, path, f.alex)
      expect(shown.status, path).toBe(200)
      expect(shown.text, path).toContain("Nothing waiting here.")
      expect(shown.text, path).toContain(`href="/w/${WS}/pending"`)
      expect(shown.text, path).not.toContain("Nothing is waiting for you in")
      expect(shown.text, path).not.toContain("What you may decide or stop in this workspace")
      expect(shown.text, path).not.toContain(alone)
    }
    const whole = await page(f, `/w/${WS}/pending`, f.alex)
    expect(whole.text).toContain("What you may decide or stop in this workspace")
    expect(whole.text).toContain(`/w/${WS}/a/${alone}`)
  })

  it("is not found, the page and the ?group= read alike, with APPROVAL_BATCHES off or in a managed workspace", async () => {
    const f = await setup()
    const { group } = await asks(f)
    const notFound = async (why: string) => {
      const read = await f.request(`/api/w/${WS}/inbox?group=${group}`, f.alex)
      expect(read.status, why).toBe(404)
      expect(await read.json(), why).toMatchObject({ error: "not_found" })
      expect((await page(f, `/w/${WS}/g/${group}`, f.alex)).status, why).toBe(404)
      expect((await f.request(`/api/w/${WS}/inbox`, f.alex)).status, why).toBe(200)
    }
    const was = f.env.APPROVAL_BATCHES
    await switchBatches(f, "off")
    await notFound("switch off")
    await switchBatches(f, was ?? "on")
    await f.sql(f.work, "INSERT INTO tenant_state(key,value) VALUES ('managed',?)", JSON.stringify({ platform: "plt_test", subject: "sub_test", member: "mem_test", createdAt: 0 }))
    await notFound("managed")
  })
})

describe("the native app's read with batch approvals on", () => {
  it("keeps two asks of one review group as two asks in /app/v1/pending, its pending equal to the workspace's own list", async () => {
    const f = await setup()
    const { grouped, alone, group } = await asks(f)
    const web = await body<WorkspaceInboxResponse>(await f.request(`/api/w/${WS}/inbox`, f.alex))
    expect(web.items.some((item) => item.kind === "group" && item.group.group === group)).toBe(true)
    const native = await nativeSession(f)
    const app = await body<{ pending: WorkspacePendingAsk[]; inbox: InboxItem[] }>(await f.request("/app/v1/pending", undefined, undefined, native.headers))
    const listed = await body<{ pending: WorkspacePendingAsk[] }>(await f.request(`/api/w/${WS}/pending`, f.alex))
    expect(app.pending).toEqual(listed.pending)
    expect(app.pending.flatMap((ask) => ask.view === "detail" && ask.detail.kind === "approval" ? [ask.detail.id] : []).sort()).toEqual([...grouped, alone].sort())
    expect(app.inbox.map((item) => item.kind)).toEqual(["ask", "ask", "ask"])
    expect(askIds(app.inbox)).toEqual([...grouped, alone].sort())
  })
})

describe("approval_required through the Worker", () => {
  it("names the ask's review group to mehen/0.3.17 and to nothing older or unnamed, with next.url the ask's own page", async () => {
    const f = await setup()
    await addCredential(f, f.alex, f.work, "openai-dev", { kind: "workspace" })
    const machine = await f.machine(f.alex, f.work)
    const relay = async (on: Machine, file: string, userAgent: string | null) => {
      const path = "/v1/relay", input = { item: "openai-dev", method: "DELETE", url: `https://api.openai.com/v1/files/${file}`, headers: [] }
      const proof = await createProof(webCryptoSigner(on.device, on.keys.privateKey), { method: "POST", url: `https://vault.test${path}`, body: JSON.stringify(input) }, { tenant: on.workspace.id })
      return body<{ approval: string; next: { url: string }; group?: unknown }>(await f.request(path, undefined, input, { "Mehen-Proof": proof, ...(userAgent === null ? {} : { "user-agent": userAgent }) }), 409)
    }
    const first = await relay(machine, "file-one", "mehen/0.3.17")
    const [row] = await f.sql<{ review_group: string }>(f.work, "SELECT review_group FROM approvals WHERE id=?", first.approval)
    expect(first.group).toEqual({ id: row!.review_group, url: `https://vault.test/w/${WS}/g/${row!.review_group}`, open: 1 })
    expect(first.next.url).toBe(`https://vault.test/w/${WS}/a/${first.approval}`)
    for (const [file, agent] of [["file-two", "mehen/0.3.16"], ["file-three", null], ["file-four", "curl/8.0"]] as const) expect(await relay(machine, file, agent), String(agent)).not.toHaveProperty("group")
    expect((await relay(machine, "file-five", "mehen/0.3.17")).group).toMatchObject({ open: 5 })
  })
})
