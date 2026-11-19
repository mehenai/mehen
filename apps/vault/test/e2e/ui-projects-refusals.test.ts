// The projects pages' refusals through the real Worker: hidden connects in
// every state, guests and settled decisions, a replacement credential under
// an old page, the exact request on a readable approval, editors and
// workspace sources, truthful audit sentences, plain variables and OAuth
// dependants. Every request goes through worker.fetch.
import { afterEach, describe, expect, it } from "vitest"
import type { CredentialHome, WorkspaceApprovalView, WorkspaceProject, WorkspaceStepUpAction } from "@mehen/protocol"
import { setUpstreamFetch } from "../../src/relay/upstream.ts"
import { credentialStart, environmentChange, itemChangedRefusal, itemDeleteAction, sameAction, variableChange } from "../../src/ui/client/workspace-logic.ts"
import { body, refusal } from "./workspace-journey.ts"
import { WS, addCredential, completeConnect, page, projectSigned, setup } from "./ui-projects-journey.ts"

afterEach(() => setUpstreamFetch(null))

type Journey = Awaited<ReturnType<typeof setup>>

async function whole(response: Response) {
  return { status: response.status, headers: [...response.headers].sort(), text: await response.text() }
}

async function member(f: Journey, name: string) {
  const person = await f.guest(f.alex, f.work, f.platform.id, name)
  await body(await f.memberChange(f.alex, f.work, person.member!, "role", "member"))
  return person
}

async function counts(f: Journey) {
  return {
    challenges: await f.db.prepare("SELECT COUNT(*) AS n FROM challenges").first<{ n: number }>(),
    states: await f.db.prepare("SELECT COUNT(*) AS n FROM oauth_states").first<{ n: number }>(),
  }
}

describe("hidden connects", () => {
  it("connect preparation answers a foreign private request in every state exactly as an absent id", async () => {
    const f = await setup()
    const kim = await member(f, "Kim")
    const alexHome: CredentialHome = { kind: "member", member: await f.member(f.alex, f.work) }
    const prepare = (id: string) => f.request(`/api/w/${WS}/connect/${id}/action`, kim, { home: alexHome })
    const absent = await whole(await prepare("con_absent"))
    expect(absent.status).toBe(404)
    // The client exists first, so the later requests need no client intake.
    const completed = await completeConnect(f, f.alex, f.work, "alex-gmail-done", alexHome, "alex-done")
    const open = await body<{ connect: string }>(await f.request(`/api/w/${WS}/connect`, f.alex, credentialStart("google-gmail", "connect", "alex-gmail-open", alexHome).body), 201)
    const cancelled = await body<{ connect: string }>(await f.request(`/api/w/${WS}/connect`, f.alex, credentialStart("google-gmail", "connect", "alex-gmail-cancelled", alexHome).body), 201)
    await body(await f.request(`/api/w/${WS}/connect/${cancelled.connect}/cancel`, f.alex, {}))
    const expired = await body<{ connect: string }>(await f.request(`/api/w/${WS}/connect`, f.alex, credentialStart("google-gmail", "connect", "alex-gmail-expired", alexHome).body), 201)
    // Injected state: the request's deadline passes.
    await f.sql(f.work, "UPDATE workspace_credential_requests SET expires_at=1 WHERE id=?", expired.connect)
    const start = await counts(f)
    for (const id of [open.connect, cancelled.connect, expired.connect, completed]) {
      expect(await whole(await prepare(id)), id).toEqual({ ...absent, text: absent.text })
      // The same through start, which a hidden request must not reach either.
      expect(await whole(await f.request(`/api/w/${WS}/connect/${id}/start`, kim, { home: alexHome, stepUp: { nonce: "x", assertion: {} } })), id).toEqual(await whole(await f.request(`/api/w/${WS}/connect/con_absent/start`, kim, { home: alexHome, stepUp: { nonce: "x", assertion: {} } })))
    }
    expect(await counts(f)).toEqual(start)
  })
})

describe("guests and settled decisions", () => {
  it("a guest's own settled asks, denied and approved, never name who decided", async () => {
    const f = await setup()
    const sam = await member(f, "Sam")
    const machine = await f.protectedMachine(sam, f.work)
    await body(await f.memberChange(f.alex, f.work, sam.member!, "role", "guest"))
    const ask = async (argv: string[]) => (await body<{ approval: string }>(await f.deviceCall(machine, "/v1/runs", { project: f.platform.id, env: "prod", envSource: "flag", remote: null, worktree: "/guest", head: null, vars: [], command: argv.join(" "), argv }), 409)).approval
    const decide = async (id: string, decision: "approve" | "deny") => {
      const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/approvals/${id}/action`, f.alex, { decision }))
      await body(await f.signed(`/api/w/${WS}/approvals/${id}/decide`, f.alex, { decision }, action, WS))
    }
    const denied = await ask(["node", "denied.js"])
    await decide(denied, "deny")
    const approved = await ask(["node", "approved.js"])
    await decide(approved, "approve")
    for (const id of [denied, approved]) {
      const json = await body<WorkspaceApprovalView>(await f.request(`/api/w/${WS}/approvals/${id}`, sam))
      if (json.view !== "detail") throw new Error("Expected the guest's own detail view")
      expect(json.approval.decidedBy).toEqual({ name: null, self: false })
      expect(JSON.stringify(json)).not.toContain("Alex")
      const html = (await page(f, `/w/${WS}/a/${id}`, sam)).text
      expect(html, id).toContain('data-region="settled"')
      expect(html, id).not.toContain("Alex")
      // An insider still sees who decided.
      expect((await page(f, `/w/${WS}/a/${id}`, f.alex)).text).toContain("by you")
    }
  })
})

describe("an old item page and a replacement credential", () => {
  it("the old page's delete signature is refused for the replacement, which survives; the page refuses before signing", async () => {
    const f = await setup()
    await addCredential(f, f.alex, f.work, "reused-key", { kind: "workspace" })
    const shown = await body<{ id: string; kind: string; version: number; configRevision: number; dependencyRevision: number }>(await f.request(`/api/w/${WS}/items/reused-key`, f.alex))
    const oldPage = (await page(f, `/w/${WS}/items/reused-key`, f.alex)).text
    expect(oldPage).toContain(`&quot;id&quot;:&quot;${shown.id}&quot;`)
    // The old page prepares and signs its delete, but does not send it yet.
    const oldAction = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/items/reused-key/action`, f.alex, { action: "delete" }))
    expect(oldAction).toEqual(itemDeleteAction(shown))
    const oldProof = await f.proof(f.alex, oldAction, WS)
    // Another tab deletes it and makes a new credential under the same name.
    const other = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/items/reused-key/action`, f.alex, { action: "delete" }))
    await body(await f.signed(`/api/w/${WS}/items/reused-key/delete`, f.alex, {}, other, WS))
    await addCredential(f, f.alex, f.work, "reused-key", { kind: "workspace" })
    const [replacement] = await f.sql<{ id: string }>(f.work, "SELECT id FROM items WHERE slug='reused-key'")
    expect(replacement?.id).not.toBe(shown.id)
    // At the server: the old signature cannot delete the replacement.
    const before = await f.snapshot(f.work)
    expect((await f.request(`/api/w/${WS}/items/reused-key/delete`, f.alex, { stepUp: oldProof })).status).toBe(403)
    expect(await f.snapshot(f.work)).toEqual(before)
    // At the page: the preparation is not the shown action, and the fresh
    // read is another credential, so neither the step-up nor the passkey runs.
    const challenges = await f.db.prepare("SELECT COUNT(*) AS n FROM challenges").first<{ n: number }>()
    const now = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/items/reused-key/action`, f.alex, { action: "delete" }))
    expect(sameAction(itemDeleteAction(shown), now)).toBe(false)
    expect(itemChangedRefusal(shown, await body(await f.request(`/api/w/${WS}/items/reused-key`, f.alex)))?.message).toBe("This name now belongs to a different credential than the one this page showed.")
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM challenges").first<{ n: number }>()).toEqual(challenges)
    expect(await f.sql(f.work, "SELECT id FROM items WHERE slug='reused-key'")).toEqual([{ id: replacement!.id }])
  })
})

describe("the exact request on a readable approval", () => {
  it("shows every signed header with its digest, the body digest and the stored warnings", async () => {
    const f = await setup()
    await addCredential(f, f.alex, f.work, "openai-dev", { kind: "workspace" })
    const machine = await f.machine(f.alex, f.work)
    const asked = await f.deviceCall(machine, "/v1/relay", { item: "openai-dev", method: "DELETE", url: "https://api.openai.com/v1/files/file-ui-probe", headers: [["X-Ui-Probe", "SIGNED-HEADER-VALUE"]] })
    const error = await body<{ error: string; approval: string }>(asked, 409)
    expect(error.error).toBe("approval_required")
    const view = await body<WorkspaceApprovalView>(await f.request(`/api/w/${WS}/approvals/${error.approval}`, f.alex))
    if (view.view !== "detail") throw new Error("detail")
    const html = (await page(f, `/w/${WS}/a/${error.approval}`, f.alex)).text
    const shown = html.slice(html.indexOf('<div id="notice"'), html.indexOf("</main>"))
    for (const value of ["x-ui-probe", "SIGNED-HEADER-VALUE", "Headers sent with the request", view.approval.request.headersSha256, view.approval.request.bodySha256, "DELETE", "https://api.openai.com/v1/files/file-ui-probe"]) expect(shown, value).toContain(value)
    for (const warning of view.approval.warnings) expect(shown).toContain(warning)
    // The page's own digest check covers the headers it now shows.
    expect(html).toContain(`&quot;headers&quot;:[[&quot;accept-encoding&quot;`)
  })
})

describe("project controls the vault agrees with", () => {
  it("an editor of a guest-shared project, without the share list, is offered no workspace source", async () => {
    const f = await setup()
    await addCredential(f, f.alex, f.work, "workspace-key", { kind: "workspace" })
    await f.guest(f.alex, f.work, f.platform.id, "Sam")
    const kim = await member(f, "Kim")
    const html = (await page(f, `/w/${WS}/projects/${f.platform.id}`, kim)).text
    expect(html).not.toContain('value="workspace-key" data-home="workspace"')
    expect(html).toContain('data-form="var"')
    expect(html).toContain("Ask a manager of this project, or an owner or admin, to point a variable here at a workspace credential.")
    const change = variableChange(f.platform.id, "dev", "TOKEN", null, { kind: "item", item: "workspace-key", field: "key" })
    expect((await f.request(`/api/w/${WS}/projects/action`, kim, { change: change.change, input: change.input })).status).toBe(403)
    // A plain value is still an allowed source for this editor.
    const plain = variableChange(f.platform.id, "dev", "LOG_LEVEL", null, { kind: "plain", value: "info" })
    expect(sameAction(await plain.expected, await body(await f.request(`/api/w/${WS}/projects/action`, kim, { change: plain.change, input: plain.input })))).toBe(true)
  })

  it("an existing plain variable can be replaced and cleared from the page, and a stale one refuses", async () => {
    const f = await setup()
    await body(await projectSigned(f, f.alex, f.work, variableChange(f.platform.id, "dev", "LOG_LEVEL", null, { kind: "plain", value: "info" })))
    const boot = (await page(f, `/w/${WS}/projects/${f.platform.id}`, f.alex)).text
    expect(boot).toContain('<code data-plain>info</code>')
    expect(boot).toContain('&quot;plain&quot;:&quot;info&quot;')
    await body(await projectSigned(f, f.alex, f.work, variableChange(f.platform.id, "dev", "LOG_LEVEL", { kind: "plain", value: "info" }, { kind: "plain", value: "debug" })))
    // Another tab already changed it: the page's before-state is stale.
    const stale = variableChange(f.platform.id, "dev", "LOG_LEVEL", { kind: "plain", value: "info" }, { kind: "plain", value: "warn" })
    await refusal(await f.request(`/api/w/${WS}/projects/action`, f.alex, { change: stale.change, input: stale.input }), 409, { error: "conflict", message: "The expected state changed.", next: { say: "Reload this page and review the change again." } })
    await body(await projectSigned(f, f.alex, f.work, variableChange(f.platform.id, "dev", "LOG_LEVEL", { kind: "plain", value: "debug" }, null)))
    const project = await body<WorkspaceProject>(await f.request(`/api/w/${WS}/projects/${f.platform.id}`, f.alex))
    expect(project.vars.find((v) => v.name === "LOG_LEVEL")).toMatchObject({ source: "unset" })
  })
})

describe("audit sentences", () => {
  it("unprotecting with four-eyes already off claims no four-eyes change and no notice", async () => {
    const f = await setup()
    const off = { protected: false, fences: [], fourEyes: false }
    await body(await projectSigned(f, f.alex, f.work, environmentChange(f.platform.id, "staging", off, { ...off, protected: true })))
    await body(await projectSigned(f, f.alex, f.work, environmentChange(f.platform.id, "staging", { ...off, protected: true }, off)))
    const html = (await page(f, `/w/${WS}/audit`, f.alex)).text
    expect(html).toContain("You changed the protection or fences of <code>staging</code>")
    expect(html).not.toContain("four-eyes")
    expect(html).not.toContain("notified")
  })
})

describe("OAuth dependants", () => {
  it("an OAuth client's page lists its visible connection and only says another member's private one exists", async () => {
    const f = await setup()
    await completeConnect(f, f.alex, f.work, "gmail-shared", { kind: "workspace" }, "alex-shared")
    const tom = await member(f, "Tom")
    await completeConnect(f, tom, f.work, "gmail-tom-private", { kind: "member", member: tom.member! }, "tom-private")
    expect(await f.sql(f.work, "SELECT COUNT(*) AS n FROM credential_dependencies")).toEqual([{ n: 2 }])
    const html = (await page(f, `/w/${WS}/items/google-oauth-client`, f.alex)).text
    expect(html).toContain('data-action="delete"')
    expect(html).toContain('data-region="dependent-connections"')
    expect(html).toContain("gmail-shared")
    expect(html).toContain('data-region="hidden-dependants"')
    expect(html).not.toContain("gmail-tom-private")
    // The connection's own page names its client.
    expect((await page(f, `/w/${WS}/items/gmail-shared`, f.alex)).text).toContain('data-region="oauth-client"')
  })
})
