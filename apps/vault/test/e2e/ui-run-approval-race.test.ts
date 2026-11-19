// The run approval page's credential list is read from the project as it
// is now, after the approval itself.
// These reproduce the reviewer's race through the real Worker: something
// changes between the page's approval read and its project read, and the
// page reads the approval again after the project. A repointed reference or
// a rehomed credential (its config_rev changes) makes the ask vanish for its
// reader, so the page is the uniform not-found page with no list and no
// decision. An ask decided in between is shown from the second read, as
// decided. Without a race the page offers Approve. The notice for an ask
// still readable but changed or stale while its list is shown is pinned on
// the rendered page in src/ui/workspace-wiring-gallery.test.ts.
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test"
import { expect, it } from "vitest"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import worker from "../../src/index.ts"
import { CHANGED_SINCE_REQUESTED } from "../../src/ui/wording.ts"
import { variableChange } from "../../src/ui/client/workspace-logic.ts"
import type { Env } from "../../src/env.ts"
import type { Invocation, WorkspaceInvocation } from "../../src/vault/core.ts"
import { ORIGIN } from "../helpers.ts"
import { body } from "./workspace-journey.ts"
import { WS, addCredential, page, projectSigned, setup } from "./ui-projects-journey.ts"

type Journey = Awaited<ReturnType<typeof setup>>

async function askedRun(f: Journey) {
  await addCredential(f, f.alex, f.work, "prod-key", { kind: "workspace" })
  await addCredential(f, f.alex, f.work, "prod-key-next", { kind: "workspace" })
  await body(await projectSigned(f, f.alex, f.work, variableChange(f.platform.id, "prod", "TOKEN", null, { kind: "item", item: "prod-key", field: "key" })))
  const machine = await f.protectedMachine(f.alex, f.work)
  return (await body<{ approval: string }>(await f.deviceCall(machine, "/v1/runs", { project: f.platform.id, env: "prod", envSource: "flag", remote: null, worktree: "/race", head: null, vars: ["TOKEN"], command: "node deploy.js", argv: ["node", "deploy.js"] }), 409)).approval
}

// The approval page fetched with `during` run once, just before the vault
// answers the page's first project read.
async function racedPage(f: Journey, approval: string, during: () => Promise<unknown>) {
  let armed = true
  const vaults = f.env.TENANT_VAULT
  const racing = new Proxy(vaults, { get(target, key) {
    if (key === "getByName") return (name: string) => {
      const stub = target.getByName(name)
      return new Proxy(stub, { get(object, prop) {
        if (prop === "invoke") return async (input: Invocation | WorkspaceInvocation) => {
          if (armed && input.op === "projects.get") { armed = false; await during() }
          return object.invoke(input)
        }
        const value = Reflect.get(object, prop) as unknown
        return typeof value === "function" ? value.bind(object) : value
      } })
    }
    const value = Reflect.get(target, key) as unknown
    return typeof value === "function" ? value.bind(target) : value
  } })
  const bindings: Env = { ...f.env, TENANT_VAULT: racing }
  const ctx = createExecutionContext()
  const response = await worker.fetch(new Request(`${ORIGIN}/w/${WS}/a/${approval}`, { headers: { cookie: f.alex.cookie, accept: "text/html" } }), bindings, ctx)
  await waitOnExecutionContext(ctx)
  expect(armed).toBe(false)
  return { status: response.status, text: await response.text() }
}

it("without a race the run approval page lists the credential and offers Approve, with no notice", async () => {
  const f = await setup()
  const approval = await askedRun(f)
  const steady = (await page(f, `/w/${WS}/a/${approval}`, f.alex)).text
  expect(steady).toContain("prod-key")
  expect(steady).toContain('data-action="approve"')
  expect(steady).not.toContain('data-region="changed-since-requested"')
})

it("a reference repointed while the page was built: no stale list and no decision, only the page a vanished ask gets", async () => {
  const f = await setup()
  const approval = await askedRun(f)
  const raced = await racedPage(f, approval, async () => body(await projectSigned(f, f.alex, f.work, variableChange(f.platform.id, "prod", "TOKEN", { kind: "item", item: "prod-key", field: "key" }, { kind: "item", item: "prod-key-next", field: "key" }))))
  expect(raced.status).toBe(404)
  expect(raced.text).not.toContain("prod-key-next")
  expect(raced.text).not.toContain('data-region="run-credentials"')
  expect(raced.text).not.toContain('data-action="approve"')
  // The vault agrees: the old ask is gone for its reader, now and later.
  expect((await f.request(`/api/w/${WS}/approvals/${approval}`, f.alex)).status).toBe(404)
  expect((await page(f, `/w/${WS}/a/${approval}`, f.alex)).status).toBe(404)
})

it("an ask decided in another tab while the page was built is shown as decided, from the second read, with no decision offered", async () => {
  const f = await setup()
  const approval = await askedRun(f)
  // Another tab denies it between the page's two approval reads.
  const raced = await racedPage(f, approval, async () => {
    const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/approvals/${approval}/action`, f.alex, { decision: "deny" }))
    return body(await f.signed(`/api/w/${WS}/approvals/${approval}/decide`, f.alex, { decision: "deny" }, action, WS))
  })
  expect(raced.status).toBe(200)
  expect(raced.text).not.toContain('data-action="approve"')
  expect(raced.text).not.toContain('data-form="decide"')
  expect(raced.text).toContain('<p class="strip" data-region="settled"><span class="pill muted dot">denied</span> by you</p>')
  // A settled run shows no live credential list, so there is nothing to flag.
  expect(raced.text).not.toContain('data-region="run-credentials"')
  expect(raced.text).not.toContain(CHANGED_SINCE_REQUESTED)
})

it("a credential's configuration changed (rehomed, config_rev bumped) while the page was built: no stale Belongs to and no decision", async () => {
  const f = await setup()
  const approval = await askedRun(f)
  const home = { kind: "project" as const, project: f.platform.id }
  const raced = await racedPage(f, approval, async () => {
    const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/items/prod-key/action`, f.alex, { action: "rehome", home }))
    return body(await f.signed(`/api/w/${WS}/items/prod-key/rehome`, f.alex, { home }, action, WS))
  })
  expect(raced.status).toBe(404)
  expect(raced.text).not.toContain('data-region="run-credentials"')
  expect(raced.text).not.toContain("Belongs to")
  expect(raced.text).not.toContain('data-action="approve"')
  expect((await f.request(`/api/w/${WS}/approvals/${approval}`, f.alex)).status).toBe(404)
})

// A configuration-only change: the same item, home and reference, with its
// binding or ceiling edited through the real signed update, so only its
// config_rev moves. The vault reports the ask stale (it compares the
// request-time revisions with the current ones), and the page shows the
// notice with no decision, whichever read the change lands before.
async function updateConfiguration(f: Journey, change: Record<string, unknown>) {
  const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/items/prod-key/action`, f.alex, { action: "update", change }))
  return body(await f.signed(`/api/w/${WS}/items/prod-key/update`, f.alex, change, action, WS))
}

async function itemState(f: Journey) {
  return f.sql<{ id: string; home_kind: string; config_rev: number }>(f.work, "SELECT id,home_kind,config_rev FROM items WHERE slug='prod-key'")
}

async function expectChangedPage(f: Journey, text: string, approval: string, before: Awaited<ReturnType<typeof itemState>>) {
  const after = await itemState(f)
  expect(after).toEqual([{ ...before[0]!, config_rev: before[0]!.config_rev + 1 }])
  // The reference is the same stable id it was.
  const project = await body<{ vars: { env: string; name: string; item: string | null }[] }>(await f.request(`/api/w/${WS}/projects/${f.platform.id}`, f.alex))
  expect(project.vars.filter((v) => v.env === "prod")).toEqual([expect.objectContaining({ name: "TOKEN", item: "prod-key" })])
  expect(text).toContain('data-region="changed-since-requested"')
  expect(text).toContain(CHANGED_SINCE_REQUESTED)
  expect(text).not.toContain('data-action="approve"')
  expect(text).not.toContain('data-form="decide"')
  // Only the status says so: no revision reaches the reader.
  const view = await body<{ view: string; approval?: { status: string } }>(await f.request(`/api/w/${WS}/approvals/${approval}`, f.alex))
  expect(view.approval?.status).toBe("stale")
  expect(JSON.stringify(view)).not.toMatch(/config_?[rR]ev/)
}

it("a binding changed between the page's two approval reads: config_rev moves, the page says the request changed and offers no Approve", async () => {
  const f = await setup()
  const approval = await askedRun(f)
  const before = await itemState(f)
  const raced = await racedPage(f, approval, () => updateConfiguration(f, { binding: { hosts: ["api.changed.example.test"] } }))
  expect(raced.status).toBe(200)
  await expectChangedPage(f, raced.text, approval, before)
})

it("a ceiling changed before the page's first approval read: the page says the request changed and offers no Approve", async () => {
  const f = await setup()
  const approval = await askedRun(f)
  const before = await itemState(f)
  await updateConfiguration(f, { ceiling: "lease" })
  const shown = await page(f, `/w/${WS}/a/${approval}`, f.alex)
  expect(shown.status).toBe(200)
  await expectChangedPage(f, shown.text, approval, before)
})
