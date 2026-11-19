// The workspace project, credential and ask pages through the real Worker:
// every page is fetched as HTML through worker.fetch, and every change is
// sent with exactly the bodies and checks the browser's own logic builds
// (ui/client/workspace-logic.ts), signed with a real software passkey.
import { describe, expect, it } from "vitest"
import type { CredentialHome, WorkspaceApprovalView, WorkspaceRef, WorkspaceRunCreated, WorkspaceStepUpAction } from "@mehen/protocol"
import { type WorkspaceApprovalBoot, approvalBindingMatches, approvalDecision, chosenConstraints, createdAskPath, credentialStart, environmentChange, identityRefusal, itemDeleteAction, itemRehomeAction, itemUpdateAction, itemRestoreAction, itemRestoreRefusal, nameRefusalWords, projectCreate, purgeMatches, rotationStart, sameAction, shareChange, variableChange, webPagesChange } from "../../src/ui/client/workspace-logic.ts"
import { approvalSubjectOf } from "../../src/ui/pages/workspace-asks.ts"
import { body, refusal } from "./workspace-journey.ts"
import { WS, addCredential, fillIntake, page, projectSigned, setup, uiSigned } from "./ui-projects-journey.ts"

describe("workspace project and credential pages through real dispatch", () => {
  it("projects UI: create, workspace credential in prod, four-eyes on, protected-run approval with recomputed binding", async () => {
    const f = await setup()
    const listed = await page(f, `/w/${WS}/projects`, f.alex)
    expect(listed.status).toBe(200)
    expect(listed.text).toContain(`/w/${WS}/projects/${f.platform.id}`)
    await addCredential(f, f.alex, f.work, "prod-key", { kind: "workspace" })
    // A second manager for four-eyes: a guest promoted to admin.
    const tom = await f.guest(f.alex, f.work, f.platform.id, "Tom")
    await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "admin"))
    await body(await projectSigned(f, f.alex, f.work, variableChange(f.platform.id, "prod", "TOKEN", null, { kind: "item", item: "prod-key", field: "key" })))
    await body(await projectSigned(f, f.alex, f.work, environmentChange(f.platform.id, "prod", { protected: true, fences: [], fourEyes: false }, { protected: true, fences: [], fourEyes: true })))
    const projectPage = await page(f, `/w/${WS}/projects/${f.platform.id}`, f.alex)
    expect(projectPage.status).toBe(200)
    expect(projectPage.text).toContain('data-belongs="workspace">Belongs to: Whole workspace')
    expect(projectPage.text).toContain('data-pill="four-eyes"')
    expect(projectPage.text).toContain('data-region="access-sentence">Manage, including protected runs and edits (as workspace owner).</p>')
    // Alex's own machine asks; four-eyes keeps Alex from approving.
    const machine = await f.protectedMachine(f.alex, f.work)
    const runInput = { project: f.platform.id, env: "prod", envSource: "flag", remote: null, worktree: "/ui", head: null, vars: ["TOKEN"], command: "node ui.js", argv: ["node", "ui.js"] }
    const asked = await body<{ approval: string; deciders: string[] }>(await f.deviceCall(machine, "/v1/runs", runInput), 409)
    expect(asked.deciders).toEqual(["Tom"])
    const alexView = await page(f, `/w/${WS}/a/${asked.approval}`, f.alex)
    expect(alexView.text).toContain('data-region="four-eyes"')
    expect(alexView.text).toContain('data-region="cannot-approve"')
    expect(alexView.text).not.toContain('data-action="approve"')
    expect(alexView.text).toContain('data-region="run-credentials"')
    expect(alexView.text).toMatch(/<code>TOKEN<\/code> from <code>prod-key<\/code> <span class="belongs" data-belongs="workspace">Belongs to: Whole workspace/)
    // Tom's page offers Approve once the binding recomputes.
    const tomView = await page(f, `/w/${WS}/a/${asked.approval}`, tom)
    expect(tomView.text).toContain('data-action="approve"')
    expect(tomView.text).toContain('data-region="deciders">Who can approve: Tom.')
    const view = await body<WorkspaceApprovalView>(await f.request(`/api/w/${WS}/approvals/${asked.approval}`, tom))
    if (view.view !== "detail") throw new Error("Expected the detail view")
    const boot: WorkspaceApprovalBoot = { approval: view.approval.approval, digest: view.approval.digest, subject: approvalSubjectOf(view.approval), binding: view.binding ?? null, headers: view.approval.request.headers }
    expect(await approvalBindingMatches(boot)).toBe(true)
    expect(await approvalBindingMatches({ ...boot, binding: { snapshotDigest: "x", presentationDigest: boot.binding!.presentationDigest } })).toBe(false)
    // More than the agent asked for is refused before anything is sent.
    expect(chosenConstraints(boot.subject.constraints, "2", "600")).toEqual({ ok: false, problems: ["Choose no more uses than the agent asked for."] })
    const chosen = chosenConstraints(boot.subject.constraints, "1", "600")
    if (!chosen.ok) throw new Error("constraints")
    const decision = approvalDecision(boot, "approve", chosen.value)
    await body(await uiSigned(f, tom, f.work, { path: `/approvals/${asked.approval}/action`, body: decision.body }, (a) => sameAction(decision.expected, a), { path: `/approvals/${asked.approval}/decide`, body: decision.body }))
    const created = await body<WorkspaceRunCreated>(await f.deviceCall(machine, "/v1/runs", { ...runInput, approval: asked.approval }), 201)
    expect(created.authorisation?.context).toEqual({ project: f.platform.id, environment: "prod" })
    // The audit page reads ACCESS's filtered reader: Alex sees the whole
    // verified chain in sentences, each row's stored bytes folded beneath.
    const audit = await page(f, `/w/${WS}/audit`, f.alex)
    expect(audit.status).toBe(200)
    expect(audit.text).toContain('data-region="chain"')
    expect(audit.text).toContain("Chain verified")
    expect(audit.text).toContain("You created the project <code>platform</code>")
    expect(audit.text).toContain("You changed the protection or fences of <code>prod</code>")
    const older = await page(f, `/w/${WS}/audit?cursor=3`, f.alex)
    expect(older.status).toBe(200)
    expect(older.text).not.toContain("You changed the protection or fences of <code>prod</code>")
  })

  it("credentials UI: others' private credentials never appear, the purge shows nothing, rotate, rehome, delete and connect", async () => {
    const f = await setup()
    const tom = await f.guest(f.alex, f.work, f.platform.id, "Tom")
    await body(await f.memberChange(f.alex, f.work, tom.member!, "role", "member"))
    await addCredential(f, tom, f.work, "tom-private", { kind: "member", member: tom.member! })
    await addCredential(f, f.alex, f.work, "shared-key", { kind: "workspace" })
    // Alex's list and pages never show Tom's private credential.
    const list = await page(f, `/w/${WS}/credentials`, f.alex)
    expect(list.text).toContain("shared-key")
    expect(list.text).not.toContain("tom-private")
    expect(list.text).toContain('data-region="purge-private"')
    const hidden = await page(f, `/w/${WS}/items/tom-private`, f.alex)
    const absent = await page(f, `/w/${WS}/items/no-such-key`, f.alex)
    // The uniform refusal names only the slug asked for; otherwise the bytes match.
    expect({ ...hidden, text: hidden.text.replaceAll("tom-private", "<slug>") }).toEqual({ ...absent, text: absent.text.replaceAll("no-such-key", "<slug>") })
    expect(hidden.status).toBe(404)
    // Tom's own page carries the private audit limit.
    expect((await page(f, `/w/${WS}/items/tom-private`, tom)).text).toContain('data-region="private-audit"')
    // Tom reads his own private rows, minimal; a filtered view for a member.
    const tomAudit = (await page(f, `/w/${WS}/audit?item=tom-private`, tom)).text
    expect(tomAudit).toContain('data-minimal="1"')
    expect(tomAudit).toContain('data-region="filtered"')
    expect(tomAudit).not.toContain("api.openai.com")
    // Delete preparation: for Tom, Alex's private name answers with the
    // same bytes before it exists and after.
    const absentPrep = await f.request(`/api/w/${WS}/items/alex-private/action`, tom, { action: "delete" })
    await addCredential(f, f.alex, f.work, "alex-private", { kind: "member", member: await f.member(f.alex, f.work) })
    const hiddenPrep = await f.request(`/api/w/${WS}/items/alex-private/action`, tom, { action: "delete" })
    expect(hiddenPrep.status).toBe(404)
    expect(absentPrep.status).toBe(404)
    expect(await hiddenPrep.text()).toBe(await absentPrep.text())
    // The owner's purge preparation returns only the action's type and id.
    const purge = await body<Record<string, unknown>>(await f.request(`/api/w/${WS}/items/tom-private/action`, f.alex, { action: "delete" }))
    expect(Object.keys(purge).sort()).toEqual(["item", "type"])
    expect(purgeMatches(purge)).toBe(true)
    // A wrong kind is still refused at the mutation, with nothing changed.
    const before = await f.snapshot(f.work)
    await refusal(await f.request(`/api/w/${WS}/items/shared-key/rehome`, f.alex, { home: { kind: "project", project: f.platform.id }, stepUp: await f.proof(f.alex, purge as WorkspaceStepUpAction, WS) }), 403, { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    expect(await f.snapshot(f.work)).toEqual(before)
    expect(await body(await uiSigned(f, f.alex, f.work, { path: "/items/tom-private/action", body: { action: "delete" } }, purgeMatches, { path: "/items/tom-private/delete", body: {} }))).toEqual({})
    expect(await f.sql(f.work, "SELECT slug FROM items WHERE slug='tom-private'")).toEqual([])
    // A hidden private name is "not available", in the page's words.
    const taken = await f.request(`/api/w/${WS}/intakes`, tom, credentialStart("openai", "intake", "alex-private", { kind: "member", member: tom.member! }).body)
    const error = await taken.json() as { error: string; message: string }
    expect(taken.status).toBe(409)
    expect(error).toEqual({ error: "conflict", message: "name not available" })
    expect(nameRefusalWords(error as never)).toContain("not available")
    // Rotate: a fresh intake on the same name and home.
    const rotation = rotationStart("shared-key", { kind: "workspace" })
    const rotated = await body<{ intake: string }>(await f.request(`/api/w/${WS}${rotation.path}`, f.alex, rotation.body), 201)
    expect(await body<{ intent: string }>(await f.request(`/api/w/${WS}/intakes/${rotated.intake}`, f.alex))).toMatchObject({ intent: "rotate" })
    // Rehome into the project, then delete, each through its preparation.
    const to: CredentialHome = { kind: "project", project: f.platform.id }
    // The page binds the stable id and dependency revision it showed.
    const shown = await body<{ id: string; version: number; configRevision: number; dependencyRevision: number }>(await f.request(`/api/w/${WS}/items/shared-key`, f.alex))
    const rehome = itemRehomeAction(shown, { kind: "workspace" }, to)
    const moved = await body<{ home: CredentialHome }>(await uiSigned(f, f.alex, f.work, { path: "/items/shared-key/action", body: { action: "rehome", home: to } }, (a) => sameAction(rehome, a), { path: "/items/shared-key/rehome", body: { home: to } }))
    expect(moved.home).toEqual(to)
    expect(await body(await uiSigned(f, f.alex, f.work, { path: "/items/shared-key/action", body: { action: "delete" } }, (a) => sameAction(itemDeleteAction(shown), a), { path: "/items/shared-key/delete", body: {} }))).toEqual({})
    // Connect: the client intake first, then the signed start.
    const connect = credentialStart("google-gmail", "connect", "gmail-alex", { kind: "workspace" })
    const started = await body<{ connect: string; intake?: { intake: string } }>(await f.request(`/api/w/${WS}${connect.path}`, f.alex, connect.body), 201)
    expect(createdAskPath(WS, started)).toBe(`/w/${WS}/i/${started.intake?.intake}`)
    await fillIntake(f, f.alex, started.intake!.intake, { kind: "workspace" })
    const connectPage = await page(f, `/w/${WS}/c/${started.connect}`, f.alex)
    expect(connectPage.status).toBe(200)
    expect(connectPage.text).toContain('data-action="start-connect"')
    expect(connectPage.text).toContain('data-region="home-choice"')
    expect(connectPage.text).not.toMatch(/href="\/(items|i|c)\//)
    const home: CredentialHome = { kind: "workspace" }
    const opened = await body<{ authorizeUrl: string }>(await uiSigned(f, f.alex, f.work, { path: `/connect/${started.connect}/action`, body: { home } }, (a) => typeof a === "object" && a !== null && (a as { type?: unknown }).type === "connect.start" && (a as { connect?: unknown }).connect === started.connect, { path: `/connect/${started.connect}/start`, body: { home } }))
    expect(new URL(opened.authorizeUrl).protocol).toBe("https:")
  })

  it("a replaced value: the credential page says it is kept and offers Restore it, which restores with a passkey over the versions shown, and a stale restore shows the vault's refusal", async () => {
    const f = await setup()
    await addCredential(f, f.alex, f.work, "kept-key", { kind: "workspace" })
    expect((await page(f, `/w/${WS}/items/kept-key`, f.alex)).text).not.toContain('data-region="previous"')
    const rotation = rotationStart("kept-key", { kind: "workspace" })
    await fillIntake(f, f.alex, (await body<{ intake: string }>(await f.request(`/api/w/${WS}${rotation.path}`, f.alex, rotation.body), 201)).intake, { kind: "workspace" })
    const shown = await body<{ id: string; version: number; configRevision: number; dependencyRevision: number; previous: { version: number } | null }>(await f.request(`/api/w/${WS}/items/kept-key`, f.alex))
    expect(shown).toMatchObject({ version: 2, previous: { version: 1 } })
    const itemPage = await page(f, `/w/${WS}/items/kept-key`, f.alex)
    expect(itemPage.text).toMatch(/Previous value kept until <time[^>]*>[^<]+<\/time>, replaced by Alex on <time[^>]*>[^<]+<\/time>, fields: <code>key<\/code>\./)
    expect(itemPage.text).toContain('data-action="restore"')
    expect(itemPage.text).toContain("&quot;previous&quot;:1")
    expect(itemRestoreRefusal(shown, 1, shown)).toBeNull()
    const terms = { version: shown.version, previous: 1 }
    const expected = await itemRestoreAction(shown, 1)
    const restored = await uiSigned(f, f.alex, f.work, { path: "/items/kept-key/action", body: { action: "restore", ...terms } }, (a) => sameAction(expected, a), { path: "/items/kept-key/restore", body: terms })
    expect(restored.status).toBe(200)
    const after = await body<{ version: number }>(await f.request(`/api/w/${WS}/items/kept-key`, f.alex))
    expect(after.version).toBeGreaterThan(shown.version)
    // The terms the page showed are stale now: the vault's refusal, as it words it.
    const stale = await f.request(`/api/w/${WS}/items/kept-key/action`, f.alex, { action: "restore", ...terms })
    const refused = await stale.json() as { error: string; message: string }
    expect([stale.status, refused.error]).toEqual([409, "conflict"])
    expect(refused.message).toBe((await body<{ message: string }>(await f.request(`/api/w/${WS}/items/kept-key/restore`, f.alex, { ...terms, stepUp: { nonce: "unchecked", assertion: {} } }), 409)).message)
  })

  it("In web pages: the credential page shows the card where typing into web pages is on, and its Save stores the pages added with a passkey over only the change", async () => {
    const f = await setup()
    await addCredential(f, f.alex, f.work, "web-key", { kind: "workspace" })
    const itemPage = await page(f, `/w/${WS}/items/web-key`, f.alex)
    expect(itemPage.text).toContain('data-region="in-web-pages"')
    expect(itemPage.text).toContain('data-action="save-web-pages"')
    const shown = await body<{ id: string; version: number; configRevision: number; ceiling: string; browser?: unknown }>(await f.request(`/api/w/${WS}/items/web-key`, f.alex))
    expect(shown.browser).toBeUndefined()
    const change = webPagesChange({ ceiling: shown.ceiling, signinOrigins: [], typeInto: [] }, { ceiling: shown.ceiling, signinOrigins: [], typeInto: ["https://dash.example.net"] })
    expect(change).toEqual({ browser: { signinOrigins: [], typeInto: ["https://dash.example.net"] } })
    const expected = await itemUpdateAction(shown, change)
    expect((await uiSigned(f, f.alex, f.work, { path: "/items/web-key/action", body: { action: "update", change } }, (a) => sameAction(expected, a), { path: "/items/web-key/update", body: change! })).status).toBe(200)
    expect(await body<{ browser?: unknown }>(await f.request(`/api/w/${WS}/items/web-key`, f.alex))).toMatchObject({ browser: { signinOrigins: [], typeInto: ["https://dash.example.net"] } })
    expect((await page(f, `/w/${WS}/items/web-key`, f.alex)).text).toContain('<li class="row" data-origin="https://dash.example.net">')
  })

  it("forbidden controls are invisible, owner-only words stand in, guests see only their own projects and asks", async () => {
    const f = await setup()
    await addCredential(f, f.alex, f.work, "prod-key", { kind: "workspace" })
    await body(await projectSigned(f, f.alex, f.work, variableChange(f.platform.id, "prod", "TOKEN", null, { kind: "item", item: "prod-key", field: "key" })))
    await body(await projectSigned(f, f.alex, f.work, environmentChange(f.platform.id, "prod", { protected: true, fences: [], fourEyes: false }, { protected: true, fences: [], fourEyes: true })))
    // Kim: a member who manages the project through a direct share.
    const kim = await f.guest(f.alex, f.work, f.platform.id, "Kim")
    await body(await f.memberChange(f.alex, f.work, kim.member!, "role", "member"))
    await body(await projectSigned(f, f.alex, f.work, shareChange(f.platform.id, { kind: "member", member: kim.member! }, { level: "edit", protected: true, expiresAt: null }, { level: "manage", protected: true, expiresAt: null })))
    const kimPage = (await page(f, `/w/${WS}/projects/${f.platform.id}`, kim)).text
    expect(kimPage).toContain("Only an owner or admin can loosen platform/prod: it uses workspace credentials.")
    expect(kimPage).toContain("Only an owner or admin can change fences for platform/prod.")
    const prodCard = kimPage.slice(kimPage.indexOf('data-env-card="prod"'), kimPage.indexOf('data-env-card="staging"') > kimPage.indexOf('data-env-card="prod"') ? kimPage.indexOf('data-env-card="staging"') : undefined)
    expect(prodCard).not.toContain('data-control="four-eyes-off"')
    expect(prodCard).not.toContain('data-control="fences"')
    expect(prodCard).not.toContain('data-control="unprotect"')
    expect(kimPage).not.toContain('data-control="fences"')
    // The vault agrees: the same loosening is refused with those words.
    await refusal(await f.request(`/api/w/${WS}/projects/action`, kim, { change: "environment", input: environmentChange(f.platform.id, "prod", { protected: true, fences: [], fourEyes: true }, { protected: true, fences: [], fourEyes: false }).input }), 403, { error: "forbidden", message: "You are not allowed to do that.", next: { say: "Only an owner or admin can loosen platform/prod: it uses workspace credentials." } })
    // Alex sees every control.
    const alexPage = (await page(f, `/w/${WS}/projects/${f.platform.id}`, f.alex)).text
    expect(alexPage).toContain('data-control="four-eyes-off"')
    expect(alexPage).toContain('data-control="fences"')
    expect(alexPage).not.toContain('data-region="owner-only"')
    // A guest sees only the project shared with them, and no share list.
    const second = projectCreate("hidden-project", "", [{ name: "dev", protected: false, fourEyes: false }], "dev")
    if (!second.ok) throw new Error("create")
    await body(await projectSigned(f, f.alex, f.work, second.value), 201)
    const guest = await f.guest(f.alex, f.work, f.platform.id, "Sam")
    const guestList = (await page(f, `/w/${WS}/projects`, guest)).text
    expect(guestList).toContain("platform")
    expect(guestList).not.toContain("hidden-project")
    expect(guestList).not.toContain('data-region="create-project"')
    const guestProject = (await page(f, `/w/${WS}/projects/${f.platform.id}`, guest)).text
    expect(guestProject).toContain("Shared with you.")
    expect(guestProject).not.toContain("Kim")
    expect(guestProject).not.toContain('data-action="share"')
    // Guests see only their own asks: Alex's pending private intake is not theirs.
    await body(await f.request(`/api/w/${WS}/intakes`, f.alex, credentialStart("openai", "intake", "alex-pending", { kind: "workspace" }).body), 201)
    const guestPending = (await page(f, `/w/${WS}/pending`, guest)).text
    expect(guestPending).not.toContain("alex-pending")
    expect((await page(f, `/w/${WS}/pending`, f.alex)).text).toContain("alex-pending")
    // A guest's audit page is filtered to their own actions.
    const guestAudit = (await page(f, `/w/${WS}/audit`, guest)).text
    expect(guestAudit).toContain("Filtered view: only owners and admins can verify the whole chain.")
    expect(guestAudit).not.toContain("hidden-project")
  })

  it("a share changed between preparation and signature is still refused at the final check", async () => {
    const f = await setup()
    const tom = await f.guest(f.alex, f.work, f.platform.id, "Tom")
    const edit = { level: "edit" as const, protected: true, expiresAt: null }
    const change = shareChange(f.platform.id, { kind: "member", member: tom.member! }, edit, { level: "use", protected: false, expiresAt: null })
    const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/projects/action`, f.alex, { change: change.change, input: change.input }))
    expect(sameAction(await change.expected, action)).toBe(true)
    const proof = await f.proof(f.alex, action, WS)
    // Another tab changes the share after this page's preparation.
    await body(await projectSigned(f, f.alex, f.work, shareChange(f.platform.id, { kind: "member", member: tom.member! }, edit, { level: "use", protected: true, expiresAt: null })))
    const shares = await f.sql(f.work, "SELECT * FROM project_shares ORDER BY id")
    await refusal(await f.request(`/api/w/${WS}${change.path}`, f.alex, { ...change.input, stepUp: proof }), 409, { error: "conflict", message: "The expected state changed." })
    expect(await f.sql(f.work, "SELECT * FROM project_shares ORDER BY id")).toEqual(shares)
  })

  it("confirmation refuses a renamed workspace before signing and a stale share at preparation", async () => {
    const f = await setup()
    const shown = f.work
    // Another tab renames the workspace after this page loaded.
    await body(await f.signed(`/api/w/${WS}/settings`, f.alex, { change: "name", name: "Northwind Labs" }, { type: "workspace.update", name: "Northwind Labs", slug: WS }, WS))
    const now = await body<WorkspaceRef>(await f.request(`/api/w/${WS}`, f.alex))
    expect(identityRefusal(shown, now)).toEqual({ error: "conflict", message: "This workspace was renamed to Northwind Labs (northwind) since the page loaded.", next: { say: "Nothing was signed. Reload the page to confirm under its current name." } })
    const challenges = await f.db.prepare("SELECT COUNT(*) AS n FROM challenges").first<{ n: number }>()
    await expect(projectSigned(f, f.alex, shown, environmentChange(f.platform.id, "staging", { protected: false, fences: [], fourEyes: false }, { protected: true, fences: [], fourEyes: false }))).rejects.toThrow("renamed to Northwind Labs")
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM challenges").first<{ n: number }>()).toEqual(challenges)
    // Two people named Tom: the share names the member by id, and a page
    // holding a stale share state gets a different action than it rebuilt.
    const renamed = { ...shown, name: "Northwind Labs" }
    const first = await f.guest(f.alex, f.work, f.platform.id, "Tom")
    const second = await f.guest(f.alex, f.work, f.platform.id, "Tom")
    const people = (await page(f, `/w/${WS}/projects/${f.platform.id}`, f.alex)).text
    expect(people).toContain(`Tom (${first.member})`)
    expect(people).toContain(`Tom (${second.member})`)
    // A share request's link (?share=) opens the form with that Tom chosen.
    const asked = (await page(f, `/w/${WS}/projects/${f.platform.id}?share=${second.member}`, f.alex)).text
    expect(asked).toContain('data-region="share-fold" open>')
    expect(asked).toMatch(new RegExp(`<option value="${second.member}"[^>]* selected>`))
    expect(people).not.toContain(" selected>")
    const stale = shareChange(f.platform.id, { kind: "member", member: second.member! }, null, { level: "use", protected: false, expiresAt: null })
    // The live share is edit: the stale before-state is refused at
    // preparation, before any passkey is asked, and nothing changes.
    const shares = await f.sql(f.work, "SELECT * FROM project_shares ORDER BY id")
    const before = await f.db.prepare("SELECT COUNT(*) AS n FROM challenges").first<{ n: number }>()
    await refusal(await f.request(`/api/w/${WS}/projects/action`, f.alex, { change: stale.change, input: stale.input }), 409, { error: "conflict", message: "The expected state changed." })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM challenges").first<{ n: number }>()).toEqual(before)
    expect(await f.sql(f.work, "SELECT * FROM project_shares ORDER BY id")).toEqual(shares)
    const fresh = shareChange(f.platform.id, { kind: "member", member: second.member! }, { level: "edit", protected: true, expiresAt: null }, { level: "use", protected: false, expiresAt: null })
    await body(await projectSigned(f, f.alex, renamed, fresh))
    expect(sameAction(await stale.expected as WorkspaceStepUpAction, await fresh.expected)).toBe(false)
  })
})
