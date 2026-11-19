// The consoles' pages (routes/ui-operator.ts) through the real Worker, as a
// browser asks for them: the operator's pages for the operator only, a
// platform's admin pages for its admins only, everyone else (signed out,
// or not asking for a page, too) the same answer as an address with no
// page, and the console links only in the shells of an account that has
// them. Never a subject's name.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { type OperatorChangeAnswer, type OperatorCommand, type OperatorProposalAnswer, operatorApproveStepUpAction, operatorProposeStepUpAction } from "@mehen/protocol"
import { type ConsoleFixture, type Person, answer, consoleFixture } from "./console-support.ts"
import { ORIGIN } from "./helpers.ts"
import { addSubject, newPlatformKey } from "./platform-fixtures.ts"

type Setup = ConsoleFixture & { alex: Person; sam: Person; kim: Person }

// Alex is the operator; Sam is made an admin of globex; Kim is neither.
async function setup(): Promise<Setup & { platform: string }> {
  const f = await consoleFixture()
  await f.grantOperator("acc_owner")
  const s = { ...f, alex: await f.person("acc_owner"), sam: await f.person("acc_admin"), kim: await f.person("acc_member") }
  const operate = async (command: OperatorCommand) => answer<OperatorChangeAnswer>(await f.request(command.command === "register" ? "/api/operator/platforms" : "/api/operator/platforms/globex", s.alex, { command, stepUp: await f.operatorProof(s.alex, "globex", command) }), command.command === "register" ? 201 : 200)
  const { jwk } = await newPlatformKey()
  const created = await operate({ command: "register", slug: "globex", name: "Globex", key: jwk, limits: {}, confirm: "globex" })
  await operate({ command: "add-admin", account: "acc_admin" })
  await addSubject(f.env, created.platform.id, "subject-never-shown")
  return { ...s, platform: created.platform.id }
}

async function page(f: ConsoleFixture, path: string, who?: Person, init: { accept?: string; method?: string } = {}): Promise<{ status: number; body: string; location: string | null }> {
  const worker = (await import("../src/index.ts")).default
  const ctx = createExecutionContext()
  const headers: Record<string, string> = { accept: init.accept ?? "text/html", "sec-fetch-site": "same-origin", ...(who ? { cookie: who.cookie } : {}) }
  const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { method: init.method ?? "GET", headers, redirect: "manual" }) as Request<unknown, IncomingRequestCfProperties>, f.env, ctx)
  await waitOnExecutionContext(ctx)
  return { status: response.status, body: await response.text(), location: response.headers.get("location") }
}

const OPERATOR_PAGES = ["/operator", "/operator/register", "/operator/platforms/globex", "/operator/operators", "/operator/workspaces", "/operator/workspaces/tn_Beta1234567", "/operator/accounts", "/operator/accounts/acc_member", "/operator/audit", "/operator/settings"]
const ADMIN_PAGES = ["/platforms", "/platforms/globex"]

describe("the console pages", () => {
  it("the operator's list says how this deployment decides who creates workspaces", async () => {
    const f = await setup()
    expect((await page(f, "/operator", f.alex)).body).toContain('data-region="workspace-creation">Workspace creation is only for accounts an operator allows on the account&#39;s page in Accounts (Settings).</p>')
    f.env.WORKSPACE_CREATION = "accounts"
    expect((await page(f, "/operator", f.alex)).body).toContain("Workspace creation is on for every account (Settings).")
    await f.env.DB.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('workspace_creation','operator',?,'operator:acc_owner')").bind(Date.now()).run()
    expect((await page(f, "/operator", f.alex)).body).toContain("Workspace creation is only for accounts an operator allows on the account&#39;s page in Accounts (Settings).")
  })
  it("are the plain not-found page for an account without the role, byte for byte", async () => {
    const f = await setup()
    const nowhere = await page(f, "/w/no-such-workspace", f.kim)
    expect(nowhere.status).toBe(404)
    for (const path of [...OPERATOR_PAGES, ...ADMIN_PAGES, "/operator/platforms/nothing", "/platforms/nothing"]) {
      const seen = await page(f, path, f.kim)
      expect({ path, status: seen.status, same: seen.body === nowhere.body }).toEqual({ path, status: 404, same: true })
    }
    // The operator administers nothing until added, and an admin is no
    // operator: each gets their own plain not-found page, without the
    // console links their pages have.
    for (const [who, paths] of [[f.alex, ADMIN_PAGES], [f.sam, OPERATOR_PAGES]] as const) {
      const theirs = (await page(f, "/w/no-such-workspace", who)).body
      for (const path of paths) {
        const seen = await page(f, path, who)
        expect({ path, status: seen.status, same: seen.body === theirs }).toEqual({ path, status: 404, same: true })
      }
    }
  })

  it("are the plain not-found page signed out, and not_found to anything but a browser's GET for a page", async () => {
    const f = await setup()
    const nowhere = await page(f, "/no-such-page")
    const asJson = await page(f, "/no-such-page", f.alex, { accept: "application/json" })
    const posted = await page(f, "/no-such-page", f.alex, { method: "POST" })
    expect([nowhere.status, asJson.status, posted.status]).toEqual([404, 404, 404])
    for (const path of [...OPERATOR_PAGES, ...ADMIN_PAGES]) {
      const seen = await page(f, path)
      expect({ path, status: seen.status, same: seen.body === nowhere.body, location: seen.location }).toEqual({ path, status: 404, same: true, location: null })
      expect(await page(f, path, f.alex, { accept: "application/json" }), path).toEqual(asJson)
      expect(await page(f, path, f.alex, { method: "POST" }), path).toEqual(posted)
    }
  })

  it("show the operator every platform and one with its forms, and never a subject", async () => {
    const f = await setup()
    const list = await page(f, "/operator", f.alex)
    expect(list.status).toBe(200)
    expect(list.body).toContain('href="/operator/platforms/globex"')
    const one = await page(f, "/operator/platforms/globex", f.alex)
    expect(one.status).toBe(200)
    for (const form of ["platform-suspend", "rotate-key", "revoke-key", "platform-limits", "add-admin", "delete-subjects", "retire", "remove"]) expect(one.body, form).toContain(`data-form="${form}"`)
    expect(one.body).toContain('data-admin="acc_admin"')
    expect(one.body).toContain("Registered the platform")
    expect(one.body).not.toContain("subject-never-shown")
    const register = (await page(f, "/operator/register", f.alex)).body
    expect(register).toContain('data-form="platform-register"')
    // The slugs taken, so the form refuses one before the passkey.
    expect(register).toContain("&quot;heldSlugs&quot;:{&quot;globex&quot;:&quot;registered&quot;}")
  })

  it("show the operator the Operators view, linked from the list, saying a second operator is needed while there is none", async () => {
    const f = await setup()
    expect((await page(f, "/operator", f.alex)).body).toContain('href="/operator/operators"')
    const alone = await page(f, "/operator/operators", f.alex)
    expect(alone.status).toBe(200)
    expect(alone.body).toContain('data-operator="acc_owner"')
    expect(alone.body).toContain('data-region="needs-second-operator"')
    expect(alone.body).toContain("Needs a second operator; use the script.")
    await f.grantOperator("acc_admin")
    const two = await page(f, "/operator/operators", f.alex)
    expect(two.body).not.toContain('data-region="needs-second-operator"')
    expect(two.body).toContain('data-kind="operator.revoke" data-target="acc_admin"')
    expect(two.body).toContain('data-kind="operator.resign" data-target="acc_owner"')
  })

  it("show the operator the Workspaces view, linked from the list, with its filter and search, and one workspace", async () => {
    const f = await setup()
    expect((await page(f, "/operator", f.alex)).body).toContain('href="/operator/workspaces"')
    const all = await page(f, "/operator/workspaces", f.alex)
    expect(all.status).toBe(200)
    expect(all.body).toContain('href="/operator/workspaces/tn_Beta1234567"')
    expect(all.body).toContain('href="/operator/workspaces/tn_Alpha123456"')
    const searched = await page(f, "/operator/workspaces?q=wind&filter=active", f.alex)
    expect(searched.body).toContain('href="/operator/workspaces/tn_Beta1234567"')
    expect(searched.body).not.toContain('href="/operator/workspaces/tn_Alpha123456"')
    expect(searched.body).toContain('value="wind"')
    // A query the route refuses reads every workspace rather than failing the page.
    expect((await page(f, "/operator/workspaces?filter=everything", f.alex)).body).toContain('href="/operator/workspaces/tn_Alpha123456"')
    const one = await page(f, "/operator/workspaces/tn_Beta1234567", f.alex)
    expect(one.status).toBe(200)
    expect(one.body).toContain('data-region="restore-checklist"')
    expect(one.body).toContain("Needs a second operator; use the script.")
    await f.env.DB.prepare("UPDATE workspaces SET status='deleting',delete_after=? WHERE id='tn_Alpha123456'").bind(Date.now() + 86_400_000).run()
    const deleting = await page(f, "/operator/workspaces/tn_Alpha123456", f.alex)
    expect(deleting.body).toContain("Only an active workspace is restored")
    expect(deleting.body).not.toContain('data-form="restore-pitr"')
    expect((await page(f, "/operator/workspaces/tn_Nowhere1234", f.alex)).status).toBe(404)
  })

  it("show the operator the Accounts view, linked from the list, searched and filtered, and one account with what may change", async () => {
    const f = await setup()
    expect((await page(f, "/operator", f.alex)).body).toContain('href="/operator/accounts"')
    const all = await page(f, "/operator/accounts", f.alex)
    expect(all.status).toBe(200)
    expect(all.body).toContain('href="/operator/accounts/acc_member"')
    const searched = await page(f, "/operator/accounts?q=acc_member&filter=no-recovery", f.alex)
    expect(searched.status).toBe(200)
    expect(searched.body).toContain(`aria-current="page">No recovery</a>`)
    expect(searched.body).toContain('name="q" value="acc_member"')
    // A search the vault refuses is the page unsearched, never an error.
    expect((await page(f, "/operator/accounts?filter=everyone", f.alex)).status).toBe(200)
    const one = await page(f, "/operator/accounts/acc_member", f.alex)
    expect(one.status).toBe(200)
    for (const region of ["account", "workspaces", "passkeys", "sessions", "events-card", "workspace-creation", "suspension", "danger-zone"]) expect(one.body, region).toContain(`data-region="${region}"`)
    expect(one.body).toContain('data-kind="account.suspend"')
    expect(one.body).toContain('data-region="needs-second"')
    expect(one.body).toContain('data-region="delete-blocked"')
    const yours = await page(f, "/operator/accounts/acc_owner", f.alex)
    expect(yours.body).toContain("This is your own account; another operator changes it.")
    expect(yours.body).not.toContain('data-action="account-propose"')
    expect((await page(f, "/operator/accounts/acc_nobody", f.alex)).status).toBe(404)
    expect((await page(f, "/operator/accounts/not-an-id", f.alex)).status).toBe(404)
  })

  it("show the account an approved operator role to accept on Your account, and nobody else", async () => {
    const f = await setup()
    await f.grantOperator("acc_admin")
    const terms = { kind: "operator.grant" as const, target: "acc_member", params: {} }
    const proposed = await answer<OperatorProposalAnswer>(await f.request("/api/operator/proposals", f.alex, { ...terms, stepUp: await f.proof(f.alex, "/api/operator/stepup/start", await operatorProposeStepUpAction(terms)) }), 201)
    const { id, digest } = proposed.proposal!
    expect((await page(f, "/account", f.kim)).body).not.toContain('data-region="operator-invitation"')
    await answer(await f.request(`/api/operator/proposals/${id}`, f.sam, { decision: "approve", digest, stepUp: await f.proof(f.sam, "/api/operator/stepup/start", operatorApproveStepUpAction(id, digest)) }))
    const kim = (await page(f, "/account", f.kim)).body
    expect(kim).toContain('data-region="operator-invitation"')
    expect(kim).toContain(`data-action="accept-operator" data-proposal="${id}"`)
    expect((await page(f, "/account", f.sam)).body).not.toContain('data-region="operator-invitation"')
  })

  it("show an admin only their platform, with no operator change", async () => {
    const f = await setup()
    const list = await page(f, "/platforms", f.sam)
    expect(list.status).toBe(200)
    expect(list.body).toContain('href="/platforms/globex"')
    const one = await page(f, "/platforms/globex", f.sam)
    expect(one.status).toBe(200)
    expect([...one.body.matchAll(/data-form="([a-z-]+)"/g)].map((m) => m[1]).sort()).toEqual(["defaults", "delete-subject", "rotate-key"])
    expect(one.body).not.toContain("subject-never-shown")
  })

  it("offer an admin only the keys whose revocation leaves another key with no end, and none once every live key is ending", async () => {
    const f = await setup()
    const operate = async (command: OperatorCommand) => answer<OperatorChangeAnswer>(await f.request("/api/operator/platforms/globex", f.alex, { command, stepUp: await f.operatorProof(f.alex, "globex", command) }))
    const { jwk } = await newPlatformKey()
    const rotated = await operate({ command: "rotate-key", key: jwk, overlapHours: 1, confirm: "globex" })
    const ending = rotated.platform.keys.find((k) => k.expiresAt !== null)!
    const fresh = rotated.platform.keys.find((k) => k.expiresAt === null)!
    const offered = (body: string) => [...(body.match(/data-form="revoke-key"[\s\S]*?<\/form>/)?.[0] ?? "").matchAll(/<option value="([^"]+)"/g)].map((m) => m[1])
    const overlap = await page(f, "/platforms/globex", f.sam)
    expect(offered(overlap.body)).toEqual([ending.id])
    expect(overlap.body).toContain("new key with 0 hours instead: that ends every other key at once.")
    expect(offered((await page(f, "/operator/platforms/globex", f.alex)).body).sort()).toEqual([ending.id, fresh.id].sort())
    await operate({ command: "revoke-key", key: fresh.id, confirm: "globex" })
    const allEnding = await page(f, "/platforms/globex", f.sam)
    expect(allEnding.body).not.toContain('data-form="revoke-key"')
    expect(allEnding.body).toContain('data-region="last-key"')
  })

  it("link the consoles only from the shells of an account that has them", async () => {
    const f = await setup()
    const alex = await page(f, "/account", f.alex)
    expect(alex.body).toContain('href="/operator"')
    expect(alex.body).not.toContain('href="/platforms"')
    const sam = await page(f, "/account", f.sam)
    expect(sam.body).toContain('href="/platforms"')
    expect(sam.body).not.toContain('href="/operator"')
    const kim = await page(f, "/account", f.kim)
    expect(kim.body).not.toMatch(/href="\/(operator|platforms)"/)
  })
})
