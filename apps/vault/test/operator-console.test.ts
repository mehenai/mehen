// The operator console and platform admins (routes/console.ts) through the
// real Worker, with real web sessions and the real passkey step-up.

import { runInDurableObject } from "cloudflare:test"
import { describe, expect, it } from "vitest"
import { type AdminChangeAnswer, type AdminPlatformCommand, type ConsoleAccess, DEFAULT_PLATFORM_LIMITS, type OperatorChangeAnswer, type OperatorCommand, type OperatorPlatformDetail, type OperatorPlatformList, type OperatorRequirement, type PlatformEventPage, canonicalJson, operatorRequirementsRefusal, operatorStepUpAction } from "@mehen/protocol"
import type { PlatformVault } from "../src/platform/platform-vault.ts"
import { maintainPlatforms } from "../src/platform/sweeps.ts"
import { type ConsoleFixture, type Person, answer, consoleFixture } from "./console-support.ts"
import { addSubject, newPlatformKey } from "./platform-fixtures.ts"

const HIDDEN = { error: "not_found", message: "No such operation." }

type Setup = ConsoleFixture & { alex: Person; sam: Person; kim: Person }

// Alex is the operator; Sam will be an admin; Kim is neither.
async function setup(): Promise<Setup> {
  const f = await consoleFixture()
  await f.grantOperator("acc_owner")
  return { ...f, alex: await f.person("acc_owner"), sam: await f.person("acc_admin"), kim: await f.person("acc_member") }
}

async function operate(f: Setup, slug: string, command: OperatorCommand, who: Person = f.alex): Promise<Response> {
  const stepUp = await f.operatorProof(who, slug, command)
  return command.command === "register" ? f.request("/api/operator/platforms", who, { command, stepUp }) : f.request(`/api/operator/platforms/${slug}`, who, { command, stepUp })
}

async function administer(f: Setup, slug: string, command: AdminPlatformCommand, who: Person = f.sam): Promise<Response> {
  return f.request(`/api/platforms/${slug}`, who, { command, stepUp: await f.adminProof(who, slug, command) })
}

async function register(f: Setup, slug: string): Promise<OperatorChangeAnswer> {
  const { jwk } = await newPlatformKey()
  return answer<OperatorChangeAnswer>(await operate(f, slug, { command: "register", slug, name: `Platform ${slug}`, key: jwk, limits: {}, confirm: slug }), 201)
}

// The refusal of an operator write from an account that lacks something an
// operator account must have.
function notReady(f: ConsoleFixture, missing: OperatorRequirement[]): unknown {
  return { error: "forbidden", message: operatorRequirementsRefusal(missing), next: { url: `${f.env.VAULT_ORIGIN}/account`, say: "Your account page shows your passkeys, your recovery and any cooling-off; come back once nothing is missing." } }
}

async function refusal(response: Response, status: number, body: unknown): Promise<void> {
  expect({ status: response.status, body: await response.json() }).toEqual({ status, body })
}

async function events(f: Setup, platform: string): Promise<{ actor: string; action: string }[]> {
  return (await f.env.DB.prepare("SELECT actor,action FROM platform_events WHERE platform=? AND action!='platform.activity' ORDER BY at,rowid").bind(platform).all<{ actor: string; action: string }>()).results
}

describe("who sees the console", () => {
  it("gives every operator and admin route not_found to an account without the role, and to anyone signed out", async () => {
    const f = await setup()
    const globex = await register(f, "globex")
    const reads = ["/api/operator/platforms", "/api/operator/platforms/globex", "/api/operator/platforms/globex/events", "/api/operator/platforms/nothing", "/api/platforms", "/api/platforms/globex", "/api/platforms/globex/events"]
    const writes = ["/api/operator/stepup/start", "/api/operator/platforms", "/api/operator/platforms/globex", "/api/platforms/globex", "/api/platforms/globex/stepup/start"]
    for (const who of [f.kim, f.sam, undefined]) {
      for (const path of reads) await refusal(await f.request(path, who), 404, HIDDEN)
      for (const path of writes) await refusal(await f.request(path, who, { command: { command: "resume" } }), 404, HIDDEN)
    }
    // The operator is not an admin of a platform until added.
    for (const path of ["/api/platforms", "/api/platforms/globex", "/api/platforms/globex/events"]) await refusal(await f.request(path, f.alex), 404, HIDDEN)
    expect(await answer<ConsoleAccess>(await f.request("/api/account/console", f.kim))).toEqual({ operator: false, platforms: [] })
    expect(await answer<ConsoleAccess>(await f.request("/api/account/console", f.alex))).toEqual({ operator: true, platforms: [] })
    // The console's step-ups never start on the account's own route.
    await refusal(await f.request("/api/account/stepup/start", f.alex, { action: { type: "platform.operate", platform: "globex", platformId: "plt_globex0000", command: "resume", digest: "x" } }), 404, HIDDEN)
    expect(globex.platform.slug).toBe("globex")
  })

  it("answers a slug no platform could have, such as a NUL, as it answers one no platform has", async () => {
    const f = await setup()
    await register(f, "globex")
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }))
    for (const slug of ["%00", "er%00ys", "%27%00"]) {
      for (const who of [f.kim, f.sam, f.alex, undefined]) {
        for (const path of [`/api/platforms/${slug}`, `/api/platforms/${slug}/events`]) await refusal(await f.request(path, who), 404, HIDDEN)
        await refusal(await f.request(`/api/platforms/${slug}/stepup/start`, who, { action: { type: "platform.administer", platform: "globex", platformId: "plt_globex0000", command: "revoke-key", digest: "x" } }), 404, HIDDEN)
      }
      for (const who of [f.kim, f.sam, undefined]) await refusal(await f.request(`/api/operator/platforms/${slug}`, who), 404, HIDDEN)
      for (const path of [`/api/operator/platforms/${slug}`, `/api/operator/platforms/${slug}/events`]) await refusal(await f.request(path, f.alex), 404, { error: "not_found", message: "No such platform." })
      await refusal(await f.request(`/api/operator/platforms/${slug}`, f.alex, { command: { command: "resume" } }), 404, { error: "not_found", message: "No such platform." })
    }
  })

  it("the role is set only with an explicit operator actor and a fresh operation, which records an event and a notice", async () => {
    const f = await setup()
    expect(await f.env.DB.prepare("SELECT action,detail FROM account_events WHERE account='acc_owner'").first()).toEqual({ action: "operator.grant_operator", detail: JSON.stringify({ by: "operator:test", operator: 1 }) })
    expect(await f.env.DB.prepare("SELECT kind,payload FROM account_notices WHERE account='acc_owner'").first()).toEqual({ kind: "workspace", payload: JSON.stringify({ change: "operator_role", operator: 1, by: "operator:test" }) })
    await expect(f.env.DB.prepare("UPDATE accounts SET is_operator=1 WHERE id='acc_member'").run()).rejects.toThrow("explicit operator actor required")
    await expect(f.env.DB.prepare("UPDATE accounts SET is_operator=0 WHERE id='acc_owner'").run()).rejects.toThrow("fresh operator operation required")
  })

  // An UPDATE's SET clause, within one SQL string: a WHERE that only reads
  // the role (an account that is not an operator) sets nothing.
  it("the Worker changes the role only in an applied operator proposal: one source names its operation column", () => {
    const sources = import.meta.glob<string>("../src/**/*.ts", { query: "?raw", import: "default", eager: true })
    expect(Object.keys(sources).some((file) => file.endsWith("/routes/console.ts"))).toBe(true)
    expect(Object.entries(sources).filter(([, text]) => text.includes("is_operator_op") || /SET\s(?:(?!\bWHERE\b)[^;'"`])*\bis_operator\s*=/.test(text)).map(([file]) => file)).toEqual(["../src/directory/operator-proposal-kinds.ts"])
  })
})

describe("the passkey on every write", () => {
  it("refuses an operator or admin write without a step-up, or with one for another command, and writes nothing", async () => {
    const f = await setup()
    const { jwk } = await newPlatformKey()
    const command: OperatorCommand = { command: "register", slug: "globex", name: "Globex", key: jwk, limits: {}, confirm: "globex" }
    await refusal(await f.request("/api/operator/platforms", f.alex, { command }), 403, { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    const other = await f.operatorProof(f.alex, "globex", { ...command, name: "Something else" })
    expect((await f.request("/api/operator/platforms", f.alex, { command, stepUp: other })).status).toBe(403)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM platforms").first()).toEqual({ n: 0 })
    await register(f, "globex")
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }))
    const limits: OperatorCommand = { command: "limits", limits: { callsPerMinute: 100 } }
    expect((await f.request("/api/operator/platforms/globex", f.alex, { command: limits })).status).toBe(403)
    const defaults: AdminPlatformCommand = { command: "defaults", defaults: { scopes: {}, tags: ["globex"], customReads: "approve", rules: {} }, revision: 1 }
    expect((await f.request("/api/platforms/globex", f.sam, { command: defaults })).status).toBe(403)
    // A proof is the account's own: Alex's passkey cannot stand in for Sam's.
    const alexs = await f.proof(f.alex, "/api/operator/stepup/start", { type: "platform.operate", platform: "globex", platformId: "plt_globex0000", command: "limits", digest: "x" })
    expect((await f.request("/api/platforms/globex", f.sam, { command: defaults, stepUp: alexs })).status).toBe(403)
    expect(await f.env.DB.prepare("SELECT limits,defaults_rev FROM platforms WHERE slug='globex'").first()).toEqual({ limits: canonicalJson(DEFAULT_PLATFORM_LIMITS), defaults_rev: 1 })
  })

  it("refuses a write with no step-up before planning it, so a plan's answer never reaches a session without the passkey", async () => {
    const f = await setup()
    await register(f, "globex")
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }))
    const { jwk } = await newPlatformKey()
    const passkey = { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." }
    // With a proof, each of these is the plan's own refusal (409).
    await refusal(await f.request("/api/operator/platforms", f.alex, { command: { command: "register", slug: "globex", name: "Again", key: jwk, limits: {}, confirm: "globex" } }), 403, passkey)
    await refusal(await f.request("/api/operator/platforms/globex", f.alex, { command: { command: "add-admin", account: "acc_nobody" } }), 403, passkey)
    const registered = JSON.parse((await f.env.DB.prepare("SELECT jwk FROM platform_keys").first<{ jwk: string }>())!.jwk) as Record<string, unknown>
    await refusal(await f.request("/api/platforms/globex", f.sam, { command: { command: "rotate-key", key: registered, overlapHours: 1, confirm: "globex" } }), 403, passkey)
  })

  it("refuses a step-up older than five minutes", async () => {
    const f = await setup()
    await register(f, "globex")
    const command: OperatorCommand = { command: "limits", limits: { callsPerMinute: 100 } }
    const stepUp = await f.operatorProof(f.alex, "globex", command)
    await f.env.DB.prepare("UPDATE challenges SET expires_at=? WHERE kind='stepup-v2'").bind(Date.now() - 1).run()
    expect((await f.request("/api/operator/platforms/globex", f.alex, { command, stepUp })).status).toBe(403)
  })

  it("binds the step-up to the platform's id, so an unused proof for one platform never serves another later under its slug", async () => {
    const f = await setup()
    const first = await register(f, "globex")
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }))
    const command: OperatorCommand = { command: "limits", limits: { callsPerMinute: 100 } }
    const stepUp = await f.operatorProof(f.alex, "globex", command)
    const { jwk } = await newPlatformKey()
    const adminCommand: AdminPlatformCommand = { command: "rotate-key", key: jwk, overlapHours: 24, confirm: "globex" }
    const adminStepUp = await f.adminProof(f.sam, "globex", adminCommand)
    // The slug comes free (as a removal frees it) and a new platform takes
    // it, registered by a second operator account so Alex's and Sam's
    // passkeys sign nothing after their proofs.
    await f.env.DB.prepare("UPDATE platforms SET slug='globex-before' WHERE id=?").bind(first.platform.id).run()
    await f.grantOperator("acc_guest")
    const guest = await f.person("acc_guest")
    const fresh = await newPlatformKey()
    const second = await answer<OperatorChangeAnswer>(await operate(f, "globex", { command: "register", slug: "globex", name: "Globex again", key: fresh.jwk, limits: {}, confirm: "globex" }, guest), 201)
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }, guest))
    await refusal(await f.request("/api/operator/platforms/globex", f.alex, { command, stepUp }), 403, { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    await refusal(await f.request("/api/platforms/globex", f.sam, { command: adminCommand, stepUp: adminStepUp }), 403, { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    expect(await f.env.DB.prepare("SELECT limits FROM platforms WHERE id=?").bind(second.platform.id).first()).toEqual({ limits: canonicalJson(DEFAULT_PLATFORM_LIMITS) })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM platform_keys WHERE platform=?").bind(second.platform.id).first()).toEqual({ n: 1 })
  })

  it("never accepts the same assertion twice", async () => {
    const f = await setup()
    await register(f, "globex")
    const command: OperatorCommand = { command: "limits", limits: { callsPerMinute: 100 } }
    const stepUp = await f.operatorProof(f.alex, "globex", command)
    await answer(await f.request("/api/operator/platforms/globex", f.alex, { command, stepUp }))
    await refusal(await f.request("/api/operator/platforms/globex", f.alex, { command, stepUp }), 403, { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." })
    expect((await events(f, (await f.env.DB.prepare("SELECT id FROM platforms WHERE slug='globex'").first<{ id: string }>())!.id)).map((e) => e.action)).toEqual(["operator.register", "operator.limits"])
  })

  it("asks for the slug typed back on a destructive command, before the passkey", async () => {
    const f = await setup()
    await register(f, "globex")
    for (const command of [{ command: "suspend", reason: "Odd traffic", confirm: "eris" }, { command: "remove", reason: "Again", confirm: "GLOBEX" }, { command: "retire", afterDays: 0, confirm: "globex " }]) {
      await refusal(await f.request("/api/operator/platforms/globex", f.alex, { command }), 400, { error: "bad_request", message: "Type the platform's slug to confirm." })
    }
    expect(await f.env.DB.prepare("SELECT status FROM platforms WHERE slug='globex'").first()).toEqual({ status: "active" })
  })

  it("asks for the slug typed back on every key added, for the operator and an admin alike, whatever the overlap", async () => {
    const f = await setup()
    await register(f, "globex")
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }))
    const { jwk } = await newPlatformKey()
    const typeIt = { error: "bad_request", message: "Type the platform's slug to confirm." }
    await refusal(await f.request("/api/operator/platforms", f.alex, { command: { command: "register", slug: "other", name: "Other", key: jwk, limits: {}, confirm: "globex" } }), 400, typeIt)
    for (const overlapHours of [0, 24]) {
      await refusal(await f.request("/api/operator/platforms/globex", f.alex, { command: { command: "rotate-key", key: jwk, overlapHours, confirm: "other" } }), 400, typeIt)
      await refusal(await f.request("/api/platforms/globex", f.sam, { command: { command: "rotate-key", key: jwk, overlapHours, confirm: "Globex" } }), 400, typeIt)
    }
    // Leaving it out is refused by the command's schema.
    await refusal(await f.request("/api/platforms/globex", f.sam, { command: { command: "rotate-key", key: jwk, overlapHours: 0 } }), 400, expect.objectContaining({ error: "bad_request" }))
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM platform_keys").first()).toEqual({ n: 1 })
  })
})

describe("what ends a console write", () => {
  it("revoking the role from the script hides every operator route at once, the read and a write with a fresh proof", async () => {
    const f = await setup()
    await register(f, "globex")
    const command: OperatorCommand = { command: "limits", limits: { callsPerMinute: 100 } }
    const stepUp = await f.operatorProof(f.alex, "globex", command)
    await f.revokeOperator("acc_owner")
    for (const path of ["/api/operator/platforms", "/api/operator/platforms/globex", "/api/operator/platforms/globex/events"]) await refusal(await f.request(path, f.alex), 404, HIDDEN)
    await refusal(await f.request("/api/operator/platforms/globex", f.alex, { command, stepUp }), 404, HIDDEN)
    expect(await f.env.DB.prepare("SELECT limits FROM platforms WHERE slug='globex'").first()).toEqual({ limits: canonicalJson(DEFAULT_PLATFORM_LIMITS) })
  })

  it("an account that is both operator and admin cannot use one role's proof on the other's route", async () => {
    const f = await setup()
    await register(f, "globex")
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_owner" }))
    const { jwk } = await newPlatformKey()
    // rotate-key has the same terms on both routes; only the step-up's type differs.
    const command = { command: "rotate-key", key: jwk, overlapHours: 24, confirm: "globex" } as const
    const asAdmin = await f.adminProof(f.alex, "globex", command)
    const asOperator = await f.operatorProof(f.alex, "globex", command)
    const passkey = { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." }
    await refusal(await f.request("/api/operator/platforms/globex", f.alex, { command, stepUp: asAdmin }), 403, passkey)
    await refusal(await f.request("/api/platforms/globex", f.alex, { command, stepUp: asOperator }), 403, passkey)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM platform_keys").first()).toEqual({ n: 1 })
  })

  it("refuses an operator's or an admin's write while the account cools off after a recovery, or has a security change pending", async () => {
    const f = await setup()
    await register(f, "globex")
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }))
    const command: OperatorCommand = { command: "limits", limits: { callsPerMinute: 100 } }
    const defaults: AdminPlatformCommand = { command: "defaults", defaults: { scopes: {}, tags: ["globex"], customReads: "approve", rules: {} }, revision: 1 }
    const operatorProof = await f.operatorProof(f.alex, "globex", command)
    const adminProof = await f.adminProof(f.sam, "globex", defaults)
    const until = Date.now() + 3_600_000
    await f.env.DB.prepare("UPDATE accounts SET restricted_until=?,restricted_reason='recovery' WHERE id IN ('acc_owner','acc_admin')").bind(until).run()
    const coolingOff = { error: "forbidden", message: "Your account is cooling off. You can read, narrow, deny, revoke and freeze, but cannot widen access.", next: { url: `${f.env.VAULT_ORIGIN}/account`, say: `It ends ${new Date(until).toISOString().slice(0, 16).replace("T", " ")} UTC; until then, ask another owner or admin if this cannot wait.` } }
    // The operator is told it is the cooling-off that an operator account
    // must not have; the admin gets the step-up's own refusal.
    const operatorCoolingOff = notReady(f, ["cooling-off"])
    await refusal(await f.request("/api/operator/platforms/globex", f.alex, { command, stepUp: operatorProof }), 403, operatorCoolingOff)
    await refusal(await f.request("/api/platforms/globex", f.sam, { command: defaults, stepUp: adminProof }), 403, coolingOff)
    // Nor can a new step-up start meanwhile; reads stay open.
    await refusal(await f.request("/api/operator/stepup/start", f.alex, { action: await operatorStepUpAction("globex", (await f.env.DB.prepare("SELECT id FROM platforms WHERE slug='globex'").first<{ id: string }>())!.id, command) }), 403, operatorCoolingOff)
    expect((await f.request("/api/operator/platforms/globex", f.alex)).status).toBe(200)
    await f.env.DB.prepare("UPDATE accounts SET restricted_until=NULL,restricted_reason=NULL,security_transition='trn_pending' WHERE id IN ('acc_owner','acc_admin')").run()
    await refusal(await f.request("/api/operator/platforms/globex", f.alex, { command, stepUp: operatorProof }), 403, notReady(f, ["security-change"]))
    expect(await answer(await f.request("/api/platforms/globex", f.sam, { command: defaults, stepUp: adminProof }), 403)).toMatchObject({ error: "account_pending" })
    expect(await f.env.DB.prepare("SELECT limits,defaults_rev FROM platforms WHERE slug='globex'").first()).toEqual({ limits: canonicalJson(DEFAULT_PLATFORM_LIMITS), defaults_rev: 1 })
  })
})

describe("what an operator account must have", () => {
  it("refuses every operator write and step-up from an account without a security key, saying so before any passkey, and the list says so too", async () => {
    const f = await consoleFixture()
    await f.grantOperator("acc_owner")
    const alex = await f.person("acc_owner", "device")
    const { jwk } = await newPlatformKey()
    const command: OperatorCommand = { command: "register", slug: "globex", name: "Globex", key: jwk, limits: {}, confirm: "globex" }
    await refusal(await f.request("/api/operator/stepup/start", alex, { action: await operatorStepUpAction("globex", null, command) }), 403, notReady(f, ["security-key"]))
    await refusal(await f.request("/api/operator/platforms", alex, { command }), 403, notReady(f, ["security-key"]))
    expect((await answer<OperatorPlatformList>(await f.request("/api/operator/platforms", alex))).missing).toEqual(["security-key"])
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM platforms").first()).toEqual({ n: 0 })
    // One passkey only: no recovery either, and every missing thing is named.
    const kim = await f.person("acc_member", "none")
    await f.grantOperator("acc_member")
    await refusal(await f.request("/api/operator/platforms", kim, { command }), 403, notReady(f, ["recovery", "two-passkeys", "security-key"]))
    // With a security key the same account registers.
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"usb\"]' WHERE account='acc_owner' AND credential_id LIKE 'second-%'").run()
    expect((await answer<OperatorPlatformList>(await f.request("/api/operator/platforms", alex))).missing).toEqual([])
    await answer(await f.request("/api/operator/platforms", alex, { command, stepUp: await f.operatorProof(alex, "globex", command) }), 201)
  })

  it("a write whose security key is gone by the time it arrives is refused and writes nothing", async () => {
    const f = await setup()
    await register(f, "globex")
    const command: OperatorCommand = { command: "limits", limits: { callsPerMinute: 100 } }
    const stepUp = await f.operatorProof(f.alex, "globex", command)
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"internal\"]' WHERE account='acc_owner'").run()
    await refusal(await f.request("/api/operator/platforms/globex", f.alex, { command, stepUp }), 403, notReady(f, ["security-key"]))
    expect(await f.env.DB.prepare("SELECT limits FROM platforms WHERE slug='globex'").first()).toEqual({ limits: canonicalJson(DEFAULT_PLATFORM_LIMITS) })
  })
})

describe("the operator", () => {
  it("the platform list carries the deployment's workspace creation rule", async () => {
    const f = await setup()
    expect((await answer<OperatorPlatformList>(await f.request("/api/operator/platforms", f.alex))).workspaceCreation).toBe("operator")
    f.env.WORKSPACE_CREATION = "accounts"
    expect((await answer<OperatorPlatformList>(await f.request("/api/operator/platforms", f.alex))).workspaceCreation).toBe("accounts")
  })
  it("registers, lists, reads, suspends, resumes, rotates, revokes, sets limits and retires, each with an event, a notice and the actor operator:<account>", async () => {
    const f = await setup()
    const created = await register(f, "globex")
    expect(created.done).toMatch(/^Registered globex\. Platform id plt_/)
    expect(created.platform).toMatchObject({ slug: "globex", name: "Platform globex", status: "active", createdBy: "operator:acc_owner", limits: DEFAULT_PLATFORM_LIMITS, subjects: { creating: 0, active: 0, deleting: 0, deleted: 0, purged: 0 }, admins: [], removal: null, usage: null, defaultsRevision: 1 })
    expect(created.platform.keys).toHaveLength(1)
    const [firstKey] = created.platform.keys
    await addSubject(f.env, created.platform.id, "subject-one")
    expect((await answer<OperatorPlatformList>(await f.request("/api/operator/platforms", f.alex))).platforms.map((p) => [p.slug, p.subjects.active])).toEqual([["globex", 1]])
    await answer(await operate(f, "globex", { command: "suspend", reason: "Odd traffic", confirm: "globex" }))
    await answer(await operate(f, "globex", { command: "resume" }))
    const { jwk } = await newPlatformKey()
    const rotated = await answer<OperatorChangeAnswer>(await operate(f, "globex", { command: "rotate-key", key: jwk, overlapHours: 2, confirm: "globex" }))
    expect(rotated.platform.keys.map((k) => k.live)).toEqual([true, true])
    await answer(await operate(f, "globex", { command: "revoke-key", key: firstKey!.id, confirm: "globex" }))
    await answer(await operate(f, "globex", { command: "limits", limits: { subjects: 5 } }))
    const retired = await answer<OperatorChangeAnswer>(await operate(f, "globex", { command: "retire", afterDays: 7, confirm: "globex" }))
    expect(retired.platform).toMatchObject({ status: "retiring", statusBy: "operator:acc_owner", limits: { ...DEFAULT_PLATFORM_LIMITS, subjects: 5 } })
    const detail = await answer<OperatorPlatformDetail>(await f.request("/api/operator/platforms/globex", f.alex))
    expect(detail.operatorActions24h).toBe(7)
    const log = await events(f, created.platform.id)
    expect(log.map((e) => e.action)).toEqual(["operator.register", "operator.suspend", "operator.resume", "operator.rotate_key", "operator.revoke_key", "operator.limits", "operator.retire"])
    expect(new Set(log.map((e) => e.actor))).toEqual(new Set(["operator:acc_owner"]))
    const page = await answer<PlatformEventPage>(await f.request("/api/operator/platforms/globex/events", f.alex))
    expect(page.events.map((e) => e.action)).toEqual([...log.map((e) => e.action)].reverse())
    const notices = (await f.env.DB.prepare("SELECT payload FROM account_notices WHERE account='acc_owner' AND json_extract(payload,'$.change')='platform' ORDER BY at,rowid").all<{ payload: string }>()).results.map((r) => JSON.parse(r.payload).command)
    expect(notices).toEqual(["register", "suspend", "resume", "rotate-key", "revoke-key", "limits", "retire"])
  })

  it("refuses what the script refuses, with the same reasons", async () => {
    const f = await setup()
    await register(f, "globex")
    const { jwk } = await newPlatformKey()
    await refusal(await operate(f, "globex", { command: "register", slug: "globex", name: "Again", key: jwk, limits: {}, confirm: "globex" }), 409, { error: "conflict", message: "Nothing changed: a platform with that slug exists." })
    await refusal(await operate(f, "removed-abc", { command: "register", slug: "removed-abc", name: "Sneaky", key: jwk, limits: {}, confirm: "removed-abc" }), 409, { error: "conflict", message: "Nothing changed: slugs starting removed- are kept for removed platforms." })
    const { privateKey } = await newPlatformKey()
    await refusal(await operate(f, "other", { command: "register", slug: "other", name: "Other", key: { ...(await crypto.subtle.exportKey("jwk", privateKey)) }, limits: {}, confirm: "other" }), 400, { error: "bad_request", message: "The key holds a private part; send only the public half." })
    await refusal(await operate(f, "other", { command: "register", slug: "other", name: "Other", key: jwk, limits: { decisionTtlSeconds: 3600 }, confirm: "other" }), 400, expect.objectContaining({ error: "bad_request" }))
    await refusal(await operate(f, "globex", { command: "resume" }), 409, { error: "conflict", message: "Nothing changed: the platform is active." })
    await refusal(await operate(f, "globex", { command: "delete-subjects", reason: "None", confirm: "globex" }), 409, { error: "conflict", message: "Nothing changed: the platform has no live subjects." })
  })

  it("refuses a register that loses a race for its slug or key with Nothing changed, not a 500", async () => {
    const f = await setup()
    // Another write takes the slug, or the key, between the plan and the batch.
    await f.env.DB.prepare("CREATE TRIGGER race_slug BEFORE INSERT ON platforms WHEN NEW.slug='racing' BEGIN INSERT INTO platforms (id,slug,name,status,limits,defaults,defaults_rev,created_at,created_by,status_at,status_by) VALUES ('plt_racer0001',NEW.slug,'Racer','active',NEW.limits,NEW.defaults,1,NEW.created_at,'operator:racer',NEW.status_at,'operator:racer'); END").run()
    await f.env.DB.prepare("CREATE TRIGGER race_key BEFORE INSERT ON platform_keys WHEN NEW.platform<>'plt_racer0002' AND EXISTS (SELECT 1 FROM platforms WHERE id=NEW.platform AND slug='keyrace') BEGIN INSERT INTO platforms (id,slug,name,status,limits,defaults,defaults_rev,created_at,created_by,status_at,status_by) VALUES ('plt_racer0002','keyracer','Racer','active','{}','{}',1,0,'operator:racer',0,'operator:racer'); INSERT INTO platform_keys (id,platform,jwk,thumbprint,created_at,created_by) VALUES ('pky_racer0002','plt_racer0002',NEW.jwk,NEW.thumbprint,0,'operator:racer'); END").run()
    const changed = { error: "conflict", message: "Nothing changed: the platform changed while this ran. Read it again and retry." }
    for (const slug of ["racing", "keyrace"]) {
      const { jwk } = await newPlatformKey()
      await refusal(await operate(f, slug, { command: "register", slug, name: "Racing", key: jwk, limits: {}, confirm: slug }), 409, changed)
    }
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM platforms").first()).toEqual({ n: 0 })
  })

  it("adds and removes a platform's admins, each recorded with a notice to them", async () => {
    const f = await setup()
    const globex = await register(f, "globex")
    await refusal(await operate(f, "globex", { command: "add-admin", account: "acc_nobody" }), 409, { error: "conflict", message: "Nothing changed: no active account with that id." })
    const added = await answer<OperatorChangeAnswer>(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }))
    expect(added.platform.admins).toEqual([{ account: "acc_admin", name: "admin", addedAt: expect.any(String), addedBy: "operator:acc_owner" }])
    await refusal(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }), 409, { error: "conflict", message: "Nothing changed: that account is already an admin of the platform." })
    expect(await answer<ConsoleAccess>(await f.request("/api/account/console", f.sam))).toEqual({ operator: false, platforms: [{ id: globex.platform.id, slug: "globex", name: "Platform globex" }] })
    expect((await f.env.DB.prepare("SELECT payload FROM account_notices WHERE account='acc_admin'").first<{ payload: string }>())?.payload).toBe(JSON.stringify({ change: "platform_admin", admin: true, platform: { id: globex.platform.id, slug: "globex" }, by: "operator:acc_owner" }))
    await answer(await operate(f, "globex", { command: "remove-admin", account: "acc_admin" }))
    await refusal(await f.request("/api/platforms/globex", f.sam), 404, HIDDEN)
    expect((await events(f, globex.platform.id)).map((e) => e.action)).toEqual(["operator.register", "operator.add_admin", "operator.remove_admin"])
  })
})

describe("a platform admin", () => {
  async function withAdmin(): Promise<Setup & { globex: OperatorChangeAnswer; other: OperatorChangeAnswer }> {
    const f = await setup()
    const globex = await register(f, "globex")
    const other = await register(f, "other")
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }))
    return { ...f, globex, other }
  }

  it("sees only their own platforms, and nothing of another or of the operator's", async () => {
    const f = await withAdmin()
    expect((await answer<{ platforms: { slug: string }[] }>(await f.request("/api/platforms", f.sam))).platforms.map((p) => p.slug)).toEqual(["globex"])
    expect(await answer(await f.request("/api/platforms/globex", f.sam))).toMatchObject({ slug: "globex", status: "active", limits: DEFAULT_PLATFORM_LIMITS, defaultsRevision: 1, usage: null })
    for (const path of ["/api/platforms/other", "/api/platforms/other/events", "/api/operator/platforms", "/api/operator/platforms/globex"]) await refusal(await f.request(path, f.sam), 404, HIDDEN)
    await refusal(await f.request("/api/platforms/other/stepup/start", f.sam, { action: { type: "platform.administer", platform: "other", platformId: "plt_other0000", command: "revoke-key", digest: "x" } }), 404, HIDDEN)
    // An operator's command is not an admin's, and the admin's step-up
    // cannot be started for another platform or as the operator's.
    await refusal(await f.request("/api/platforms/globex", f.sam, { command: { command: "suspend", reason: "No", confirm: "globex" } }), 400, expect.objectContaining({ error: "bad_request" }))
    await refusal(await f.request("/api/platforms/globex/stepup/start", f.sam, { action: { type: "platform.administer", platform: "other", platformId: "plt_other0000", command: "revoke-key", digest: "x" } }), 400, { error: "bad_request", message: "That action does not belong to this scope." })
    await refusal(await f.request("/api/platforms/globex/stepup/start", f.sam, { action: { type: "platform.administer", platform: "globex", platformId: f.other.platform.id, command: "revoke-key", digest: "x" } }), 400, { error: "bad_request", message: "That action does not belong to this scope." })
    await refusal(await f.request("/api/platforms/globex/stepup/start", f.sam, { action: { type: "platform.operate", platform: "globex", platformId: "plt_globex0000", command: "suspend", digest: "x" } }), 400, { error: "bad_request", message: "That action does not belong to this scope." })
    await refusal(await f.request("/api/operator/stepup/start", f.sam, { action: { type: "platform.operate", platform: "globex", platformId: "plt_globex0000", command: "suspend", digest: "x" } }), 404, HIDDEN)
  })

  it("edits the defaults with the platform's own rules, the revision moving, and refuses a stale or wider one", async () => {
    const f = await withAdmin()
    const defaults = { providers: ["github-oauth"], scopes: {}, tags: ["globex"], customReads: "approve" as const, rules: { "github-oauth": [{ action: "approve" as const, methods: ["GET"], paths: ["/repos/*/*/contents/**"], note: "reading a repository's files" }] } }
    const changed = await answer<AdminChangeAnswer>(await administer(f, "globex", { command: "defaults", defaults, revision: 1 }))
    expect(changed.platform).toMatchObject({ defaults, defaultsRevision: 2 })
    await refusal(await administer(f, "globex", { command: "defaults", defaults, revision: 1 }), 409, { error: "conflict", message: "Nothing changed: the defaults changed since they were read; read them again." })
    await refusal(await f.request("/api/platforms/globex", f.sam, { command: { command: "defaults", defaults: { ...defaults, templates: ["no-such-template"] }, revision: 2 } }), 400, expect.objectContaining({ error: "bad_request" }))
    const [event] = (await events(f, f.globex.platform.id)).filter((e) => e.action === "admin.defaults")
    expect(event).toEqual({ actor: "admin:acc_admin", action: "admin.defaults" })
  })

  it("adds a key with an overlap and revokes one, but never the last live key", async () => {
    const f = await withAdmin()
    const [first] = f.globex.platform.keys
    await refusal(await administer(f, "globex", { command: "revoke-key", key: first!.id, confirm: "globex" }), 409, { error: "conflict", message: "Nothing changed: that would leave the platform with no key once its other keys end; add a new key first." })
    const { jwk } = await newPlatformKey()
    const rotated = await answer<AdminChangeAnswer>(await administer(f, "globex", { command: "rotate-key", key: jwk, overlapHours: 0, confirm: "globex" }))
    const second = rotated.platform.keys.find((k) => k.id !== first!.id)!
    expect(rotated.platform.keys.map((k) => [k.id === first!.id, k.live])).toEqual([[true, false], [false, true]])
    await refusal(await administer(f, "globex", { command: "revoke-key", key: second.id, confirm: "globex" }), 409, { error: "conflict", message: "Nothing changed: that would leave the platform with no key once its other keys end; add a new key first." })
    await answer(await administer(f, "globex", { command: "revoke-key", key: first!.id, confirm: "globex" }))
    expect((await events(f, f.globex.platform.id)).filter((e) => e.actor === "admin:acc_admin").map((e) => e.action)).toEqual(["admin.rotate_key", "admin.revoke_key"])
  })

  it("never lets an admin revoke the new key while the old one is only live until its overlap ends", async () => {
    const f = await withAdmin()
    const [first] = f.globex.platform.keys
    const { jwk } = await newPlatformKey()
    const rotated = await answer<AdminChangeAnswer>(await administer(f, "globex", { command: "rotate-key", key: jwk, overlapHours: 1, confirm: "globex" }))
    const second = rotated.platform.keys.find((k) => k.id !== first!.id)!
    expect(rotated.platform.keys.map((k) => [k.id === first!.id, k.live, k.expiresAt === null])).toEqual([[true, true, false], [false, true, true]])
    await refusal(await administer(f, "globex", { command: "revoke-key", key: second.id, confirm: "globex" }), 409, { error: "conflict", message: "Nothing changed: that would leave the platform with no key once its other keys end; add a new key first." })
    const revoked = await f.env.DB.prepare("SELECT id FROM platform_keys WHERE platform=? AND revoked_at IS NOT NULL").bind(f.globex.platform.id).all<{ id: string }>()
    expect(revoked.results).toEqual([])
    await answer(await administer(f, "globex", { command: "revoke-key", key: first!.id, confirm: "globex" }))
  })

  it("tells every operator account and every other live admin when a key is added, by an admin or the operator", async () => {
    const f = await withAdmin()
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_member" }))
    await f.grantOperator("acc_guest")
    const told = async (command: string) =>
      (await f.env.DB.prepare("SELECT account,payload FROM account_notices WHERE json_extract(payload,'$.change')='platform' AND json_extract(payload,'$.command')=? ORDER BY account").bind(command).all<{ account: string; payload: string }>()).results.map((row) => ({ account: row.account, ...(JSON.parse(row.payload) as { by: string; key: string; platform: { slug: string } }) }))
    const ref = { id: f.globex.platform.id, slug: "globex" }
    const { jwk } = await newPlatformKey()
    const byAdmin = await answer<AdminChangeAnswer>(await administer(f, "globex", { command: "rotate-key", key: jwk, overlapHours: 24, confirm: "globex" }))
    const adminKey = byAdmin.platform.keys.find((k) => k.expiresAt === null)!.id
    const notice = { change: "platform", command: "rotate-key", platform: ref, by: "admin:acc_admin", key: adminKey }
    expect(await told("rotate-key")).toEqual(["acc_admin", "acc_guest", "acc_member", "acc_owner"].map((account) => ({ account, ...notice })))
    await f.env.DB.prepare("DELETE FROM account_notices").run()
    const second = await newPlatformKey()
    const byOperator = await answer<OperatorChangeAnswer>(await operate(f, "globex", { command: "rotate-key", key: second.jwk, overlapHours: 0, confirm: "globex" }))
    expect((await told("rotate-key")).map((n) => [n.account, n.by, n.key])).toEqual(["acc_admin", "acc_guest", "acc_member", "acc_owner"].map((account) => [account, "operator:acc_owner", byOperator.platform.keys.find((k) => k.expiresAt === null)!.id]))
    // A new platform has no admins yet: every operator account is told.
    const created = await register(f, "third")
    expect((await told("register")).filter((n) => n.platform.slug === "third").map((n) => [n.account, n.key])).toEqual([["acc_guest", created.platform.keys[0]!.id], ["acc_owner", created.platform.keys[0]!.id]])
  })

  it("answers a subject's deletion without a good passkey the same whether the subject exists or not", async () => {
    const f = await withAdmin()
    await addSubject(f.env, f.globex.platform.id, "subject-one")
    const asked = async (subject: string, stepUp?: unknown) => {
      const response = await f.request("/api/platforms/globex", f.sam, { command: { command: "delete-subject", subject, confirm: "globex" }, ...(stepUp === undefined ? {} : { stepUp }) })
      return { status: response.status, body: await response.json() }
    }
    const refused = { status: 403, body: { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." } }
    for (const stepUp of [undefined, { nonce: "made-up", assertion: {} }]) {
      expect(await asked("subject-one", stepUp)).toEqual(refused)
      expect(await asked("subject-nope", stepUp)).toEqual(refused)
    }
    expect(await f.env.DB.prepare("SELECT status FROM managed_workspaces WHERE platform=?").bind(f.globex.platform.id).first()).toEqual({ status: "active" })
  })

  it("deletes one subject by the subject the platform knows, typed in, and the event never names it", async () => {
    const f = await withAdmin()
    const tenant = await addSubject(f.env, f.globex.platform.id, "subject-one")
    const kept = await addSubject(f.env, f.globex.platform.id, "subject-two")
    await refusal(await administer(f, "globex", { command: "delete-subject", subject: "subject-nope", confirm: "globex" }), 409, { error: "conflict", message: "Nothing changed: the platform has no live subject by that name." })
    await answer(await administer(f, "globex", { command: "delete-subject", subject: "subject-one", confirm: "globex" }))
    expect(f.calls.filter((c) => c.op === "platform.subjects.remove").map((c) => [c.tenant, c.auth])).toEqual([[tenant, { kind: "system", reason: "platform admin console", actor: "admin:acc_admin" }]])
    expect((await f.env.DB.prepare("SELECT tenant,status FROM managed_workspaces ORDER BY tenant=?").bind(kept).all()).results).toEqual([{ tenant, status: "deleted" }, { tenant: kept, status: "active" }])
    const detail = (await f.env.DB.prepare("SELECT detail FROM platform_events WHERE action='admin.delete_subject'").first<{ detail: string }>())!.detail
    expect(detail).not.toContain("subject-one")
    expect(JSON.parse(detail)).toEqual({ tenant, subjectHash: expect.any(String) })
  })
})

describe("removing a platform", () => {
  it("retires it at once, deletes and purges every subject, frees the slug and keeps the record", async () => {
    const f = await setup()
    const globex = await register(f, "globex")
    const id = globex.platform.id
    const keyRow = await f.env.DB.prepare("SELECT jwk FROM platform_keys WHERE platform=?").bind(id).first<{ jwk: string }>()
    await answer(await operate(f, "globex", { command: "add-admin", account: "acc_admin" }))
    const live = await addSubject(f.env, id, "subject-live")
    const making = await addSubject(f.env, id, "subject-make", "creating")
    const waiting = await addSubject(f.env, id, "subject-gone", "deleted", { purgeAfter: Date.now() + 30 * 86_400_000 })
    const removed = await answer<OperatorChangeAnswer>(await operate(f, "globex", { command: "remove", reason: "Set up again", confirm: "globex" }))
    expect(removed.platform).toMatchObject({ status: "retiring", statusReason: "Set up again", admins: [], removal: { by: "operator:acc_owner", slug: "globex", completedAt: null }, subjects: { creating: 0, active: 0, deleting: 2, deleted: 1, purged: 0 } })
    await refusal(await f.request("/api/platforms/globex", f.sam), 404, HIDDEN)
    // The admin it ended is told, as removing one admin tells them.
    expect((await f.env.DB.prepare("SELECT payload FROM account_notices WHERE account='acc_admin' ORDER BY at,rowid").all<{ payload: string }>()).results.map((r) => JSON.parse(r.payload))).toEqual([
      { change: "platform_admin", admin: true, platform: { id, slug: "globex" }, by: "operator:acc_owner" },
      { change: "platform_admin", admin: false, platform: { id, slug: "globex" }, by: "operator:acc_owner" },
    ])
    await refusal(await operate(f, "globex", { command: "resume" }), 409, { error: "conflict", message: "Nothing changed: the platform is being removed." })
    const { jwk } = await newPlatformKey()
    await refusal(await operate(f, "globex", { command: "register", slug: "globex", name: "Globex", key: jwk, limits: {}, confirm: "globex" }), 409, { error: "conflict", message: "Nothing changed: globex is still held by the platform being removed; it is free once the cron has purged that platform's subjects, within 30 minutes for 50 or fewer." })

    await maintainPlatforms(f.env, Date.now())
    await maintainPlatforms(f.env, Date.now())

    // Every subject went through the subject lifecycle: deleted, then purged.
    expect(new Set(f.calls.filter((c) => c.op === "platform.subjects.remove").map((c) => c.tenant))).toEqual(new Set([live, making]))
    expect(new Set(f.calls.filter((c) => c.op === "platform.subjects.purge").map((c) => c.tenant))).toEqual(new Set([live, making, waiting]))
    // The record stays: the row under a reserved slug with the slug it had,
    // the keys revoked, the subjects' tombstones and every event.
    const row = await f.env.DB.prepare("SELECT slug,removed_slug,status,removed_at FROM platforms WHERE id=?").bind(id).first<{ slug: string; removed_slug: string; status: string; removed_at: number | null }>()
    expect(row).toMatchObject({ removed_slug: "globex", status: "retired", removed_at: expect.any(Number) })
    expect(row?.slug).toMatch(/^removed-[a-z2-7]{24}$/)
    expect((await f.env.DB.prepare("SELECT revoked_at IS NOT NULL AS revoked FROM platform_keys WHERE platform=?").bind(id).all()).results).toEqual([{ revoked: 1 }])
    expect((await f.env.DB.prepare("SELECT status,subject,subject_hash IS NOT NULL AS hashed,final_audit_head FROM managed_workspaces WHERE platform=? ORDER BY tenant").bind(id).all()).results).toEqual([live, making, waiting].sort().map((tenant) => ({ status: "purged", subject: null, hashed: 1, final_audit_head: `head-${tenant}` })))
    expect((await events(f, id)).map((e) => e.action)).toEqual(["operator.register", "operator.add_admin", "operator.remove", "platform.retired", "platform.removed"])
    expect(await runInDurableObject(f.env.PLATFORM_VAULT.getByName(id), (_: PlatformVault, state) => state.storage.sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '_cf_%'").toArray())).toEqual([])
    const list = await answer<OperatorPlatformList>(await f.request("/api/operator/platforms", f.alex))
    expect(list.platforms.map((p) => [p.slug === row?.slug, p.removal?.slug, p.removal?.completedAt !== null])).toEqual([[true, "globex", true]])

    // The slug is free again; the old key is not, because a key names one platform.
    await refusal(await operate(f, "globex", { command: "register", slug: "globex", name: "Globex", key: JSON.parse(keyRow!.jwk), limits: {}, confirm: "globex" }), 409, { error: "conflict", message: "Nothing changed: that key is already registered; the platform must make a new one." })
    const again = await answer<OperatorChangeAnswer>(await operate(f, "globex", { command: "register", slug: "globex", name: "Globex", key: jwk, limits: {}, confirm: "globex" }), 201)
    expect(again.platform).toMatchObject({ slug: "globex", status: "active", removal: null })
    expect(again.platform.id).not.toBe(id)
  })
})
