// Every operation uses worker.fetch. SQL is only for operator setup, injected
// failures and independent persisted-state assertions, never area handlers.
import { applyD1Migrations, createExecutionContext, runInDurableObject, waitOnExecutionContext } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { afterEach, beforeEach, expect, vi } from "vitest"
import { AccountSessionSchema, createProof, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, getTemplate, jwkThumbprint, seal, importSealPublicKey, sha256B64, webCryptoSigner, type CredentialHome, type InviteTerms, type WorkspaceRef, type WorkspaceStepUpAction, type WorkspaceDeviceScope } from "@mehen/protocol"
import { POLICY_FLOOR } from "@mehen/protocol/policy-safety"
import { CAPABILITIES } from "../../src/vault/areas/devices.ts"
import { enrolmentFingerprint } from "../../src/directory/enrolment.ts"
import { canonicalJson } from "@mehen/protocol/api"
import type { Env } from "../../src/env.ts"
import worker from "../../src/index.ts"
import type { Invocation, WorkspaceInvocation } from "../../src/vault/core.ts"
import { resetWorkspaceDatabase } from "../workspace-fixtures.ts"
import { ORIGIN } from "../helpers.ts"
import { newDeviceKey, publicJwk } from "../devices.ts"
import { assertion, registration, softwarePasskey, type SoftwarePasskey } from "./passkeys.ts"

let network: ReturnType<typeof vi.spyOn<typeof globalThis, "fetch">>
beforeEach(() => { network = vi.spyOn(globalThis, "fetch").mockImplementation(async () => { throw new Error("Unexpected real network call in a workspace journey") }) })
afterEach(() => { expect(network).not.toHaveBeenCalled(); network.mockRestore() })

export type Person = { account: string; cookie: string; passkey: SoftwarePasskey; counter: number; codes: string[]; member?: string; onboarding?: "bootstrap" | "join" }
export const acceptedScope = (privateCredentials = true): WorkspaceDeviceScope => ({ tags: [], projects: [], maxEnvironment: "unprotected", modes: ["relay", "sign", "mint", "placeholder"], privateCredentials })
export const expectedMember = (member: string, name: string, role: string) => ({ member, name, role, pendingRole: null, status: "active", teams: [], machines: 0, joinedAt: expect.any(String) })
export type Machine = { keys: CryptoKeyPair; device: string; workspace: WorkspaceRef }
export async function body<T>(response: Response, status = 200): Promise<T> {
  const text = await response.text()
  expect({ status: response.status, body: response.status === status ? undefined : text }).toEqual({ status, body: undefined })
  return JSON.parse(text) as T
}
export async function refusal(response: Response, status: number, expected: unknown): Promise<void> {
  expect(response.status).toBe(status)
  expect(response.headers.get("Mehen-Error")).toBe("1")
  expect(await response.json()).toEqual(expected)
}
export async function journey() {
  const db = env.WORKSPACE_DB
  await resetWorkspaceDatabase(db)
  await applyD1Migrations(db, env.TEST_MIGRATIONS)
   // Keep the real default-on Worker/DO dispatcher; this wrapper injects only
  // explicit lost-reply and unavailable-target faults.
  const faults = { lostReply: "", blockInstall: false, blockWorkspace: "", blockRestriction: false, installCalls: 0, holdInstall: null as Promise<void> | null }
  const namespace = new Proxy(env.TENANT_VAULT, { get(target, key) {
    if (key === "getByName") return (name: string) => {
      const stub = target.getByName(name)
      return new Proxy(stub, { get(object, prop) {
        if (prop === "cutoverGeneration") return () => object.cutoverGeneration()
        if (prop === "invoke") return async (input: Invocation | WorkspaceInvocation) => {
          if (input.op === "access.security.install") { faults.installCalls++; await faults.holdInstall }
          if (input.op === "access.security.install" && (faults.blockInstall || name === faults.blockWorkspace) || input.op === "access.security.restriction" && faults.blockRestriction) throw new Error("Injected unavailable workspace")
          const result = await object.invoke(input)
          if (input.op === faults.lostReply) { faults.lostReply = ""; throw new Error("Injected lost RPC reply after commit") }
          return result
        }
        const value = Reflect.get(object, prop) as unknown
        return typeof value === "function" ? value.bind(object) : value
      } })
    }
    const value = Reflect.get(target, key) as unknown
    return typeof value === "function" ? value.bind(target) : value
  } })
  const bindings: Env = { ...env, DB: db, TENANT_VAULT: namespace }
  async function request(path: string, person?: Person, input?: unknown, headers: Record<string, string> = {}, method = input === undefined ? "GET" : "POST") {
    const ctx = createExecutionContext()
    const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { method, headers: { origin: ORIGIN, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "content-type": "application/json", ...(person ? { cookie: person.cookie } : {}), ...headers }, ...(input === undefined ? {} : { body: JSON.stringify(input) }) }), bindings, ctx)
    await waitOnExecutionContext(ctx)
    return response
  }
  async function signup(invite: string, name: string): Promise<Person> {
    const passkey = await softwarePasskey()
    const { options } = await body<{ options: { challenge: string } }>(await request("/api/auth/signup/options", undefined, { invite, name }))
    const response = await request("/api/auth/signup/verify", undefined, { invite, name, response: await registration(passkey, options.challenge) })
    const cookie = response.headers.get("set-cookie")?.split(";")[0]
    expect(cookie).toBeTruthy()
    const { account, onboarding } = await body<{ account: string; onboarding: "bootstrap" | "join" }>(response)
    // Only the bootstrap account is granted workspace creation, in its own signup batch.
    const granted = onboarding === "bootstrap"
    expect(await db.prepare("SELECT name,can_create_workspaces,recovery_setup_at FROM accounts WHERE id=?").bind(account).first()).toEqual({ name, can_create_workspaces: granted ? 1 : 0, recovery_setup_at: null })
    const person: Person = { account, cookie: cookie!, passkey, counter: 0, codes: [], onboarding }
    expect(AccountSessionSchema.parse(await body(await request("/api/account", person))).canCreateWorkspaces).toBe(granted)
    return person
  }
  async function proof(person: Person, action: WorkspaceStepUpAction, slug?: string) {
    const start = slug ? `/api/w/${slug}/stepup/start` : "/api/account/stepup/start"
    const { nonce, options } = await body<{ nonce: string; options: { challenge: string } }>(await request(start, person, { action }))
    return { nonce, assertion: await assertion(person.passkey, options.challenge, ++person.counter) }
  }
  async function signed(path: string, person: Person, input: Record<string, unknown>, action: WorkspaceStepUpAction, slug?: string) {
    return request(path, person, { ...input, stepUp: await proof(person, action, slug) })
  }
  async function signin(person: Person) {
    const started = await body<{ flow: string; options: { challenge: string } }>(await request("/api/auth/signin/options", undefined, {}))
    const response = await request("/api/auth/signin/verify", undefined, { flow: started.flow, response: await assertion(person.passkey, started.options.challenge, ++person.counter) })
    person.cookie = response.headers.get("set-cookie")?.split(";")[0] ?? ""
    expect(await body(response)).toEqual({ account: person.account })
  }
  async function cron() { await worker.scheduled({} as ScheduledController, bindings) }
  async function recoverySetup(person: Person) {
    const generated = await body<{ batch: string; codes: string[]; confirmPosition: number; expiresAt: string }>(await signed("/api/account/recovery/generate", person, {}, { type: "recovery.generate" }))
    expect(generated.codes).toHaveLength(10)
    expect(await body(await request("/api/account/recovery/confirm", person, { batch: generated.batch, code: generated.codes[generated.confirmPosition - 1] }))).toEqual({})
    person.codes = generated.codes
    expect(await db.prepare("SELECT COUNT(*) AS n FROM recovery_codes WHERE account=? AND status='active'").bind(person.account).first()).toEqual({ n: 10 })
  }
  async function createWorkspace(person: Person, slug: string, name: string) {
    const workspace = await body<WorkspaceRef>(await signed("/api/workspaces", person, { slug, name }, { type: "workspace.create", slug, name }), 201)
    expect(workspace).toEqual({ id: expect.stringMatching(/^tn_/), slug, name })
    const membership = await db.prepare("SELECT id,state FROM memberships WHERE account=? AND workspace=?").bind(person.account, workspace.id).first<{ id: string; state: string }>()
    expect(membership?.state).toBe("member")
    return workspace
  }
  async function sql<T extends Record<string, SqlStorageValue>>(workspace: WorkspaceRef, query: string, ...values: SqlStorageValue[]): Promise<T[]> {
    return runInDurableObject(env.TENANT_VAULT.getByName(workspace.id), instance => instance.context.sql.exec<T>(query, ...values).toArray())
  }
  async function snapshot(workspace: WorkspaceRef) {
    return runInDurableObject(env.TENANT_VAULT.getByName(workspace.id), instance => {
      const sql = instance.context.sql
      return Object.fromEntries(sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' ORDER BY name").toArray().map(({ name }) => {
        if (!/^[a-z_][a-z0-9_]*$/.test(name)) throw new Error("Unexpected application table")
        return [name, sql.exec(`SELECT * FROM ${name}`).toArray()]
      }))
    })
  }
  async function member(person: Person, workspace: WorkspaceRef) {
    const row = await db.prepare("SELECT id FROM memberships WHERE account=? AND workspace=?").bind(person.account, workspace.id).first<{ id: string }>()
    if (!row) throw new Error("No membership")
    return row.id
  }
  async function project(person: Person, workspace: WorkspaceRef, slug = "platform") {
    const input = { slug, remote: null, defaultEnv: "dev", environments: [{ name: "dev", protected: false, fourEyes: false }, { name: "staging", protected: false, fourEyes: false }, { name: "prod", protected: true, fourEyes: true }] }
    const action = await body<WorkspaceStepUpAction>(await request(`/api/w/${workspace.slug}/projects/action`, person, { change: "create", input }))
    return body<{ id: string; slug: string }>(await signed(`/api/w/${workspace.slug}/projects`, person, input, action, workspace.slug), 201)
  }
  async function invite(owner: Person, workspace: WorkspaceRef, terms: InviteTerms, email = false) {
    const result = await body<{ url: string; invite: { id: string }; emailed: string }>(await signed(`/api/w/${workspace.slug}/invites`, owner, { terms, email }, { type: "member.invite", terms }, workspace.slug), 201)
    return { ...result, code: result.url.split("#")[1]! }
  }
  async function memberChange(owner: Person, workspace: WorkspaceRef, id: string, change: "confirm" | "role" | "remove", role?: string) {
    const input = { change, ...(role ? { role } : {}) }
    const { action } = await body<{ action: WorkspaceStepUpAction }>(await request(`/api/w/${workspace.slug}/members/${id}/action`, owner, input))
    return signed(`/api/w/${workspace.slug}/members/${id}/${change}`, owner, role ? { role } : {}, action, workspace.slug)
  }
  async function guest(owner: Person, workspace: WorkspaceRef, projectId: string, name: string, confirm = true) {
    const terms: InviteTerms = { role: "guest", email: null, teams: [], shares: [{ project: projectId, level: "edit", protected: true, expiresAt: null }], expiresAt: new Date(Date.now() + 86400000).toISOString() }
    const issued = await invite(owner, workspace, terms)
    const person = await signup(issued.code, name)
    await recoverySetup(person)
    const joined = await body<{ member: string; state: string }>(await request("/api/account/invites/join", person, { code: issued.code }))
    expect(joined).toEqual({ member: expect.stringMatching(/^mem_/), state: "pending_confirmation" })
    person.member = joined.member
    if (confirm) expect(await body(await memberChange(owner, workspace, joined.member, "confirm"))).toEqual(expectedMember(joined.member, name, "guest"))
    return person
  }
  async function startMachine(workspace: WorkspaceRef) {
    const keys = await newDeviceKey(), jwk = await publicJwk(keys)
    const input = { workspace: workspace.slug, owner: { kind: "self" }, name: "integration-machine", backend: "software", jwk }
    const encoded = JSON.stringify(input), url = `${ORIGIN}/v1/enrol`
    const signedProof = await createProof(webCryptoSigner("new", keys.privateKey), { method: "POST", url, body: encoded }, { tenant: "enrol" })
    const started = await body<{ enrolment: string; code: string; url: string }>(await request("/v1/enrol", undefined, input, { "Mehen-Proof": signedProof }), 201)
    const thumbprint = await jwkThumbprint(jwk)
    const group = fingerprintGroups(fingerprintOf(thumbprint))[await fingerprintGroupIndex(started.code)]!
    return { keys, started, thumbprint, group }
  }
  async function deviceCall(machine: Machine, path: string, input?: unknown, tenant = machine.workspace.id, id = machine.device, methodOverride?: string) {
    const method = methodOverride ?? (input === undefined ? "GET" : "POST"), encoded = input === undefined ? null : JSON.stringify(input), url = `${ORIGIN}${path}`
    const signedProof = await createProof(webCryptoSigner(id, machine.keys.privateKey), { method, url, body: encoded }, { tenant })
    return request(path, undefined, input, { "Mehen-Proof": signedProof }, method)
  }
  async function acceptMachine(person: Person, workspace: WorkspaceRef, start: Awaited<ReturnType<typeof startMachine>>, privateCredentials = true) {
    const view = await body<{ scope: import("@mehen/protocol").WorkspaceDeviceScope; start: import("@mehen/protocol").EnrolStartContext }>(await request(`/api/w/${workspace.slug}/enrolments/${start.started.code}`, person))
    const action: WorkspaceStepUpAction = { type: "enrol.accept", workspace: workspace.id, enrolment: start.started.enrolment, thumbprint: start.thumbprint, account: person.account, member: await member(person, workspace), scope: { ...view.scope, privateCredentials }, start: view.start }
    return signed(`/api/w/${workspace.slug}/enrolments/${start.started.code}/accept`, person, { group: start.group, privateCredentials }, action, workspace.slug)
  }
  async function machine(person: Person, workspace: WorkspaceRef): Promise<Machine> {
    const start = await startMachine(workspace)
    await body(await acceptMachine(person, workspace, start))
    const pending = { keys: start.keys, device: start.started.enrolment, workspace }
    const active = await body<{ status: string; device: string; workspace: WorkspaceRef; scope: { privateCredentials: boolean } }>(await deviceCall(pending, `/v1/enrol/${start.started.enrolment}`, undefined, "enrol"))
    const owner = await expectedOwner(person, workspace)
    expect(active).toEqual({ status: "active", tenant: workspace.id, workspace, device: expect.stringMatching(/^dev_/), owner, scope: acceptedScope() })
    return { keys: start.keys, device: active.device, workspace }
  }
  async function protectedMachine(person: Person, workspace: WorkspaceRef) {
    const enrolled = await machine(person, workspace)
    const current = await body<{ scope: import("@mehen/protocol").WorkspaceDeviceScope }>(await deviceCall(enrolled, "/v1/me"))
    const after = { ...current.scope, maxEnvironment: "protected" as const }
    const base = `/api/w/${workspace.slug}/devices/${enrolled.device}`
    const { action } = await body<{ action: WorkspaceStepUpAction }>(await request(`${base}/action`, person, { change: { kind: "rescope_propose", before: current.scope, after } }))
    const proposal = await body<{ id: string; state: string }>(await signed(`${base}/rescope`, person, { before: current.scope, after }, action, workspace.slug))
    const planned = await body<{ action: WorkspaceStepUpAction }>(await request(`${base}/action`, person, { change: { kind: "rescope_accept", proposal: proposal.id } }))
    const committed = await body(await signed(`${base}/rescope-accept`, person, { proposal: proposal.id }, planned.action, workspace.slug))
    expect(committed).toEqual({ id: proposal.id, device: enrolled.device, thumbprint: await jwkThumbprint(await publicJwk(enrolled.keys)), before: current.scope, after, beforeDigest: await sha256B64(canonicalJson(current.scope)), afterDigest: await sha256B64(canonicalJson(after)), proposer: { member: await member(person, workspace), name: (await expectedOwner(person, workspace)).name }, requiredSigners: [{ as: "owner_acceptance", account: person.account, name: (await expectedOwner(person, workspace)).name }], signedBy: [person.account], expiresAt: expect.any(String), state: "committed" })
    expect(await body(await deviceCall(enrolled, "/v1/me"))).toEqual(await expectedMachineStatus(person, enrolled, after))
    return enrolled
  }
  async function credential(person: Person, workspace: WorkspaceRef, slug: string, home: CredentialHome) {
    const [previous] = await sql<{ version: number; last_used_at: number | null }>(workspace, "SELECT version,last_used_at FROM items WHERE slug=?", slug)
    const created = await body<{ intake: string }>(await request(`/api/w/${workspace.slug}/intakes`, person, { provider: "openai", slug, home: home.kind === "member" ? "private" : home.kind, ...(home.kind === "project" ? { project: home.project } : {}) }), 201)
    const view = await body<{ binding: { value: { hosts: string[] } }; sealKey: { jwk: JsonWebKey; kid: string } }>(await request(`/api/w/${workspace.slug}/intakes/${created.intake}`, person))
    const sealKey = await body<{ jwk: JsonWebKey; kid: string }>(await request("/v1/seal-key"))
    const input = { slug, home, binding: view.binding.value, publicFields: {}, tags: [], sealed: { key: await seal(await importSealPublicKey(sealKey.jwk), "sk-integration-not-a-real-secret", `intake/${created.intake}/key`) } }
    const digest = await sha256B64(canonicalJson(input))
    const result = await body<{ item: { slug: string } }>(await signed(`/api/w/${workspace.slug}/intakes/${created.intake}/submit`, person, input, { type: "intake.submit", intake: created.intake, digest }, workspace.slug))
    const [stored] = await sql<{ id: string }>(workspace, "SELECT id FROM items WHERE slug=?", slug)
    const template = getTemplate("openai")!
    const policyFloor = await Promise.all(POLICY_FLOOR.filter(entry => entry.host === "api.openai.com").map(async entry => ({ ...entry, ruleDigest: await sha256B64(canonicalJson({ host: entry.host, action: entry.action, reason: entry.reason, rule: entry.rule })) })))
    expect(result).toEqual({ item: { slug, home, kind: "api-key", provider: "openai", account: null, accountVerified: false, tags: [], ceiling: "placeholder", hosts: ["api.openai.com"], status: "active", updatedAt: expect.any(String), lastUsedAt: previous?.last_used_at ? new Date(previous.last_used_at).toISOString() : null, policy: template.policy, description: null, publicFields: {}, secretFields: [{ name: "key", set: true, length: "sk-integration-not-a-real-secret".length, prefix: "sk-", fingerprint: expect.stringMatching(/^[A-Za-z0-9_-]{12}$/) }], binding: template.binding, injection: template.injection, version: (previous?.version ?? 0) + 1, rotatedAt: previous ? expect.any(String) : null, policyFloor } })
    if (!stored) throw new Error("Credential not stored")
    return { result, id: stored.id }
  }
  async function expectedOwner(person: Person, workspace: WorkspaceRef) {
    const row = await db.prepare("SELECT name FROM accounts WHERE id=?").bind(person.account).first<{ name: string }>()
    if (!row) throw new Error("No account")
    return { kind: "member" as const, member: await member(person, workspace), name: row.name }
  }
  async function expectedMachineStatus(person: Person, machine: Machine, scope = acceptedScope()) {
    const [role] = await sql<{ role: string }>(machine.workspace, "SELECT role FROM members WHERE id=?", await member(person, machine.workspace))
    return { tenant: machine.workspace.id, device: machine.device, name: "integration-machine", scope, frozen: false, fingerprint: fingerprintOf(await jwkThumbprint(await publicJwk(machine.keys))), capabilities: CAPABILITIES, ownerRole: role?.role, workspace: machine.workspace, owner: await expectedOwner(person, machine.workspace), displayRev: 1 }
  }
  async function expectedEnrol(person: Person, workspace: WorkspaceRef, start: Awaited<ReturnType<typeof startMachine>>, state: "pending_admission" | "active", privateCredentials: boolean) {
    const row = await db.prepare("SELECT start_at,expires_at,hard_expires_at FROM enrolments WHERE id=?").bind(start.started.enrolment).first<{ start_at: number; expires_at: number; hard_expires_at: number }>()
    if (!row) throw new Error("No enrolment")
    return { workspace, enrolment: start.started.enrolment, ref: start.started.code, code: start.started.code, name: "integration-machine", host: null, backend: "software", start: { at: new Date(row.start_at).toISOString(), clientLabel: "A browser", place: null }, acceptorPlace: null, requestedOwner: { kind: "self" }, owner: await expectedOwner(person, workspace), scope: acceptedScope(privateCredentials), digest: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), fingerprint: await enrolmentFingerprint(start.started.code, start.thumbprint), state, actions: state === "active" ? [] : ["accept", "reject"], expiresAt: new Date(row.expires_at).toISOString(), hardExpiresAt: new Date(row.hard_expires_at).toISOString(), lease: state === "active" ? "terminal" : "live", claimed: null, reason: null, successor: null }
  }
  async function projectMutation(person: Person, workspace: WorkspaceRef, change: string, input: Record<string, unknown>, path: string) {
    const action = await body<WorkspaceStepUpAction>(await request(`/api/w/${workspace.slug}/projects/action`, person, { change, input }))
    return signed(`/api/w/${workspace.slug}${path}`, person, input, action, workspace.slug)
  }
  const alex = await signup("test-bootstrap-code", "Alex")
  return { env: bindings, db, alex, faults, signin, cron, protectedMachine, expectedMachineStatus, expectedEnrol, request, signup, proof, signed, recoverySetup, createWorkspace, sql, snapshot, member, project, invite, memberChange, guest, startMachine, acceptMachine, machine, deviceCall, credential, projectMutation }
}
export async function workJourney() {
  const f = await journey()
  await f.recoverySetup(f.alex)
  const personal = await f.createWorkspace(f.alex, "alex", "Personal")
  const work = await f.createWorkspace(f.alex, "northwind", "Northwind")
  const project = await f.project(f.alex, work)
  return { ...f, personal, work, project }
}
