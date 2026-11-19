// A person at the vault's pages, for tests: a browser session with a
// software passkey, doing what the pages do with the same API calls.

import { Database } from "bun:sqlite"
import { join } from "node:path"
import { canonicalJson, fingerprintGroupIndex, fingerprintGroups, fingerprintOf, importSealPublicKey, jwkThumbprint, seal, sha256B64, type InviteTerms, type WorkspaceMemberView, type WorkspaceRef, type WorkspaceStepUpAction } from "@mehen/protocol"
import { softwarePasskey, type SoftwarePasskey } from "./software-passkey.ts"

const realFetch = globalThis.fetch

export class Person {
  readonly origin: string
  account = ""
  private cookie = ""
  private passkey: SoftwarePasskey | null = null

  constructor(origin: string) {
    this.origin = origin
  }

  async call<T>(path: string, input?: unknown, status = 200): Promise<T> {
    const response = await realFetch(`${this.origin}${path}`, { method: input === undefined ? "GET" : "POST", headers: { origin: this.origin, "sec-fetch-site": "same-origin", "content-type": "application/json", ...(this.cookie ? { cookie: this.cookie } : {}) }, ...(input === undefined ? {} : { body: JSON.stringify(input) }) })
    const set = response.headers.get("set-cookie")
    if (set) this.cookie = set.split(";")[0] ?? this.cookie
    const text = await response.text()
    if (response.status !== status) throw new Error(`${path}: ${response.status} ${text}`)
    return JSON.parse(text) as T
  }

  // A page as the browser loads it.
  async page(path: string): Promise<string> {
    const response = await realFetch(`${this.origin}${path}`, { headers: { accept: "text/html", ...(this.cookie ? { cookie: this.cookie } : {}) } })
    const text = await response.text()
    if (response.status !== 200) throw new Error(`${path}: ${response.status} ${text}`)
    return text
  }

  async signed<T>(path: string, input: Record<string, unknown>, action: WorkspaceStepUpAction, slug?: string, status = 200): Promise<T> {
    const started = await this.call<{ nonce: string; options?: { challenge: string } }>(slug ? `/api/w/${slug}/stepup/start` : "/api/account/stepup/start", { action })
    const stepUp = started.options ? { nonce: started.nonce, assertion: await this.passkey!.assertion(started.options.challenge) } : { nonce: started.nonce, grace: true }
    return this.call<T>(path, { ...input, stepUp }, status)
  }

  // The sign-up page, its recovery codes and the new workspace page.
  async signUp(code: string, name = "Local person"): Promise<void> {
    this.passkey = await softwarePasskey(this.origin)
    const { options } = await this.call<{ options: { challenge: string } }>("/api/auth/signup/options", { invite: code, name })
    const signup = await this.call<{ account: string }>("/api/auth/signup/verify", { invite: code, name, response: await this.passkey.registration(options.challenge) })
    this.account = signup.account
    const generated = await this.signed<{ batch: string; codes: string[]; confirmPosition: number }>("/api/account/recovery/generate", {}, { type: "recovery.generate" })
    await this.call("/api/account/recovery/confirm", { batch: generated.batch, code: generated.codes[generated.confirmPosition - 1] })
  }

  async createWorkspace(slug: string, name: string): Promise<WorkspaceRef> {
    return this.signed<WorkspaceRef>("/api/workspaces", { slug, name }, { type: "workspace.create", slug, name }, undefined, 201)
  }

  // The projects page: the vault plans the action, the passkey signs it.
  async createProject(workspace: string, slug: string): Promise<{ id: string; slug: string }> {
    const input = { slug, remote: null, defaultEnv: "dev", environments: [{ name: "dev", protected: false, fourEyes: false }] }
    const action = await this.call<WorkspaceStepUpAction>(`/api/w/${workspace}/projects/action`, { change: "create", input })
    return this.signed(`/api/w/${workspace}/projects`, input, action, workspace, 201)
  }

  // The people page's invite form: the link it shows, and its code.
  async invite(workspace: string, terms: InviteTerms): Promise<{ url: string; code: string }> {
    const made = await this.signed<{ url: string }>(`/api/w/${workspace}/invites`, { terms, email: false }, { type: "member.invite", terms }, workspace, 201)
    return { url: made.url, code: made.url.split("#")[1] ?? "" }
  }

  // The sign-up page's last step for an invited person.
  async join(code: string): Promise<{ member: string; state: string }> {
    return this.call("/api/account/invites/join", { code })
  }

  // Review and confirm on the people page.
  async confirm(workspace: string, member: string): Promise<WorkspaceMemberView> {
    const { action } = await this.call<{ action: WorkspaceStepUpAction }>(`/api/w/${workspace}/members/${member}/action`, { change: "confirm" })
    return this.signed(`/api/w/${workspace}/members/${member}/confirm`, {}, action, workspace)
  }

  // The enrolment page: check the words, type the hidden group, accept.
  async acceptMachine(dataDir: string, workspace: WorkspaceRef, code: string, enrolment: string, record: { jwk: Parameters<typeof jwkThumbprint>[0] }): Promise<void> {
    const view = await this.call<{ scope: Record<string, unknown>; start: unknown }>(`/api/w/${workspace.slug}/enrolments/${code}`)
    const directory = new Database(join(dataDir, "directory.sqlite"), { readonly: true })
    const member = (directory.query("SELECT id FROM memberships WHERE account=? AND workspace=?").get(this.account, workspace.id) as { id: string }).id
    directory.close()
    const thumbprint = await jwkThumbprint(record.jwk)
    const group = fingerprintGroups(fingerprintOf(thumbprint))[await fingerprintGroupIndex(code)]
    const accept = { type: "enrol.accept", workspace: workspace.id, enrolment, thumbprint, account: this.account, member, scope: { ...view.scope, privateCredentials: true }, start: view.start } as unknown as WorkspaceStepUpAction
    await this.signed(`/api/w/${workspace.slug}/enrolments/${code}/accept`, { group, privateCredentials: true }, accept, workspace.slug)
  }

  // The intake page: a key sealed in the browser to the vault.
  async addKey(workspace: string, slug: string, provider: string, value: string): Promise<void> {
    const intake = await this.call<{ intake: string }>(`/api/w/${workspace}/intakes`, { provider, slug, home: "workspace" }, 201)
    const view = await this.call<{ binding: { value: { hosts: string[] } } }>(`/api/w/${workspace}/intakes/${intake.intake}`)
    const sealKey = await this.call<{ jwk: JsonWebKey }>("/v1/seal-key")
    const submit = { slug, home: { kind: "workspace" }, binding: view.binding.value, publicFields: {}, tags: [], sealed: { key: await seal(await importSealPublicKey(sealKey.jwk), value, `intake/${intake.intake}/key`) } }
    await this.signed(`/api/w/${workspace}/intakes/${intake.intake}/submit`, submit, { type: "intake.submit", intake: intake.intake, digest: await sha256B64(canonicalJson(submit)) }, workspace)
  }
}
