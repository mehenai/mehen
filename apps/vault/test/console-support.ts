// The operator console in tests: the platform fixtures' directory (with
// stand-in managed workspaces), people with a real web session and a
// software passkey, requests through the real Worker, and the real
// passkey step-up.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test"
import { type AdminPlatformCommand, type OperatorCommand, type WorkspaceStepUpAction, adminStepUpAction, base64UrlEncode, operatorStepUpAction } from "@mehen/protocol"
import type { Env } from "../src/env.ts"
import { SESSION_COOKIE, sha256Text } from "../src/directory/session.ts"
import { type OperatorAccountRow, type OperatorIo, parseOperatorArgs, runOperator } from "../scripts/operator.ts"
import { type SoftwarePasskey, assertion, softwarePasskey } from "./e2e/passkeys.ts"
import { ORIGIN } from "./helpers.ts"
import { type WorkspaceAnswer, type WorkspaceCall, platformEnv } from "./platform-fixtures.ts"

export type Person = { account: string; cookie: string; passkey: SoftwarePasskey; counter: number }
// A person's passkey beside the one they sign with: a security key (so
// they meet every requirement of an operator account), another built into
// a device (two passkeys, none a security key), or none.
export type SecondPasskey = "security-key" | "device" | "none"
export type StepUp = { nonce: string; assertion: Record<string, unknown> }

export type ConsoleFixture = {
  env: Env
  calls: WorkspaceCall[]
  person(account: string, second?: SecondPasskey): Promise<Person>
  request(path: string, person?: Person, input?: unknown, method?: string): Promise<Response>
  operatorProof(person: Person, slug: string, command: OperatorCommand): Promise<StepUp>
  adminProof(person: Person, slug: string, command: AdminPlatformCommand): Promise<StepUp>
  proof(person: Person, start: string, action: WorkspaceStepUpAction): Promise<StepUp>
  grantOperator(account: string): Promise<void>
  revokeOperator(account: string): Promise<void>
}

// The fixture's accounts are acc_owner, acc_admin, acc_member, acc_guest
// and acc_kim, none of them an operator. Each person signs with a software
// passkey built into a device and, unless asked otherwise, also has a
// security key, so with two passkeys recovery is ready and an operator
// account has everything it needs. `answer` is what the workspace objects
// answer, the platform fixtures' stand-in unless a test says otherwise.
export async function consoleFixture(answer?: WorkspaceAnswer): Promise<ConsoleFixture> {
  const { env, calls } = await platformEnv(answer)
  const now = Date.now()
  async function person(account: string, second: SecondPasskey = "security-key"): Promise<Person> {
    const passkey = await softwarePasskey()
    const token = `console-${crypto.randomUUID()}`
    const other = second === "none" ? [] : [env.DB.prepare("INSERT INTO passkeys(credential_id,account,public_key,counter,transports,created_at,last_used_at,handle,added_via) VALUES (?,?,?,0,?,?,?,?,'settings')").bind(`second-${crypto.randomUUID()}`, account, (await softwarePasskey()).cose.slice().buffer, JSON.stringify(second === "security-key" ? ["usb", "nfc"] : ["internal"]), now - 30_000, now - 30_000, `pk_${crypto.randomUUID().replaceAll("-", "")}`)]
    await env.DB.batch([
      ...other,
      env.DB.prepare("INSERT INTO passkeys(credential_id,account,public_key,counter,transports,created_at,last_used_at,handle,added_via) VALUES (?,?,?,0,'[\"internal\"]',?,?,?,'signup')").bind(base64UrlEncode(passkey.credentialId), account, passkey.cose.slice().buffer, now - 60_000, now - 60_000, `pk_${crypto.randomUUID().replaceAll("-", "")}`),
      env.DB.prepare("INSERT INTO web_sessions(token_hash,id,account,created_at,expires_at,last_seen_at,kind,method,client) VALUES (?,?,?,?,?,?,'web','passkey','Test browser')").bind(await sha256Text(token), `ses_${crypto.randomUUID().replaceAll("-", "")}`, account, now, now + 2_592_000_000, now),
    ])
    return { account, cookie: `${SESSION_COOKIE}=${token}`, passkey, counter: 0 }
  }
  async function request(path: string, who?: Person, input?: unknown, method = input === undefined ? "GET" : "POST"): Promise<Response> {
    const worker = (await import("../src/index.ts")).default
    const ctx = createExecutionContext()
    const headers: Record<string, string> = { origin: ORIGIN, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", accept: "application/json", ...(input === undefined ? {} : { "content-type": "application/json" }), ...(who ? { cookie: who.cookie } : {}) }
    const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { method, headers, ...(input === undefined ? {} : { body: JSON.stringify(input) }) }) as Request<unknown, IncomingRequestCfProperties>, env, ctx)
    await waitOnExecutionContext(ctx)
    return response
  }
  async function proof(who: Person, start: string, action: WorkspaceStepUpAction): Promise<StepUp> {
    const response = await request(start, who, { action })
    if (response.status !== 200) throw new Error(`step-up start ${start}: ${response.status} ${await response.text()}`)
    const { nonce, options } = (await response.json()) as { nonce: string; options: { challenge: string } }
    return { nonce, assertion: await assertion(who.passkey, options.challenge, ++who.counter) }
  }
  // The id of the platform the slug names now, as a page has it.
  async function platformId(slug: string): Promise<string> {
    return (await env.DB.prepare("SELECT id FROM platforms WHERE slug=?").bind(slug).first<{ id: string }>())?.id ?? "plt_none"
  }
  // The operator script, as the operator runs it from their own machine.
  async function operatorScript(command: "grant-operator" | "revoke-operator", account: string): Promise<void> {
    const io: OperatorIo = {
      async query(_target, sql) {
        return (await env.DB.prepare(sql).all<OperatorAccountRow>()).results
      },
      async update(_target, statements) {
        return (await env.DB.batch<{ id: string }>(statements.map((sql) => env.DB.prepare(sql))))[0]?.results ?? []
      },
      bookmark: async () => "fixture-bookmark",
      ask: async () => account,
      print: () => {},
    }
    if ((await runOperator(parseOperatorArgs(["--local", command, account, "--actor", "operator:test"]), io)) !== 0) throw new Error(`${command} failed`)
  }
  return {
    env,
    calls,
    person,
    request,
    proof,
    operatorProof: async (who, slug, command) => proof(who, "/api/operator/stepup/start", await operatorStepUpAction(slug, command.command === "register" ? null : await platformId(slug), command)),
    adminProof: async (who, slug, command) => proof(who, `/api/platforms/${slug}/stepup/start`, await adminStepUpAction(slug, await platformId(slug), command)),
    grantOperator: (account) => operatorScript("grant-operator", account),
    revokeOperator: (account) => operatorScript("revoke-operator", account),
  }
}

export async function answer<T = Record<string, unknown>>(response: Response, status = 200): Promise<T> {
  const text = await response.text()
  if (response.status !== status) throw new Error(`expected ${status}, got ${response.status}: ${text}`)
  return JSON.parse(text) as T
}
