// mehen against the real Worker under `wrangler dev -e local`: the enrolment
// proofs and the identity refusals as the real server sends them.
// Approving an enrolment needs a passkey in a browser, so an active device
// is out of reach here; the mock vault covers the signed-in commands.
// Skipped, with the reason, when wrangler cannot start.

import { afterAll, describe, expect, test } from "bun:test"
import { mkdtemp, mkdir, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { EXIT, type EnrolStartResponse, type EnrolStatus } from "@mehen/protocol/api"
import { keyFingerprint } from "./commands/enrol.ts"
import { writeConfig } from "./config.ts"
import { createDeviceKey, loadDeviceKey } from "./device-key.ts"
import { HttpVaultApi } from "./http-client.ts"
import { runJv } from "./testing/run-mehen.ts"
import { VaultApiError } from "./vault-api.ts"

const SERVER_DIR = join(import.meta.dir, "..", "..", "vault")
// The test-only keys from wrangler.jsonc env.test, worthless elsewhere.
const ROOT_KEYS = '{"1":"dGVzdC1yb290LWtleS1ub3QtYS1zZWNyZXQtMzJieXQ"}'
const SEAL_PRIVATE_JWK =
  '{"kty":"EC","crv":"P-256","x":"IFu5oTRAkuJbqGAyU-XhbZTUbMDuWlA_VPjMvHboOiA","y":"Kq34ITAoveGw9XtQyZoqkyIEDbgU_4alhSi115VpVDQ","d":"54ec9Zobfk7EdlSkw65vyEMdu1lFOvoP5FWX83K6qHA"}'

type Worker = { url: string; proc: ReturnType<typeof Bun.spawn>; state: string }

// The last lines wrangler dev printed, kept so a failure that looks like an
// unreachable vault can show what the dev server was doing (CI diagnostic).
const WORKER_LOG_LINES = 40
const workerLog: string[] = []

async function keepLog(stream: ReadableStream<Uint8Array>): Promise<void> {
  const decoder = new TextDecoder()
  const reader = stream.getReader()
  let partial = ""
  for (;;) {
    const { done, value } = await reader.read()
    if (done) return
    const lines = (partial + decoder.decode(value, { stream: true })).split("\n")
    partial = lines.pop() ?? ""
    workerLog.push(...lines)
    if (workerLog.length > WORKER_LOG_LINES) workerLog.splice(0, workerLog.length - WORKER_LOG_LINES)
  }
}

function workerLogTail(): string {
  return workerLog.length ? workerLog.join("\n") : "(wrangler dev printed nothing)"
}

function freePort(): number {
  const probe = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response() })
  const port = probe.port as number
  probe.stop(true)
  return port
}

async function startWorker(): Promise<Worker | string> {
  if (process.env.MEHEN_SKIP_WRANGLER) return "MEHEN_SKIP_WRANGLER is set"
  const state = await mkdtemp(join(tmpdir(), "mehen-wrangler-"))
  await mkdir(join(state, "assets"))
  const migrate = Bun.spawn(["bunx", "wrangler", "d1", "migrations", "apply", "DB", "--local", "-e", "local", "--persist-to", state], {
    cwd: SERVER_DIR,
    stdout: "pipe",
    stderr: "pipe",
    timeout: 120_000,
  })
  if ((await migrate.exited) !== 0) {
    await rm(state, { recursive: true, force: true })
    return `wrangler d1 migrations failed: ${(await new Response(migrate.stderr).text()).trim().split("\n").at(-1)}`
  }
  const port = freePort()
  const proc = Bun.spawn(
    [
      "bunx", "wrangler", "dev", "-e", "local", "--persist-to", state, "--assets", join(state, "assets"),
      "--ip", "127.0.0.1", "--port", String(port),
      "--var", `ROOT_KEYS:${ROOT_KEYS}`, "--var", `SEAL_PRIVATE_JWK:${SEAL_PRIVATE_JWK}`, "--var", "BOOTSTRAP_CODE:mehen-integration-test",
    ],
    { cwd: SERVER_DIR, stdout: "pipe", stderr: "pipe", timeout: 600_000 },
  )
  void keepLog(proc.stdout)
  void keepLog(proc.stderr)
  const url = `http://127.0.0.1:${port}`
  const deadline = Date.now() + 90_000
  while (Date.now() < deadline) {
    if (proc.exitCode !== null || proc.signalCode !== null) break
    try {
      const response = await fetch(`${url}/v1/me`)
      if (response.headers.get("Mehen-Error")) return { url, proc, state }
    } catch {
      // not listening yet
    }
    await Bun.sleep(500)
  }
  proc.kill()
  await proc.exited
  await rm(state, { recursive: true, force: true })
  return "wrangler dev did not become ready within 90 s"
}

const started = await startWorker()
const worker = typeof started === "string" ? null : started
if (typeof started === "string") console.error(`worker.integration.test.ts: skipping: ${started}`)
const cleanups: (() => Promise<void>)[] = []

afterAll(async () => {
  for (const cleanup of cleanups) await cleanup()
  if (worker) {
    worker.proc.kill()
    await worker.proc.exited
    await rm(worker.state, { recursive: true, force: true })
  }
})

// The dev server must still answer as the vault before a CLI call is made,
// and a CLI call that exits 7 (the vault unreachable) fails with wrangler's
// last lines, so a dev server that died mid-file is told apart from the CLI.
async function runAgainstWorker(args: string[], env: Record<string, string>): Promise<Awaited<ReturnType<typeof runJv>>> {
  const url = worker?.url ?? ""
  let answered = false
  try {
    answered = (await fetch(`${url}/v1/me`)).headers.has("Mehen-Error")
  } catch {
    answered = false
  }
  if (!answered) throw new Error(`wrangler dev at ${url} no longer answers as the vault (exit ${worker?.proc.exitCode ?? "none"}, signal ${worker?.proc.signalCode ?? "none"}). Its last lines:\n${workerLogTail()}`)
  const result = await runJv(args, env)
  if (result.code === EXIT.transient) throw new Error(`mehen ${args.join(" ")} exited 7 (the vault unreachable): ${result.stdout}${result.stderr}\nwrangler dev's last lines:\n${workerLogTail()}`)
  return result
}

async function configDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "mehen-it-"))
  cleanups.push(() => rm(dir, { recursive: true, force: true }))
  return dir
}

describe.skipIf(worker === null)("mehen against the real Worker (wrangler dev)", () => {
  const url = worker?.url ?? ""

  // mehen enrol needs --workspace <slug> (design 9.2.1): without it the
  // refusal is local, and the Worker sees nothing. The Worker is reached
  // through a counting proxy so "nothing was sent" is observed, not assumed.
  test("mehen enrol without --workspace is a usage error with the Connect an agent next, and nothing reaches the Worker", async () => {
    const dir = await configDir()
    let forwarded = 0
    const proxy = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(request) {
        forwarded += 1
        const target = new URL(request.url)
        const upstream = new URL(url)
        target.protocol = upstream.protocol
        target.host = upstream.host
        return fetch(new Request(target.toString(), request))
      },
    })
    cleanups.push(async () => proxy.stop(true))
    const result = await runJv(["enrol", "--name", "it-mac", "--backend", "software", "--json"], { MEHEN_CONFIG_DIR: dir, MEHEN_VAULT_URL: `http://127.0.0.1:${proxy.port}`, MEHEN_POLL_INTERVAL_MS: "200" })
    expect(result.code).toBe(EXIT.usage)
    expect(JSON.parse(result.stdout)).toMatchObject({
      error: "usage",
      message: "mehen enrol needs --workspace <slug>: the workspace this machine joins.",
      next: { command: "mehen enrol --workspace <slug>", say: "Run `mehen enrol --workspace <slug>`; the slug is on the workspace's Connect an agent page." },
    })
    expect(forwarded).toBe(0)
    // No key was made and no config written.
    expect(await Bun.file(join(dir, "device-key.json")).exists()).toBe(false)
    expect(await Bun.file(join(dir, "config.json")).exists()).toBe(false)
  })

  // The enrol lifecycle against S1a's routes: enrol
  // prints the ask and exits 0, the record is on disk, a wait that times out
  // is exit 4 with the live ask and keeps the record, and pending lists it.
  test("mehen enrol --workspace <slug> starts an attempt the Worker accepts and exits 0; mehen wait times out with exit 4 and keeps it; mehen pending lists it", async () => {
    const root = await configDir()
    const env = { MEHEN_HOME: root, MEHEN_VAULT_URL: url, MEHEN_POLL_INTERVAL_MS: "200" }
    const started = await runAgainstWorker(["enrol", "--workspace", "integration-space", "--name", "it-mac", "--backend", "software", "--json"], env)
    expect(started.code).toBe(EXIT.ok)
    const pending = JSON.parse(started.stdout) as { status: string; enrolment: string; url: string; expiresAt: string; hardExpiresAt: string | null; renewals: number; claimed: boolean; slot: string; ask: { intent: unknown } }
    expect(pending).toMatchObject({ status: "pending", renewals: 0, claimed: false, ask: { intent: { workspace: "integration-space", team: null } } })
    expect(pending.url).toBe(`${url}/w/integration-space/e/${(JSON.parse(started.stdout) as { code: string }).code}`)
    expect(Date.parse(pending.hardExpiresAt as string)).toBeGreaterThan(Date.parse(pending.expiresAt))
    expect(await Bun.file(join(pending.slot, "enrolment.json")).exists()).toBe(true)
    const waited = await runAgainstWorker(["wait", pending.enrolment, "--timeout", "1", "--json"], env)
    expect(waited.code).toBe(EXIT.human)
    expect(JSON.parse(waited.stdout)).toMatchObject({ error: "timeout", ask: { id: pending.enrolment, url: pending.url } })
    expect(await Bun.file(join(pending.slot, "enrolment.json")).exists()).toBe(true)
    const listed = await runAgainstWorker(["pending", "--json"], env)
    expect(listed.code).toBe(EXIT.ok)
    expect((JSON.parse(listed.stdout) as { pending: { id: string; url: string }[] }).pending).toEqual([expect.objectContaining({ id: pending.enrolment, url: pending.url })])
  })

  // Renewal in place: the same id with a later expiry;
  // again within a minute is a 409 with retryAfter; a superseded attempt's
  // renewal is the 409 carrying the settled answer, and mehen wait on it
  // ends for good with mehen enrol as the next step.
  test("renew keeps the id with a later expiry; a second renew within a minute is 409 retryAfter; a superseded attempt settles as expired and mehen wait removes its record", async () => {
    const root = await configDir()
    const env = { MEHEN_HOME: root, MEHEN_VAULT_URL: url, MEHEN_POLL_INTERVAL_MS: "200" }
    const started = await runAgainstWorker(["enrol", "--workspace", "integration-space", "--name", "it-renew", "--backend", "software", "--json"], env)
    const first = JSON.parse(started.stdout) as { enrolment: string; expiresAt: string; slot: string }
    const key = await loadDeviceKey(first.slot, "software", {})
    const renewer = new HttpVaultApi({ vaultUrl: url, tenant: "enrol", signer: key.signer(first.enrolment) })
    await Bun.sleep(5)
    const renewed = await renewer.request<{ enrolment: string; expiresAt: string; hardExpiresAt: string }>("POST", `/v1/enrol/${first.enrolment}/renew`)
    expect(renewed.enrolment).toBe(first.enrolment)
    expect(Date.parse(renewed.expiresAt)).toBeGreaterThan(Date.parse(first.expiresAt))
    const again = (await renewer.request("POST", `/v1/enrol/${first.enrolment}/renew`).catch((e: unknown) => e)) as VaultApiError
    expect(again).toBeInstanceOf(VaultApiError)
    expect(again.status).toBe(409)
    expect(again.body).toMatchObject({ error: "conflict" })
    expect(typeof again.body.retryAfter).toBe("number")
    expect(again.body.enrolment).toBeUndefined()
    expect(await renewer.request<EnrolStatus>("GET", `/v1/enrol/${first.enrolment}`)).toMatchObject({ status: "pending_owner_acceptance", expiresAt: renewed.expiresAt })
    // A second attempt with the same key supersedes the first at the vault.
    const jwk = JSON.parse(await Bun.file(join(first.slot, "device-key.json")).text()) as { kty: "EC"; crv: "P-256"; x: string; y: string }
    const starter = new HttpVaultApi({ vaultUrl: url, tenant: "enrol", signer: key.signer("new") })
    await starter.request<EnrolStartResponse>("POST", "/v1/enrol", { name: "it-renew-2", backend: "software", jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, workspace: "integration-space", owner: { kind: "self" } })
    const settled = (await renewer.request("POST", `/v1/enrol/${first.enrolment}/renew`).catch((e: unknown) => e)) as VaultApiError
    expect(settled.status).toBe(409)
    expect(settled.body.enrolment).toEqual({ status: "expired", reason: "superseded" })
    const waited = await runAgainstWorker(["wait", first.enrolment, "--json"], env)
    expect(waited.code).toBe(EXIT.error)
    expect(JSON.parse(waited.stdout)).toMatchObject({ error: "expired", next: { command: "mehen enrol --workspace integration-space" } })
    expect(await Bun.file(join(first.slot, "enrolment.json")).exists()).toBe(false)
  })

  test("enrolment proofs: dev new to start, the enrolment id to poll; a replay or a tampered body is refused", async () => {
    const dir = await configDir()
    const { key, jwk } = await createDeviceKey(dir, "software", {})
    let captured: Request | null = null
    const starter = new HttpVaultApi({
      vaultUrl: url,
      tenant: "enrol",
      signer: key.signer("new"),
      fetch: async (request) => {
        captured = request.clone()
        return fetch(request)
      },
    })
    const body = { name: "it-direct", backend: "software", jwk, workspace: "integration-space", owner: { kind: "self" } }
    const started = await starter.request<EnrolStartResponse>("POST", "/v1/enrol", body)
    expect(started.fingerprint).toBe(await keyFingerprint(jwk))

    const replay = await fetch(captured as unknown as Request)
    expect(replay.status).toBe(401)
    expect(((await replay.json()) as { error: string }).error).toBe("proof_invalid")

    const tampering = new HttpVaultApi({
      vaultUrl: url,
      tenant: "enrol",
      signer: key.signer("new"),
      fetch: (request) => fetch(new Request(request.url, { method: "POST", headers: request.headers, body: JSON.stringify({ ...body, name: "someone-else" }) })),
    })
    const tampered = (await tampering.request("POST", "/v1/enrol", body).catch((e: unknown) => e)) as VaultApiError
    expect(tampered).toBeInstanceOf(VaultApiError)
    expect(tampered.body.error).toBe("proof_invalid")

    const poller = new HttpVaultApi({ vaultUrl: url, tenant: "enrol", signer: key.signer(started.enrolment) })
    expect(await poller.request<EnrolStatus>("GET", `/v1/enrol/${started.enrolment}`)).toMatchObject({ status: "pending_owner_acceptance", expiresAt: started.expiresAt })
    const wrongDev = new HttpVaultApi({ vaultUrl: url, tenant: "enrol", signer: key.signer("new") })
    const refused = (await wrongDev.request("GET", `/v1/enrol/${started.enrolment}`).catch((e: unknown) => e)) as VaultApiError
    expect(refused.body.error).toBe("proof_invalid")

    // A pending key cannot act as a device: ls exits 4 (a human must approve
    // it); spanning status reports the same refusal in the slot's check.
    await writeConfig(dir, { vault: url, tenant: "enrol", device: started.enrolment, backend: "software" })
    const ls = await runAgainstWorker(["ls", "--json"], { MEHEN_CONFIG_DIR: dir, MEHEN_VAULT_URL: url })
    expect(ls.code).toBe(EXIT.human)
    expect((JSON.parse(ls.stdout) as { error: string }).error).toBe("device_pending")
    const status = await runAgainstWorker(["status", "--json"], { MEHEN_CONFIG_DIR: dir, MEHEN_VAULT_URL: url })
    expect(status.code).toBe(EXIT.ok)
    expect((JSON.parse(status.stdout) as { workspaces: { check: { ok: boolean; error?: string } }[] }).workspaces[0]?.check).toMatchObject({ ok: false, error: "device_pending" })
  })

  test("status and ls with a device the vault does not know exit 6 with the vault's next", async () => {
    const dir = await configDir()
    await createDeviceKey(dir, "software", {})
    await writeConfig(dir, { vault: url, tenant: "ten_unknown", device: "dev_unknown", backend: "software" })
    const ls = await runAgainstWorker(["ls", "--json"], { MEHEN_CONFIG_DIR: dir, MEHEN_VAULT_URL: url })
    expect(ls.code).toBe(EXIT.identity)
    const body = JSON.parse(ls.stdout) as { error: string; message: string }
    expect(["unauthenticated", "proof_invalid", "device_revoked"]).toContain(body.error)
    expect(body.message.length).toBeGreaterThan(0)
    // Spanning status names the refusal in the slot's check and deletes nothing.
    const status = await runAgainstWorker(["status", "--json"], { MEHEN_CONFIG_DIR: dir, MEHEN_VAULT_URL: url })
    expect(status.code).toBe(EXIT.ok)
    const check = (JSON.parse(status.stdout) as { workspaces: { check: { ok: boolean; error: string; message: string } }[] }).workspaces[0]?.check
    expect(check?.ok).toBe(false)
    expect(["unauthenticated", "proof_invalid", "device_revoked"]).toContain(check?.error ?? "")
    expect(check?.message.length).toBeGreaterThan(0)
  })
})
