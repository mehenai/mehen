// The vault Worker on one machine: Bun serves it, its Durable Objects and D1
// are SQLite files under the data directory, and its bindings are local
// stand-ins. The engine itself is the hosted vault's, unchanged.

import { closeSync, existsSync, openSync, readFileSync, rmSync, writeSync } from "node:fs"
import { join } from "node:path"
import { MIGRATIONS } from "mehen-local:migrations"
import { ASSETS } from "mehen-local:assets"
import worker, { PlatformVault, WorkspaceVault } from "mehen-local:vault"
import { ensureSafeDirectory } from "../../cli/src/home.ts"
import { CliError } from "../../cli/src/errors.ts"
import { type Address, type LocalConfig, LocalConfigError, addressFor } from "./config.ts"
import { loadSecrets, storedData, writePrivate } from "./custody.ts"
import { LocalD1 } from "./d1.ts"
import { LocalNamespace } from "./durable-objects.ts"
import { hardenProcess } from "./harden.ts"
import { LocalBucket } from "./r2.ts"
import { localRateLimits } from "./rate-limit.ts"
import type { LocalOptions, LocalState, LocalVault } from "./types.ts"

export type { LocalOptions, LocalState, LocalVault }

export const BOOTSTRAP_FILE = "bootstrap"
export const INSTANCE_FILE = "instance"
export const LOCK_FILE = "serve.lock"
const BOOTSTRAP_SHAPE = /^[A-Za-z0-9_-]{32}$/
const SWEEP_MS = 15 * 60_000

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url")
}

const CONTENT_TYPES: Record<string, string> = { js: "text/javascript; charset=utf-8", css: "text/css; charset=utf-8", svg: "image/svg+xml", png: "image/png", woff2: "font/woff2", txt: "text/plain; charset=utf-8" }

function assets() {
  return {
    async fetch(input: Request | string): Promise<Response> {
      const url = new URL(typeof input === "string" ? input : input.url)
      const body = Object.hasOwn(ASSETS, url.pathname) ? ASSETS[url.pathname] : undefined
      if (body === undefined) return new Response("Not found", { status: 404 })
      const type = CONTENT_TYPES[url.pathname.split(".").pop() ?? ""] ?? "application/octet-stream"
      return new Response(Buffer.from(body, "base64"), { headers: { "content-type": type, "cache-control": "no-cache" } })
    },
  }
}

function refuseDataDir(path: string, why: string): CliError {
  return new CliError("key_insecure", `Refusing to keep the vault in ${path}: it ${why}, so someone else could read or replace it.`, {
    say: "Give the vault a data directory only this user can write (--data), not one below a world-writable folder such as /tmp, then start it again.",
  })
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return (error as { code?: string }).code === "EPERM"
  }
}

// One server per data directory: two would each hold a root key in memory
// and write the same files. The lock is a file made with O_EXCL holding the
// owner's pid; one whose owner is gone is taken over.
const HELD = new Set<string>()

export function acquireDataLock(dataDir: string): () => void {
  const path = join(dataDir, LOCK_FILE)
  if (HELD.has(dataDir)) throw new CliError("conflict", `This process is already serving the vault in ${dataDir}.`, { say: "Use the vault that is running, or stop it first." })
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(path, "wx", 0o600)
      writeSync(fd, `${process.pid}\n`)
      closeSync(fd)
      HELD.add(dataDir)
      return () => {
        HELD.delete(dataDir)
        if (existsSync(path) && readFileSync(path, "utf8").trim() === String(process.pid)) rmSync(path, { force: true })
      }
    } catch (error) {
      if ((error as { code?: string }).code !== "EEXIST") throw error
      const pid = Number(readFileSync(path, "utf8").trim())
      if (Number.isInteger(pid) && pid > 0 && pid !== process.pid && alive(pid)) {
        throw new CliError("conflict", `Another mehen serve (pid ${pid}) is already using the vault in ${dataDir}.`, { say: `Use that vault, or stop it first (\`mehen up --remove\`, or end pid ${pid}). If no such process is a mehen serve, remove ${path} and start again.` })
      }
      rmSync(path, { force: true })
    }
  }
  throw new CliError("conflict", `Could not take the lock on the vault in ${dataDir}.`, { say: `Remove ${path} if no mehen serve is running, then start again.` })
}

export async function startLocalVault(config: LocalConfig, options: LocalOptions = {}): Promise<LocalVault> {
  // Refused before anything binds a port or reads a key.
  if (config.origin === null) addressFor(config, config.port || 1)
  ensureSafeDirectory(config.dataDir, refuseDataDir)
  const release = acquireDataLock(config.dataDir)
  try {
    return await startLocked(config, release, options)
  } catch (error) {
    release()
    throw error
  }
}

async function startLocked(config: LocalConfig, release: () => void, options: LocalOptions): Promise<LocalVault> {
  const hardening = hardenProcess()
  const { dataDir } = config

  const db = new LocalD1(join(dataDir, "directory.sqlite"))
  const applied = db.migrate(MIGRATIONS)
  const tenants = new LocalNamespace<object, object>(dataDir, "WorkspaceVault", WorkspaceVault)
  const platforms = new LocalNamespace<object, object>(dataDir, "PlatformVault", PlatformVault)
  const backups = new LocalBucket(join(dataDir, "backups"))
  const accounts = () => db.db.query("SELECT 1 FROM accounts LIMIT 1").get() !== null
  let loaded
  try {
    loaded = await loadSecrets(dataDir, options.custody ?? { platform: process.platform, env: process.env, helper: null }, storedData(dataDir, accounts()))
  } catch (error) {
    tenants.close()
    platforms.close()
    db.db.close()
    throw error
  }
  const { secrets, custody } = loaded

  const instance = b64url(crypto.getRandomValues(new Uint8Array(18)))
  const bootstrapPath = join(dataDir, BOOTSTRAP_FILE)

  const env: Record<string, unknown> = {
    TENANT_VAULT: tenants,
    PLATFORM_VAULT: platforms,
    DB: db,
    VAULT_BACKUPS: backups,
    ASSETS: assets(),
    ...localRateLimits(),
    VAULT_ORIGIN: "",
    RP_ID: "",
    CLI_MINIMUM_VERSION: "0.3.0",
    CLI_RECOMMENDED_VERSION: "0.4.0",
    WORKSPACE_CREATION: "accounts",
    SIGNUP_MODE_MAX: "invite",
    POLICY_RULES: "on",
    APPROVAL_BATCHES: "on",
    POLICY_POSTURES: "on",
    APPROVAL_DIAL: "on",
    STEPUP_GRACE: "on",
    MANDATES: "on",
    BROWSER_FILL: "on",
    PUSH: "off",
    BOOTSTRAP_CODE: undefined,
    ...secrets,
  }

  // While the vault has no account, a one-time code lets the first person
  // sign up. It lives in a 0600 file for `mehen up` to open in the browser,
  // and goes the moment an account exists.
  const settleBootstrap = () => {
    if (accounts()) {
      env.BOOTSTRAP_CODE = undefined
      rmSync(bootstrapPath, { force: true })
      return
    }
    if (typeof env.BOOTSTRAP_CODE === "string") return
    // A restart keeps the code a browser may already have open.
    const kept = existsSync(bootstrapPath) ? readFileSync(bootstrapPath, "utf8").trim() : ""
    const code = BOOTSTRAP_SHAPE.test(kept) ? kept : b64url(crypto.getRandomValues(new Uint8Array(24)))
    if (code !== kept) writePrivate(bootstrapPath, code)
    env.BOOTSTRAP_CODE = code
  }
  settleBootstrap()
  tenants.bind(env)
  platforms.bind(env)

  const pending = new Set<Promise<unknown>>()
  const ctx = {
    waitUntil(p: Promise<unknown>) {
      pending.add(p)
      void p.catch(() => undefined).finally(() => pending.delete(p))
    },
    passThroughOnException() {},
    props: {},
  }

  let address: Address | null = null
  const state = (): LocalState => ({
    origin: address?.origin ?? "",
    instance,
    accounts: accounts(),
    custody,
    bootstrap: typeof env.BOOTSTRAP_CODE === "string",
    workspaces: db.db.query("SELECT slug, name FROM workspaces WHERE status = 'active' ORDER BY created_at").all() as { slug: string; name: string }[],
  })

  const closeStores = () => {
    tenants.close()
    platforms.close()
    db.db.close()
  }
  // Cloudflare sets cf-connecting-ip itself; here a client could send its
  // own and slip the rate limits, so it is always the peer's address.
  const IDENTITY_HEADERS = ["cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor", "true-client-ip", "x-real-ip", "x-forwarded-for"]

  async function handle(request: Request, peer: { requestIP(r: Request): { address: string } | null }): Promise<Response> {
    const live = address
    // A page on another site can point a name of its own at this address
    // (DNS rebinding); only requests addressed to this vault are served.
    if (!live || !live.hosts.has(request.headers.get("host") ?? "")) return new Response("Misdirected request", { status: 421 })
    const url = new URL(request.url)
    // Passkeys are made for localhost, and 127.0.0.1 is another site to a
    // browser, so a page asked for by address is sent to its name.
    if (live.loopback && request.headers.get("host")?.startsWith("127.0.0.1") && (request.method === "GET" || request.method === "HEAD") && (request.headers.get("accept") ?? "").includes("text/html")) {
      return new Response(null, { status: 308, headers: { location: `${live.origin}${url.pathname}${url.search}` } })
    }
    // What `mehen up` reads to know where setup has got to. Loopback only:
    // a vault other machines reach says nothing about itself unasked.
    if (url.pathname === "/local/v1/state") {
      if (!live.loopback || request.method !== "GET") return new Response("Not found", { status: 404 })
      return Response.json(state(), { headers: { "cache-control": "no-store" } })
    }
    // Where `mehen up` sends the browser, so the one-time sign-up code never
    // sits in a command line, a log or the agent's transcript: the redirect
    // carries it in the fragment, which the page reads and drops.
    if (url.pathname === "/local/v1/start") {
      if (!live.loopback || request.method !== "GET") return new Response("Not found", { status: 404 })
      settleBootstrap()
      const code = env.BOOTSTRAP_CODE
      return new Response(null, { status: 302, headers: { location: typeof code === "string" ? `/signup#${code}` : "/", "cache-control": "no-store", "referrer-policy": "no-referrer" } })
    }
    const rewritten = new Request(`${live.origin}${url.pathname}${url.search}`, request)
    for (const name of IDENTITY_HEADERS) rewritten.headers.delete(name)
    rewritten.headers.set("cf-connecting-ip", peer.requestIP(request)?.address ?? "local")
    const response = await worker.fetch(rewritten, env, ctx)
    if (url.pathname === "/api/auth/signup/verify" && response.ok) settleBootstrap()
    return response
  }

  let server: ReturnType<typeof Bun.serve>
  try {
    server = Bun.serve({ hostname: config.hostname, port: config.port, fetch: handle })
  } catch (error) {
    closeStores()
    throw error
  }

  try {
    address = addressFor(config, server.port ?? config.port)
  } catch (error) {
    await server.stop(true)
    closeStores()
    throw error
  }
  env.VAULT_ORIGIN = address.origin
  env.RP_ID = address.rpId
  // Only now that this server owns the port: mehen up compares this token
  // with the one the vault on the port reports.
  writePrivate(join(dataDir, INSTANCE_FILE), instance)
  tenants.resumeAlarms()
  platforms.resumeAlarms()

  const sweep = setInterval(() => {
    settleBootstrap()
    backups.prune()
    void worker.scheduled({ cron: "*/15 * * * *", scheduledTime: Date.now() }, env, ctx).catch((error: unknown) => console.error(JSON.stringify({ at: "local.scheduled", error: error instanceof Error ? error.message : String(error) })))
  }, SWEEP_MS)

  return {
    origin: address.origin,
    port: server.port ?? config.port,
    address,
    hardening,
    applied,
    state,
    async stop() {
      clearInterval(sweep)
      await server.stop(true)
      await Promise.allSettled(pending)
      closeStores()
      release()
    },
  }
}

export { LocalConfigError }
