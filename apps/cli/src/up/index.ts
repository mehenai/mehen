// mehen up: one command from nothing to an agent using keys it never holds.
// It starts the local vault as a service that comes back with the machine,
// opens the sign-up page for the person's passkey, enrols this machine,
// and wires the agents it finds. Run again, it picks up where it stopped.
// With --json it writes one JSON object per line: what it did, each link a
// person must open (an ask), and a last line with event "done".

import { EXIT } from "@mehen/protocol/api"
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { hostname } from "node:os"
import { join } from "node:path"
import { DEFAULT_PORT, LocalConfigError, resolveConfig } from "../../../local/src/config.ts"
import type { Command } from "../command.ts"
import { fingerprintOf } from "@mehen/protocol/fingerprint"
import { type DeviceJwk, jwkThumbprint } from "@mehen/protocol/proof"
import { fingerprintLines } from "../commands/enrol.ts"
import { homeDir } from "../config.ts"
import { readEnrolmentRecord } from "../enrolment-record.ts"
import { CliError, usageError } from "../errors.ts"
import { ensureSafeDirectory, ensureSafeRoot, resolveHome } from "../home.ts"
import { selfExecutable } from "../install-state.ts"
import { LOCAL_VAULT_RECORD, keyringAdvice, keyringHost } from "../local-vault.ts"
import { printJson, printLine } from "../output.ts"
import { type Segment, type Text, colourEnabled, styler } from "../tty.ts"
import { openUrl } from "./browser.ts"
import { type ServiceKind, ServiceError, installService, removeService, serviceEnvironment, serviceKind } from "./service.ts"

const USAGE = "mehen up [--port <port>] [--data <dir>] [--no-agents] [--timeout <seconds>] | mehen up --remove"
const RECORD_FILE = LOCAL_VAULT_RECORD
const POLL_MS = 1000
const DEFAULT_TIMEOUT_SECONDS = 900

type Record_ = { origin: string; data: string; port: number; service: ServiceKind }
type Custody = "secure-enclave" | "keyring" | "file"
// A vault from before 0.4.1 lists its workspaces without their ids.
type State = { origin: string; instance: string; accounts: boolean; bootstrap: boolean; custody?: Custody; workspaces: { id?: string; slug: string; name: string }[] }
type Env = Record<string, string | undefined>

const CUSTODY_WORDS: Record<Custody, string> = {
  "secure-enclave": "The vault's key is held by this Mac's Secure Enclave.",
  keyring: "The vault's key is in your login keyring.",
  file: "The vault's key is in a file only you can read; see `mehen doctor`.",
}

// A vault from before custody was reported says nothing about it.
function custodyOf(state: State): Custody | null {
  return state.custody !== undefined && Object.hasOwn(CUSTODY_WORDS, state.custody) ? state.custody : null
}

// On a Linux desktop that could keep the key in the login keyring, a file
// custody says what moves it there.
export function custodyLine(custody: Custody | null, advice: string | null = null): string {
  if (custody === null) return ""
  return custody === "file" && advice !== null ? ` ${CUSTODY_WORDS.file} ${advice}` : ` ${CUSTODY_WORDS[custody]}`
}

// How this process runs itself again: the installed binary, or bun and the
// entry script for a run from source.
export function selfCommand(env: Env): string[] {
  const installed = selfExecutable(env)
  if (installed) return [installed]
  return [process.execPath, Bun.main]
}

// Plain text is the CLI's own words, one line per line break, or lines as
// given: a name the vault sent goes in a list, so a line feed in it is
// spelled out rather than starting a line.
export function textLines(text: string | readonly Text[]): readonly Text[] {
  return typeof text === "string" ? text.split("\n") : text
}

function emitter(json: boolean) {
  return {
    event(event: string, fields: Record<string, unknown>, text: string | readonly Text[] | null) {
      if (json) printJson({ event, ...fields })
      else if (text !== null) for (const line of textLines(text)) printLine(line)
    },
  }
}

async function answering(origin: string): Promise<State | null> {
  try {
    const response = await fetch(`${origin}/local/v1/state`, { signal: AbortSignal.timeout(2000) })
    return response.ok ? ((await response.json()) as State) : null
  } catch {
    return null
  }
}

async function until<T>(deadline: number, probe: () => Promise<T | null>): Promise<T | null> {
  for (;;) {
    const found = await probe()
    if (found !== null) return found
    if (Date.now() >= deadline) return null
    await Bun.sleep(POLL_MS)
  }
}

async function self(command: string[], args: string[], env: Env): Promise<{ code: number; out: string; err: string }> {
  const proc = Bun.spawn([...command, ...args], { env: env as Record<string, string>, stdout: "pipe", stderr: "pipe", stdin: "ignore" })
  const [out, err, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
  return { code, out, err }
}

function lastJson(text: string): Record<string, unknown> | null {
  const lines = text.trim().split("\n").filter(Boolean)
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      return JSON.parse(lines[i] as string) as Record<string, unknown>
    } catch {
      continue
    }
  }
  return null
}

function failed(step: string, result: { code: number; out: string; err: string }): CliError {
  const body = lastJson(result.out)
  const message = typeof body?.message === "string" ? body.message : result.err.trim().split("\n").at(-1) ?? `exit ${result.code}`
  return new CliError("failed", `mehen up could not ${step}: ${message}`, { say: "Fix what it says, then run `mehen up` again; it picks up where it stopped." })
}

type SetupAgent = { name?: unknown; mcp?: unknown; reason?: unknown }
type GuardAgent = { agent?: unknown; status?: unknown; reason?: unknown }

const GUARDED = new Set(["claude-code", "pi", "cursor", "codex"])

// The guard's part of an agent's line: on, on once Codex trusts it, in
// place but at warn or off, or not on and why; nothing for an agent the
// guard does not cover.
function guardNote(name: string, g: GuardAgent | undefined, ran: boolean, level: unknown): string {
  if (!GUARDED.has(name)) return ""
  if (!ran) return ", guard not on (run `mehen guard install` to see why)"
  if (g && (g.status === "added" || g.status === "updated" || g.status === "unchanged")) {
    if (level === "off") return ", guard installed, guard off"
    if (level === "warn") return `, guard installed, warn only${name === "codex" ? " once you trust it in Codex's /hooks" : ""}`
    return name === "codex" ? ", guard on once you trust it in Codex's /hooks" : ", guard on"
  }
  if (g && typeof g.reason === "string") return `, guard not on (${g.reason})`
  return ""
}

// What setup and the guard actually did, one line per agent, so a skipped
// or failed one is never reported as wired.
export function agentLines(setup: Record<string, unknown> | null, guard: Record<string, unknown> | null): string {
  if (setup === null) return "Agents: `mehen setup` did not finish; run `mehen setup` to see why."
  const wired = (Array.isArray(setup.agents) ? (setup.agents as SetupAgent[]) : []).map((a) => ({ name: String(a.name), ok: a.mcp === "added" || a.mcp === "updated" || a.mcp === "unchanged", reason: typeof a.reason === "string" ? a.reason : null }))
  const guards = new Map((Array.isArray(guard?.agents) ? (guard.agents as GuardAgent[]) : []).map((g) => [String(g.agent), g]))
  if (wired.length === 0) return "Agents: none found on this machine. Install one, then run `mehen setup`."
  const lines = wired.map((a) => {
    return a.ok ? `  ${a.name}: wired${guardNote(a.name, guards.get(a.name), guard !== null, guard?.level)}` : `  ${a.name}: not wired (${a.reason ?? "see mehen setup"})`
  })
  return `Agents (restart them to pick Mehen up):\n${lines.join("\n")}`
}

// What a person at the terminal needs for the enrolment page: the link, and
// the fingerprint, since the page hides one of its groups and accepts only
// once that group is typed from here. `words` are mehen enrol's lines for
// the fingerprint's coloured words and the hidden group.
export function enrolLines(url: string, opened: boolean, fingerprint: string | null, words: readonly Segment[][] = []): Text[] {
  const check = fingerprint ? `This machine's fingerprint is ${fingerprint}. The page shows all but one of its groups: type the one it hides, then accept with your passkey.` : "Accept this machine with your passkey."
  return [`${opened ? "Opened" : "Open"} ${url}`, check, ...(fingerprint ? words : []), "This carries on by itself."]
}

// The words and hidden group for the pending enrolment, from the key in its
// own slot, and only when that key is the one whose fingerprint enrol
// reported: nothing here is taken from the vault.
async function fingerprintWordLines(slot: unknown, enrolment: string, code: unknown, fingerprint: string | null, colour: boolean): Promise<Segment[][]> {
  if (typeof slot !== "string" || typeof code !== "string" || fingerprint === null) return []
  try {
    const read = await readEnrolmentRecord(slot)
    if (read === null || !("record" in read) || read.record.id !== enrolment) return []
    const thumbprint = await jwkThumbprint(read.record.jwk as DeviceJwk)
    if (fingerprintOf(thumbprint) !== fingerprint) return []
    return await fingerprintLines({ thumbprint, code }, styler(colour))
  } catch {
    return []
  }
}

// The enrolment's context names the workspace it joins. `mehen enrol` alone
// leaves it null until the slot is verified, since it knows only the slug it
// asked for; here the workspace comes from the vault up checked by its
// instance token, read from that vault's own database.
export function enrolContext(origin: string, workspace: State["workspaces"][number]): { origin: string; workspace: { id: string; slug: string; name: string } | null; device: null } {
  return { origin, workspace: typeof workspace.id === "string" ? { id: workspace.id, slug: workspace.slug, name: workspace.name } : null, device: null }
}

// The link stays in the message: it is the local vault's own page, which a
// next.url would have checked against the vault this machine is enrolled
// with, and refused before enrolment ends.
export function timedOut(what: string, url: string | null): CliError {
  return new CliError("timeout", url ? `Still waiting for ${what} on ${url}.` : `Still waiting for ${what}.`, { say: "Run `mehen up` again when it is done; it picks up where it stopped." })
}

async function remove(env: Env, json: boolean, root: string): Promise<number> {
  const path = join(root, RECORD_FILE)
  if (!existsSync(path)) {
    if (json) printJson({ event: "done", removed: false })
    else printLine("No local vault was set up by mehen up on this machine; nothing to remove.")
    return EXIT.ok
  }
  const record = JSON.parse(readFileSync(path, "utf8")) as Record_
  const problems = removeService(record.service, record.data, homeDir(env), env)
  if (problems.length > 0) {
    throw new CliError("failed", `The local vault's ${record.service} service is not fully removed: ${problems.join("; ")}.`, { say: "Do what it says, then run `mehen up --remove` again; the record of the service is kept until it is gone." })
  }
  rmSync(path, { force: true })
  if (json) printJson({ event: "done", removed: true, service: record.service, data: record.data })
  else printLine(`Stopped the local vault and removed its ${record.service} service. Its data is still in ${record.data}.`)
  return EXIT.ok
}

export const upCommand: Command = {
  summary: "set up Mehen on this machine in one go: the local vault, your passkey, this machine and your agents (run it again to resume)",
  spec: { usage: USAGE, flags: { port: { type: "string" }, data: { type: "string" }, "no-agents": { type: "boolean" }, timeout: { type: "string" }, remove: { type: "boolean" } }, positionals: { min: 0, max: 0 } },
  examples: [["up"], ["up", "--json"], ["up", "--no-agents"], ["up", "--remove"]],
  notes: [
    `The vault answers at http://localhost:${DEFAULT_PORT} on this machine only, and starts again when the machine does.`,
    "A person makes a passkey on the page it opens; everything after that happens here.",
    "--json writes one JSON object per line: event vault, ask (a link a person must open), workspace, machine, agents, then done.",
    "--remove stops the vault and removes its service; the data stays.",
  ],
  async run({ args, json, env }) {
    const { root, source } = resolveHome(env)
    ensureSafeRoot(root)
    if (args.bool("remove")) return remove(env, json, root)

    let config
    let savedService: string | null = null
    try {
      // Run again with no flags, it carries on with the vault it set up.
      const recordPath = join(root, RECORD_FILE)
      const saved = existsSync(recordPath) ? (JSON.parse(readFileSync(recordPath, "utf8")) as Partial<Record_>) : {}
      const port = args.string("port") ?? (typeof saved.port === "number" ? String(saved.port) : undefined)
      const dataDir = args.string("data") ?? (typeof saved.data === "string" ? saved.data : undefined)
      savedService = typeof saved.service === "string" ? saved.service : null
      config = resolveConfig({ dataDir, port }, { ...env, MEHEN_SERVE_ORIGIN: undefined, MEHEN_SERVE_HOST: undefined })
    } catch (error) {
      if (error instanceof LocalConfigError) throw usageError(error.message, USAGE)
      throw error
    }
    if (config.port === 0) throw usageError("mehen up needs a fixed port, so agents and the service find the vault at the same address every time; leave --port out for 7787 or give another.", USAGE)
    const rawTimeout = args.string("timeout")
    const timeoutSeconds = rawTimeout === null ? DEFAULT_TIMEOUT_SECONDS : Number(rawTimeout)
    if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 1) throw usageError("--timeout takes a whole number of seconds.", USAGE)
    const deadline = Date.now() + timeoutSeconds * 1000
    const out = emitter(json)
    const origin = `http://localhost:${config.port}`
    const command = selfCommand(env)

    // 1. The vault, as a service. Whatever answers on the port must be the
    // vault this data directory belongs to: it wrote its instance token
    // there, which nothing outside this user's files can know.
    const instanceFile = join(config.dataDir, "instance")
    const ours = async (): Promise<State | null> => {
      const state = await answering(origin)
      if (state === null) return null
      const token = existsSync(instanceFile) ? readFileSync(instanceFile, "utf8").trim() : null
      if (token === null || state.instance !== token) throw new CliError("conflict", `Something is answering at ${origin} that is not the vault in ${config.dataDir}, so mehen up will not use it.`, { say: `Stop what is listening on port ${config.port}, or run \`mehen up --port <another port>\`.` })
      return state
    }
    let state = await ours()
    const kind = serviceKind(env, process.platform, selfExecutable(env) !== null)
    const advice = (service: string | null) => keyringAdvice(keyringHost(env), service)
    if (state === null) {
      ensureSafeDirectory(config.dataDir, (path, why) => new CliError("key_insecure", `Refusing to keep the vault in ${path}: it ${why}.`, { say: "Give it a data directory only this user can write (--data), then run `mehen up` again." }))
      // Written before the service exists, so an interrupted install can
      // still be found and removed with mehen up --remove.
      writeFileSync(join(root, RECORD_FILE), JSON.stringify({ origin, data: config.dataDir, port: config.port, service: kind } satisfies Record_), { mode: 0o600 })
      let service
      try {
        service = installService({ kind, command: [...command, "serve", "--port", String(config.port), "--data", config.dataDir], dataDir: config.dataDir, home: homeDir(env), logFile: join(config.dataDir, "serve.log"), environment: serviceEnvironment({ ...env, MEHEN_HOME: source === "default" ? undefined : root }) }, env)
      } catch (error) {
        if (error instanceof ServiceError) throw new CliError("failed", error.message, { say: `Start the vault yourself with \`mehen serve --port ${config.port}\`, then run \`mehen up\` again.` })
        throw error
      }
      state = await until(Date.now() + 20_000, () => ours().catch(() => null))
      if (state === null) throw new CliError("failed", `The vault did not answer at ${origin} within 20 seconds.`, { say: `${service.kind === "systemd" ? "Read `journalctl --user -u mehen-vault.service`" : `Read ${join(config.dataDir, "serve.log")}`}, or start it yourself with \`mehen serve --port ${config.port}\` to see why.` })
      writeFileSync(join(root, RECORD_FILE), JSON.stringify({ origin, data: config.dataDir, port: config.port, service: service.kind } satisfies Record_), { mode: 0o600 })
      const custody = custodyOf(state)
      out.event("vault", { origin, data: config.dataDir, service: service.kind, startsAtLogin: service.startsAtLogin, custody }, `Vault running at ${origin} (${service.startsAtLogin ? `${service.kind} service, starts when you log in` : "until this machine restarts; run mehen up again after a restart"}).${custodyLine(custody, advice(service.kind))}`)
    } else {
      const custody = custodyOf(state)
      out.event("vault", { origin, data: config.dataDir, service: null, startsAtLogin: null, custody }, `Vault running at ${origin}.${custodyLine(custody, advice(savedService))}`)
    }

    // 2. The person's account and workspace, made in the browser.
    if (!state.accounts || state.workspaces.length === 0) {
      // The vault's start page sends the browser on to sign-up with its
      // one-time code, so the code never appears here or in argv.
      const url = state.accounts ? `${origin}/signin` : `${origin}/local/v1/start`
      const opened = openUrl(url, env)
      out.event("ask", { ask: { kind: "signup", url, title: state.accounts ? "Create your workspace" : "Make your passkey", what: "Make a passkey, save the recovery codes and create a workspace; this command carries on by itself", opened } }, `${opened ? "Opened" : "Open"} ${url}\nMake your passkey, save the recovery codes and create a workspace there. This carries on by itself.`)
      state = await until(deadline, async () => {
        const now = await ours()
        return now && now.accounts && now.workspaces.length > 0 ? now : null
      })
      if (state === null) throw timedOut("a passkey and a workspace", url)
    }
    const wanted = env.MEHEN_WORKSPACE
    const workspace = wanted ? state.workspaces.find((w) => w.slug === wanted) : state.workspaces[0]
    if (!workspace) throw usageError(`This vault has no workspace ${wanted}; it has ${state.workspaces.map((w) => w.slug).join(", ")}.`, USAGE)
    out.event("workspace", { slug: workspace.slug, name: workspace.name }, [`Workspace: ${workspace.name} (${workspace.slug})`])

    // 3. This machine, accepted on the page with the passkey.
    const childEnv: Env = { ...env, MEHEN_VAULT_URL: origin, MEHEN_WORKSPACE: undefined }
    const name = (hostname().split(".")[0] ?? "machine").slice(0, 64) || "machine"
    const enrol = await self(command, ["enrol", "--workspace", workspace.slug, "--name", name, "--json"], childEnv)
    if (enrol.code !== 0) throw failed("enrol this machine", enrol)
    let machine = lastJson(enrol.out)
    if (machine?.status === "pending") {
      const ask = machine.ask as { url: string; check?: { value: string } } | undefined
      const id = String(machine.enrolment)
      const opened = ask ? openUrl(ask.url, env) : false
      const fingerprint = ask?.check?.value ?? null
      const words = json ? [] : await fingerprintWordLines(machine.slot, id, machine.code, fingerprint, colourEnabled(process.stdout, env))
      out.event("ask", { ask: { ...(ask ?? {}), opened, context: enrolContext(origin, workspace) } }, enrolLines(ask?.url ?? "", opened, fingerprint, words))
      const remaining = Math.max(1, Math.ceil((deadline - Date.now()) / 1000))
      const waited = await self(command, ["wait", id, "--timeout", String(remaining), "--json"], childEnv)
      if (waited.code !== 0) {
        const body = lastJson(waited.out)
        if (body?.error === "timeout") throw timedOut("this machine to be accepted", ask?.url ?? null)
        throw failed("finish enrolling this machine", waited)
      }
      machine = lastJson(waited.out)
    }
    out.event("machine", { device: machine?.device ?? null, name }, [`This machine: ${name}`])

    // 4. The agents, where an installed mehen can register itself.
    if (args.bool("no-agents")) out.event("agents", { skipped: "no-agents" }, null)
    else if (selfExecutable(env) === null) out.event("agents", { skipped: "source" }, "Agents: run `mehen setup` with an installed mehen to wire them.")
    else {
      const setup = await self(command, ["setup", "--json"], childEnv)
      const body = lastJson(setup.out)
      // The guard hooks, where an agent runs them: Claude Code, pi, Cursor and Codex.
      const guard = await self(command, ["guard", "install", "--json"], childEnv)
      const guarded = guard.code === 0 ? lastJson(guard.out) : null
      out.event("agents", { ok: setup.code === 0, setup: body, guard: guarded }, agentLines(setup.code === 0 ? body : null, guarded))
    }

    out.event("done", { origin, workspace: workspace.slug, next: { say: "Move the keys already on this machine into the vault with `mehen adopt scan`." } }, "Done. Next: `mehen adopt scan` finds the keys already on this machine.")
    return EXIT.ok
  },
}
