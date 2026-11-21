// mehen run [--env E] [--approval A] [--stop-grace S] [--service] [--stream-writes] [--item SLUG[=VAR]]... [--] command args...
//
// Creates a run in the vault, builds the child's environment from mehen.toml and
// the vault's answer, starts the local relay when there are placeholders or
// base URLs, renews the run while the child lives and ends it on exit. At the
// run's maximum life the child gets SIGTERM --stop-grace seconds before the end.
// --service asks for a service run, which has none. --stream-writes (or
// MEHEN_RUN_STREAM_WRITES=1) has the local relay pass every write's answer
// on as it comes instead of reading it in full first. --item gives the
// command one credential with no project, each request relayed as
// vault_fetch relays it (ad-hoc.ts); in a checkout with mehen.toml the
// project's run goes on beside it.

import { constants } from "node:os"
import { dirname } from "node:path"
import * as tty from "node:tty"
import { EXIT, type NextStep, type RunCreated } from "@mehen/protocol/api"
import type { RedactionSecret, WorkspaceRunCreated } from "@mehen/protocol"
import { startRunRelay, type RunRelay } from "../relay/index.ts"
import { toCliError, usageError } from "../errors.ts"
import { askForError } from "../ask.ts"
import { errorLines } from "../output.ts"
import { terminalText } from "../tty.ts"
import type { VaultApiError } from "../vault-api.ts"
import { CommandError, type Deps, askVault, cwdOf, envOf, mehenLine, nextLines, reportFailure, stylerFor, wantsHelp, warningLine, writeLine, writeNext } from "./deps.ts"
import { inheritedEnv, resolveEnv, writeBanner } from "./environment.ts"
import { locateProjectManifest } from "./bound-project.ts"
import { type AdHocSpec, checkAdHocConflicts, checkItemSpecs, parseItemSpec, resolveAdHocItems } from "./ad-hoc.ts"
import { type Located, findManifest, gitFacts, locateManifest } from "./manifest.ts"
import { pipeRedacted } from "./output.ts"
import { type RunWarning, bypassWarning, childNodeVersion, dotenvFiles, dotenvWarning, nodeWarning } from "./run-warnings.ts"
import { type RunLogEntry, appendRunLog } from "./run-log.ts"
import { MAX_STOP_GRACE_MS, signalProcessGroup, watchRunAuthority } from "./renewal.ts"

export const RUN_USAGE = "mehen run [--env <env>] [--approval <id>] [--stop-grace <seconds>] [--service] [--stream-writes] [--item <slug>[=<VAR>]]... [--] <command> [args...]"
const FORWARDED_SIGNALS = ["SIGINT", "SIGTERM"] as const
const VALUE_FLAGS = ["--env", "--approval", "--stop-grace", "--item"] as const

type RunArgs = { env?: string; approval?: string; stopGraceMs?: number; service?: boolean; streamWrites?: boolean; items?: AdHocSpec[]; command: string[] }

// The usage when `mehen run` is asked for help, else null.
export function runHelp(argv: string[]): string | null {
  return wantsHelp(argv, VALUE_FLAGS, true) ? RUN_USAGE : null
}

const RUN_HELP = "mehen run --help"

function flagValue(argv: string[], i: number, flag: string): string {
  const value = argv[i + 1]
  if (value === undefined || value.startsWith("-")) throw usageError(`${flag} needs a value. Usage: ${RUN_USAGE}`, RUN_HELP)
  return value
}

function stopGraceMs(value: string): number {
  const seconds = /^\d+$/.test(value) ? Number(value) : NaN
  if (!(seconds >= 1 && seconds * 1000 <= MAX_STOP_GRACE_MS)) throw usageError(`--stop-grace takes whole seconds from 1 to ${MAX_STOP_GRACE_MS / 1000}. Usage: ${RUN_USAGE}`, RUN_HELP)
  return seconds * 1000
}

function setFlag(args: RunArgs, flag: string, value: string): void {
  if (flag === "--env") args.env = value
  else if (flag === "--approval") args.approval = value
  else if (flag === "--item") args.items = [...(args.items ?? []), parseItemSpec(value)]
  else args.stopGraceMs = stopGraceMs(value)
}

// Whether the local relay passes every write's answer on as it comes.
export function streamsWrites(args: Pick<RunArgs, "streamWrites">, env: Record<string, string | undefined>): boolean {
  return args.streamWrites === true || env.MEHEN_RUN_STREAM_WRITES === "1"
}

// The arguments of mehen run, or a usage error; cli.ts calls it before it
// opens the vault session, so a bad line needs no enrolment to be refused.
export function parseRunArgs(argv: string[]): RunArgs {
  const args: RunArgs = { command: [] }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? ""
    if (arg === "--") {
      args.command = argv.slice(i + 1)
      break
    }
    const inline = VALUE_FLAGS.find((flag) => arg.startsWith(`${flag}=`))
    if ((VALUE_FLAGS as readonly string[]).includes(arg)) {
      setFlag(args, arg, flagValue(argv, i, arg))
      i++
    } else if (inline !== undefined) {
      setFlag(args, inline, arg.slice(inline.length + 1))
    } else if (arg === "--service") {
      args.service = true
    } else if (arg === "--stream-writes") {
      args.streamWrites = true
    } else if (arg.startsWith("-")) {
      throw usageError(`Unknown option ${arg} for \`${RUN_USAGE}\`.`, RUN_HELP)
    } else {
      args.command = argv.slice(i)
      break
    }
  }
  if (args.command.length === 0) throw usageError(`Name the command to run. Usage: ${RUN_USAGE}`, RUN_HELP)
  if (args.items !== undefined) checkItemSpecs(args.items)
  return args
}

// The checkout's manifest when there is one, for a run with --item, which
// needs none. A manifest that is there but cannot be read is still refused.
function optionalManifest(cwd: string): Located | null {
  const facts = gitFacts(cwd)
  return findManifest(cwd, facts.root) === null ? null : locateManifest(cwd, facts)
}

function missingVars(created: RunCreated, requested: string[]): { name: string; next: NextStep }[] {
  const byName = new Map(created.vars.map((v) => [v.name, v]))
  return requested.flatMap((name) => {
    const v = byName.get(name)
    if (v === undefined) {
      return [{ name, next: { say: `The vault returned nothing for ${name}. Check how it resolves with mehen env ls --env ${created.env}.` } }]
    }
    return v.delivery === "missing" ? [{ name, next: v.next }] : []
  })
}

function exitCodeOf(exitCode: number | null, signalCode: string | null): number {
  if (exitCode !== null) return exitCode
  const number = signalCode === null ? undefined : constants.signals[signalCode as keyof typeof constants.signals]
  return 128 + (number ?? 1)
}

type RunWithOverrides = RunCreated & Partial<Pick<WorkspaceRunCreated, "overrides">>

// What the run log needs, filled in as the run goes: set once the vault
// has created the run, and the child's exit once it has one.
// `signal`: the first SIGINT or SIGTERM mehen run received while the child ran.
type Finished = { start: Omit<RunLogEntry, "endedAt" | "exit" | "signal" | "forwarded"> | null; exit: number | string | null; signal: (typeof FORWARDED_SIGNALS)[number] | null }

// The ask a refusal of one of the child's requests carries, on mehen run's
// own stderr: the block mehen fetch prints, with its links checked the same
// way, once per approval (or link) per run. The child gets its answer as
// before; most programs never show a 409, so the person would not see the
// link otherwise. The relay saves nothing to resend, so then: says to send
// the request again. The block goes out in one write, so it is not cut by the
// child's own output, though it can land after a partial line of the child's.
export function heldAskEcho(deps: Deps): (error: VaultApiError) => void {
  const shown = new Set<string>()
  const env = envOf(deps)
  const vault = askVault(deps)
  return (error) => {
    const failure = toCliError(error)
    const { ask, refusedLink } = askForError(failure, env, vault)
    if (ask === null && !refusedLink) return
    const key = failure.extras.approval ?? (ask !== null ? `${ask.kind}:${ask.id}:${ask.url}` : `refused:${failure.code}:${failure.message}`)
    if (shown.has(key)) return
    shown.add(key)
    const then = (held: { kind: string; wait: string | null }) =>
      held.kind === "approval" ? `${held.wait ? `${held.wait} waits for the decision; once approved, ` : "once approved, "}have the program send the same request again: the vault lets that exact request through once. mehen run does not save or resend it.` : held.wait
    const lines = errorLines(failure, deps.stderr, { env, vaultUrl: vault, then })
    deps.stderr.write(`${lines.map(terminalText).join("\n")}\n`)
  }
}

function writeWarning(deps: Deps, warning: RunWarning | null): void {
  if (warning === null) return
  const s = stylerFor(deps, deps.stderr)
  writeLine(deps.stderr, warningLine(s, warning.message))
  for (const line of nextLines(warning.next, askVault(deps), s, warning.commands)) writeLine(deps.stderr, line)
}

export async function runCommand(argv: string[], deps: Deps): Promise<number> {
  const finished: Finished = { start: null, exit: null, signal: null }
  const code = await runOnce(argv, deps, finished)
  if (finished.start !== null && deps.runLog !== undefined) {
    try {
      await appendRunLog(deps.runLog, { ...finished.start, endedAt: new Date().toISOString(), exit: finished.exit ?? code, ...(finished.signal !== null ? { signal: finished.signal, forwarded: true as const } : {}) })
    } catch (error) {
      const why = (error as NodeJS.ErrnoException).code ?? (error instanceof Error ? error.message : "error")
      writeLine(deps.stderr, warningLine(stylerFor(deps, deps.stderr), `could not add this run to ${deps.runLog} (${why}); the run itself is unaffected`))
    }
  }
  return code
}

async function runOnce(argv: string[], deps: Deps, finished: Finished): Promise<number> {
  const help = runHelp(argv)
  if (help !== null) {
    deps.stdout.write(`usage: ${help}\n`)
    return EXIT.ok
  }
  let created: RunWithOverrides | null = null
  let relay: RunRelay | null = null
  let authority: ReturnType<typeof watchRunAuthority> | undefined
  const handlers: [string, () => void][] = []
  const s = stylerFor(deps, deps.stderr)
  try {
    const args = parseRunArgs(argv)
    const parentEnv = envOf(deps)
    const specs = args.items ?? []
    // With --item a checkout needs no mehen.toml; with one, the project's run goes on beside the items.
    const located = specs.length > 0 ? optionalManifest(cwdOf(deps)) : await locateProjectManifest(deps.api, cwdOf(deps))
    const manifest = located?.manifest ?? null
    if (located === null) {
      const flag = args.env !== undefined ? "--env" : args.approval !== undefined ? "--approval" : args.service ? "--service" : null
      if (flag !== null) throw usageError(`${flag} needs a project, and there is no mehen.toml here: --item alone runs with no project or environment.`, RUN_HELP)
    }
    const items = specs.length > 0 ? await resolveAdHocItems(deps.api, specs) : []
    checkAdHocConflicts(items, manifest?.vars.map((v) => v.name) ?? [], [])
    const resolved = manifest === null ? null : resolveEnv(args.env, parentEnv, manifest)
    if (located !== null && resolved !== null) writeBanner(deps.stderr, located, resolved.env, args.service === true)
    if (items.length > 0) writeLine(deps.stderr, mehenLine(s, `ad hoc ${items.map((i) => `${i.item}=${i.variable}`).join(" ")} (each request is a fetch)`))

    const requested = manifest?.vars.filter((v) => v.source === "vault").map((v) => v.name) ?? []
    if (located !== null && manifest !== null && resolved !== null) {
      created = await deps.api.request<RunWithOverrides>("POST", "/v1/runs", {
        project: manifest.project,
        env: resolved.env,
        envSource: resolved.source,
        remote: located.git.remote,
        worktree: located.worktree,
        head: located.git.head,
        vars: requested,
        command: args.command.slice(0, 2).join(" ").slice(0, 200),
        argv: args.command,
        ...(args.approval !== undefined ? { approval: args.approval } : {}),
        ...(args.service ? { service: true } : {}),
      })
      finished.start = { at: new Date().toISOString(), root: dirname(manifest.path), project: manifest.project, env: resolved.env, service: args.service === true }
    }
    const run = created
    if (run !== null) {
      // Only null means a service run; a vault from before endsAt sends none.
      if (args.service && run.endsAt !== null) {
        writeLine(deps.stderr, warningLine(s, `run ${run.run} is not a service run: this vault does not offer them, so it ends at ${run.endsAt ?? "its maximum life"}`))
      }
      for (const name of new Set(run.overrides ?? [])) {
        if (!requested.includes(name)) continue
        const variable = run.vars.find(v => v.name === name)
        const source = variable && "item" in variable ? `your ${variable.item}` : variable?.delivery === "plain" ? "your plain value" : "your source"
        writeLine(deps.stderr, mehenLine(s, `${name}: override (${source})`))
      }

      const missing = missingVars(run, requested)
      if (missing.length > 0) {
        // run.env and each next step came from the vault: every line crosses the boundary.
        writeLine(deps.stderr, mehenLine(s, `not starting ${args.command[0]}: ${missing.map((m) => m.name).join(", ")} ${missing.length === 1 ? "has" : "have"} no value for env=${run.env}`))
        for (const m of missing) {
          writeLine(deps.stderr, `${m.name}:`)
          writeNext(deps.stderr, m.next, askVault(deps), s)
        }
        return EXIT.human
      }
    }

    const wanted = new Set(requested)
    const delivered = run?.vars.filter((v) => wanted.has(v.name)) ?? []
    const placeholders = delivered.some((v) => v.delivery === "placeholder")
    if (run !== null) checkAdHocConflicts(items, [], placeholders ? run.interceptHosts : [])
    const baseUrls = delivered.flatMap((v) => (v.delivery === "base-url" ? [{ item: v.item, upstream: v.value }] : []))
    const standIns = placeholders || items.length > 0
    if (standIns || baseUrls.length > 0) {
      relay = await startRunRelay({
        api: deps.api,
        run: run?.run ?? null,
        env: run?.env ?? "",
        interceptHosts: run?.interceptHosts ?? [],
        fencedHosts: run?.fencedHosts ?? [],
        baseUrls,
        ...(items.length > 0 ? { itemRoutes: items } : {}),
        proxy: standIns,
        onVaultRefusal: heldAskEcho(deps),
        parentEnv,
        streamWrites: streamsWrites(args, parentEnv),
      }).catch((error: unknown) => {
        throw new CommandError(EXIT.error, `could not start the local relay: ${error instanceof Error ? error.message : String(error)}`, {
          say: "Nothing was run. Try again; if it keeps failing, report it with this message.",
        })
      })
    }

    const childEnv = inheritedEnv(parentEnv, manifest?.vars.map((v) => v.name) ?? [], items, deps.stderr)
    for (const v of manifest?.vars ?? []) if (v.source === "plain") childEnv[v.name] = v.value
    const leased: RedactionSecret[] = []
    for (const v of delivered) {
      if (v.delivery === "missing") continue
      if (v.delivery === "base-url") {
        const local = relay?.baseUrls.get(v.item)
        if (local !== undefined) childEnv[v.name] = local
        continue
      }
      childEnv[v.name] = v.value
      if (v.delivery === "lease") leased.push({ label: v.name, value: v.value })
    }
    for (const item of items) childEnv[item.variable] = item.standIn
    if (relay !== null) Object.assign(childEnv, relay.env)

    const commandName = args.command[0] ?? "the command"
    writeWarning(deps, dotenvWarning(dotenvFiles([...(manifest !== null ? [dirname(manifest.path)] : []), cwdOf(deps)]), cwdOf(deps), commandName))
    if (standIns) {
      // The version check is a second process: it gets no leased value.
      const leasedNames = new Set(leased.map((l) => l.label))
      const probeEnv = Object.fromEntries(Object.entries(childEnv).filter(([name]) => !leasedNames.has(name)))
      const version = await childNodeVersion(commandName, probeEnv, cwdOf(deps))
      if (version !== null) writeWarning(deps, nodeWarning(version))
    }

    if (run !== null && (!Number.isFinite(Date.parse(run.expiresAt)) || Date.parse(run.expiresAt) <= Date.now())) {
      throw new CommandError(EXIT.error, `run ${run.run} expired before the child could start.`, { say: "Start a new run with mehen run." })
    }
    const redact = leased.length > 0
    const detached = !tty.isatty(0)
    let child: Bun.Subprocess<"inherit", "pipe" | "inherit", "pipe" | "inherit">
    try {
      child = Bun.spawn(args.command, {
        cwd: cwdOf(deps),
        env: childEnv,
        detached,
        stdin: "inherit",
        stdout: redact ? "pipe" : "inherit",
        stderr: redact ? "pipe" : "inherit",
      })
    } catch (error) {
      throw new CommandError(EXIT.error, `could not start ${args.command[0]}: ${error instanceof Error ? error.message : String(error)}`, {
        say: "Check the command name and that it is on PATH.",
      })
    }
    let childExited = false
    void child.exited.then(() => { childExited = true })
    // A detached child gets each signal through its group. A terminal child
    // shares mehen's foreground group and gets Ctrl-C from the terminal itself,
    // so mehen only keeps itself alive to clean up and pass on the child's exit;
    // a SIGTERM sent to mehen alone is passed to the child.
    for (const signal of FORWARDED_SIGNALS) {
      const forward = () => {
        if (childExited) return
        finished.signal ??= signal
        if (detached) signalProcessGroup(child.pid, signal)
        else if (signal === "SIGTERM") {
          try {
            process.kill(child.pid, signal)
          } catch {
            // Exited between the check and the signal.
          }
        }
      }
      handlers.push([signal, forward])
      process.on(signal, forward)
    }
    // An ad hoc run has no vault run to renew: each request is decided on its own.
    authority = run === null ? undefined : watchRunAuthority({
      api: deps.api,
      run,
      child,
      detached,
      ...(args.stopGraceMs !== undefined ? { stopGraceMs: args.stopGraceMs } : {}),
      closeCredentials: async () => {
        const active = relay
        relay = null
        await active?.close()
      },
      warn: (message) => writeLine(deps.stderr, warningLine(s, message)),
    })

    const pipes: Promise<void>[] = []
    if (redact && child.stdout instanceof ReadableStream) pipes.push(pipeRedacted(child.stdout, deps.stdout, leased))
    if (redact && child.stderr instanceof ReadableStream) pipes.push(pipeRedacted(child.stderr, deps.stderr, leased))
    await Promise.race(authority === undefined ? [child.exited] : [child.exited, authority.failure])
    if (authority?.stopping) {
      const failure = await authority.failure
      await Promise.all(pipes)
      throw failure
    }
    await Promise.all(pipes)
    finished.exit = child.signalCode ?? child.exitCode
    // Not after a Ctrl-C or a stop mehen passed on: a dev server stopped
    // before anything called it is no sign of a bypass. A quick non-zero exit
    // still warns, since a client that skipped the proxy fails fast on the 401.
    if (standIns && finished.signal === null && relay !== null && relay.seen().interceptHosts === 0) writeWarning(deps, bypassWarning([...(placeholders ? run?.interceptHosts ?? [] : []), ...items.flatMap((i) => i.hosts)], commandName))
    return exitCodeOf(child.exitCode, child.signalCode)
  } catch (error) {
    return reportFailure(deps, error)
  } finally {
    authority?.dispose()
    for (const [signal, handler] of handlers) process.off(signal, handler)
    if (relay !== null) await relay.close()
    if (created !== null) {
      const { run } = created
      await deps.api.request("DELETE", `/v1/runs/${run}`, undefined, { signal: AbortSignal.timeout(5000) }).catch(() => {
        writeLine(deps.stderr, warningLine(s, `could not end run ${run}; it expires at its last confirmed deadline.`))
      })
    }
  }
}
