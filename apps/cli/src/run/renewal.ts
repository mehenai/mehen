import * as childProcess from "node:child_process"
import { EXIT, EXIT_FOR_ERROR, type ErrorCode, type ExitCode, type RunCreated } from "@mehen/protocol/api"
import { VaultApiError, type VaultApi } from "../vault-api.ts"
import { CommandError } from "./deps.ts"

const RENEW_INTERVAL_MS = 5 * 60_000
const WARNING_MS = 60_000
const KILL_GRACE_MS = 10_000
export const DEFAULT_STOP_GRACE_MS = 10_000
export const MAX_STOP_GRACE_MS = 5 * 60_000
const PS_TIMEOUT_MS = 1000

type RunChild = { pid: number; exited: Promise<number> }
type ProcessParents = ReadonlyMap<number, number>

function readProcessParents(): Promise<ProcessParents> {
  return new Promise((resolve, reject) => {
    childProcess.execFile("ps", ["-A", "-o", "pid=,ppid="], { timeout: PS_TIMEOUT_MS, maxBuffer: 1024 * 1024, encoding: "utf8", shell: false, killSignal: "SIGKILL" }, (error, stdout) => {
      if (error !== null) {
        reject(error)
        return
      }
      const parents = new Map<number, number>()
      for (const line of stdout.split("\n")) {
        const match = /^\s*(\d+)\s+(\d+)\s*$/.exec(line)
        if (match !== null) parents.set(Number(match[1]), Number(match[2]))
      }
      resolve(parents)
    })
  })
}

function processTree(root: number, parents: ProcessParents): number[] {
  if (!parents.has(root)) return []
  const children = new Map<number, number[]>()
  for (const [pid, parent] of parents) {
    const siblings = children.get(parent) ?? []
    siblings.push(pid)
    children.set(parent, siblings)
  }
  const tree = new Set([root])
  for (const pid of tree) for (const child of children.get(pid) ?? []) tree.add(child)
  return [...tree].reverse()
}

function signalProcess(pid: number, signal: NodeJS.Signals): boolean {
  try {
    process.kill(pid, signal)
    return true
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ESRCH")) throw error
    return false
  }
}

export function signalProcessGroup(pid: number, signal: NodeJS.Signals): void {
  signalProcess(-pid, signal)
}

// Why the watcher stopped the child, and the code mehen run exits with.
type RunEnd = { reason: string; exit: ExitCode; say: string }

const MAX_LIFE_END: RunEnd = {
  reason: "has reached its maximum life",
  exit: EXIT.transient,
  say: "Renewal cannot extend a run past its maximum life. Start a new run to continue.",
}
const EXPIRED_END: RunEnd = {
  reason: "has reached its last confirmed expiry",
  exit: EXIT.transient,
  say: "The vault did not renew the run in time. Check the network and the vault, then start a new run.",
}

// Renewal refusals a retry may outlive; every other 4xx refusal ends the run at once.
const RETRYABLE_REFUSALS: ReadonlySet<ErrorCode> = new Set(["rate_limited", "upstream_failed", "refresh_retrying"])

const REFUSAL_REASONS: Partial<Record<ErrorCode, string>> = {
  not_found: "has ended or expired",
  device_revoked: "lost access because this machine was revoked",
  frozen: "lost access because the vault is frozen",
  forbidden: "is no longer authorised",
  unauthenticated: "can no longer authenticate this machine",
  proof_invalid: "can no longer authenticate this machine",
  conflict: "was ended because its sources or credentials changed",
  remote_mismatch: "no longer matches the project's bound repository",
  owner_inactive: "lost access because this machine's owner is inactive",
  project_unshared: "lost access to its project",
  workload_ended: "lost access because its workload ended",
}

function refusalEnd(code: ErrorCode): RunEnd {
  const reason = REFUSAL_REASONS[code] ?? `was refused by the vault (${code})`
  // Changed sources need only a fresh run, which a supervisor starts again.
  if (code === "conflict") return { reason, exit: EXIT.transient, say: "Start a new run; it picks up the changed sources." }
  return {
    reason,
    exit: EXIT_FOR_ERROR[code] ?? EXIT.error,
    say: "Check the vault and this machine's access, then start a new run.",
  }
}

// A 4xx answer that is a vault refusal; a 4xx without a readable vault error
// reads as internal and may come from something in between.
function terminalRefusal(error: unknown): ErrorCode | null {
  if (!(error instanceof VaultApiError) || error.status < 400 || error.status >= 500) return null
  const code = error.body.error
  return code === "internal" || RETRYABLE_REFUSALS.has(code) ? null : code
}

function runEndError(run: string, end: RunEnd): CommandError {
  return new CommandError(end.exit, `run ${run} ${end.reason}; its child processes were stopped.`, {
    say: end.say,
    command: "mehen run -- <command> [args...]",
  })
}

function hardEnd(endsAt: string | null | undefined): number | null {
  const at = typeof endsAt === "string" ? Date.parse(endsAt) : NaN
  return Number.isFinite(at) ? at : null
}

// Renews the run while the child lives. At its maximum life the child gets
// SIGTERM `stopGraceMs` before the end, with the relay still up, and SIGKILL
// at the end. When authority is lost instead, the relay closes first, then
// SIGTERM, then SIGKILL after a fixed grace.
export function watchRunAuthority(options: {
  api: VaultApi
  run: Pick<RunCreated, "run" | "expiresAt" | "endsAt">
  child: RunChild
  detached: boolean
  stopGraceMs?: number
  closeCredentials(): Promise<void>
  warn(message: string): void
}): { failure: Promise<CommandError>; readonly stopping: boolean; dispose(): void } {
  const { api, run, child } = options
  const stopGraceMs = options.stopGraceMs ?? DEFAULT_STOP_GRACE_MS
  const endsAt = hardEnd(run.endsAt)
  const controller = new AbortController()
  let confirmedExpiry = Date.parse(run.expiresAt)
  let retryDelay = 1000
  let warnedExpiry = false
  let warnedEnd = false
  let watching = true
  let ending: RunEnd | null = null
  let credentialsClosed: Promise<void> | null = null
  let killAt = Infinity
  let killed = false
  let childExited = false
  const exitedPids = new Set<number>()
  let renewTimer: ReturnType<typeof setTimeout> | undefined
  let warningTimer: ReturnType<typeof setTimeout> | undefined
  let expiryTimer: ReturnType<typeof setTimeout> | undefined
  let endTimer: ReturnType<typeof setTimeout> | undefined
  let killTimer: ReturnType<typeof setTimeout> | undefined
  let fail: (error: CommandError) => void = () => {}
  const failure = new Promise<CommandError>((resolve) => { fail = resolve })

  function stopWatching(): void {
    watching = false
    clearTimeout(renewTimer)
    clearTimeout(warningTimer)
    clearTimeout(expiryTimer)
    clearTimeout(endTimer)
    controller.abort()
  }

  function dispose(): void {
    stopWatching()
    clearTimeout(killTimer)
  }

  async function signalTree(signal: NodeJS.Signals): Promise<void> {
    if (childExited) return
    // If ps fails, only the live child itself is safe to address.
    const parents = await readProcessParents().catch(() => new Map([[child.pid, 0]]))
    if (childExited) return
    for (const pid of processTree(child.pid, parents)) {
      if (pid <= 0 || pid === process.pid || exitedPids.has(pid)) continue
      if (!signalProcess(pid, signal)) exitedPids.add(pid)
    }
  }

  function signalTerm(): void {
    if (options.detached) signalProcessGroup(child.pid, "SIGTERM")
    else void signalTree("SIGTERM")
  }

  // Started once, so a slow close never postpones a deadline.
  function closeCredentials(): Promise<void> {
    credentialsClosed ??= options.closeCredentials().catch(() => {})
    return credentialsClosed
  }

  function kill(): void {
    if (killed || ending === null) return
    killed = true
    const end = ending
    dispose()
    const killedTree = options.detached
      ? Promise.resolve(signalProcessGroup(child.pid, "SIGKILL"))
      : signalTree("SIGKILL")
    void Promise.all([killedTree, closeCredentials()]).then(() => { fail(runEndError(run.run, end)) })
  }

  // Only ever brings the kill closer.
  function scheduleKill(at: number): void {
    if (killed || at >= killAt) return
    killAt = at
    clearTimeout(killTimer)
    // Reserve time for the bounded ps snapshot before the terminal kill.
    killTimer = setTimeout(kill, Math.max(0, at - Date.now() - (options.detached ? 0 : PS_TIMEOUT_MS)))
  }

  // Authority is lost: the relay is no use now, so it closes before any signal.
  // During a maximum-life stop the child already has its SIGTERM.
  function stop(end: RunEnd): void {
    if (!watching || killed) return
    const draining = ending !== null
    ending = end
    stopWatching()
    void closeCredentials()
    scheduleKill(Date.now() + KILL_GRACE_MS)
    if (!draining) signalTerm()
  }

  // Maximum life: authority still holds, so the relay stays up while the
  // child stops, until it exits or the run ends.
  function drain(): void {
    if (!watching || ending !== null || endsAt === null) return
    ending = MAX_LIFE_END
    clearTimeout(warningTimer)
    clearTimeout(endTimer)
    scheduleKill(endsAt)
    signalTerm()
  }

  // The confirmed expiry has passed. At the run's hard end that is its
  // maximum life, which only the kill completes.
  function lapse(): void {
    if (endsAt !== null && confirmedExpiry >= endsAt) {
      drain()
      kill()
    } else stop(EXPIRED_END)
  }

  // A renewal at or after the hard end cannot extend anything.
  function scheduleRenewal(delay: number): void {
    if (endsAt === null || Date.now() + delay < endsAt) renewTimer = setTimeout(() => { void renew() }, delay)
  }

  void child.exited.then(() => {
    childExited = true
    // Kill survivors immediately while the detached group is still ours,
    // never from a delayed timer after its leader has gone.
    if (ending !== null) kill()
    else dispose()
  })

  function armDeadline(): void {
    clearTimeout(warningTimer)
    clearTimeout(expiryTimer)
    clearTimeout(endTimer)
    const now = Date.now()
    const remaining = confirmedExpiry - now
    if (!Number.isFinite(remaining) || remaining <= 0) {
      lapse()
      return
    }
    const end = endsAt ?? Infinity
    if (confirmedExpiry < end) expiryTimer = setTimeout(() => stop(EXPIRED_END), remaining)
    if (ending !== null) return
    const drainAt = end - stopGraceMs
    if (drainAt < confirmedExpiry) {
      endTimer = setTimeout(drain, Math.max(0, drainAt - now))
      if (!warnedEnd) warningTimer = setTimeout(() => {
        warnedEnd = true
        const seconds = Math.max(0, Math.round((drainAt - Date.now()) / 1000))
        options.warn(`run ${run.run} reaches its maximum life at ${new Date(end).toISOString()} and renewal cannot extend it; its child processes will be asked to stop in ${seconds} second${seconds === 1 ? "" : "s"}.`)
      }, Math.max(0, drainAt - WARNING_MS - now))
    } else if (!warnedExpiry) warningTimer = setTimeout(() => {
      warnedExpiry = true
      options.warn(`run ${run.run} has at most 60 seconds of confirmed authority left; if renewal fails, its child processes will be stopped.`)
    }, Math.max(0, remaining - WARNING_MS))
  }

  async function renew(): Promise<void> {
    if (!watching) return
    try {
      const renewed = await api.request<Pick<RunCreated, "run" | "expiresAt">>("POST", `/v1/runs/${run.run}/renew`, {}, { signal: controller.signal })
      if (!watching) return
      if (Date.now() >= confirmedExpiry) {
        lapse()
        return
      }
      const expiry = Date.parse(renewed.expiresAt)
      if (renewed.run !== run.run || !Number.isFinite(expiry) || expiry <= Date.now()) throw new Error("Invalid renewal")
      confirmedExpiry = expiry
      retryDelay = 1000
      armDeadline()
      scheduleRenewal(RENEW_INTERVAL_MS)
    } catch (error) {
      if (!watching) return
      const refusal = terminalRefusal(error)
      if (refusal !== null) {
        stop(refusalEnd(refusal))
        return
      }
      if (Date.now() >= confirmedExpiry) lapse()
      else {
        scheduleRenewal(Math.min(retryDelay, confirmedExpiry - Date.now()))
        retryDelay = Math.min(retryDelay * 2, 30_000)
      }
    }
  }

  armDeadline()
  if (watching) scheduleRenewal(RENEW_INTERVAL_MS)
  return { failure, get stopping() { return ending !== null }, dispose }
}
