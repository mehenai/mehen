// The local vault as a service that starts with the machine and comes back
// after a crash: a LaunchAgent on a Mac, a systemd user unit on Linux, or,
// where neither is available (a container, a dev run from source), a
// detached process that lives until the machine restarts.

import { spawn, spawnSync } from "node:child_process"
import { existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"

export const LAUNCHD_LABEL = "dev.mehen.vault"
export const SYSTEMD_UNIT = "mehen-vault.service"
export const PID_FILE = "serve.pid"

export type ServiceKind = "launchd" | "systemd" | "process"
// `environment`: what the service runs with beyond its own defaults, so a
// vault started at login uses the home and update choice `mehen up` ran with.
export type ServicePlan = { kind: ServiceKind; command: string[]; dataDir: string; home: string; logFile: string; environment?: Readonly<Record<string, string>> }

// The variables `mehen up` hands on to the service it installs, when set.
export const SERVICE_ENVIRONMENT = ["MEHEN_HOME", "MEHEN_NO_AUTO_UPDATE"] as const

export function serviceEnvironment(env: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const name of SERVICE_ENVIRONMENT) {
    const value = env[name]
    if (value === undefined || value === "") continue
    // A line break or control character would end the unit's line or the
    // plist's string somewhere else than it reads.
    if (/[\u0000-\u001f\u007f]/.test(value)) throw new ServiceError(`${name} holds a control character, so it cannot be written into the service; set it without one and run \`mehen up\` again.`)
    out[name] = value
  }
  return out
}

export type ServiceResult = { kind: ServiceKind; file: string | null; startsAtLogin: boolean }

function xml(text: string): string {
  return text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;")
}

export function launchdPlist(plan: ServicePlan): string {
  const args = plan.command.map((part) => `    <string>${xml(part)}</string>`).join("\n")
  const pairs = Object.entries(plan.environment ?? {})
  const environment = pairs.length === 0 ? "" : `\n  <key>EnvironmentVariables</key>\n  <dict>\n${pairs.map(([k, v]) => `    <key>${xml(k)}</key>\n    <string>${xml(v)}</string>`).join("\n")}\n  </dict>`
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${args}
  </array>${environment}
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>Umask</key>
  <integer>63</integer>
  <key>StandardOutPath</key>
  <string>${xml(plan.logFile)}</string>
  <key>StandardErrorPath</key>
  <string>${xml(plan.logFile)}</string>
</dict>
</plist>
`
}

// systemd quotes an argument containing spaces or specials in double quotes,
// with backslash and double quote escaped.
function systemdWord(word: string): string {
  if (/^[A-Za-z0-9_./:=@+-]+$/.test(word)) return word
  return `"${word.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("$", "$$$$").replaceAll("%", "%%")}"`
}

// One Environment= assignment, always quoted: systemd reads backslash and
// double quote as escapes inside the quotes and % as a specifier.
function systemdAssignment(name: string, value: string): string {
  return `"${`${name}=${value}`.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("%", "%%")}"`
}

export function systemdUnit(plan: ServicePlan): string {
  return `[Unit]
Description=Mehen vault (local)

[Service]
ExecStart=${plan.command.map(systemdWord).join(" ")}
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus
${Object.entries(plan.environment ?? {}).map(([k, v]) => `Environment=${systemdAssignment(k, v)}\n`).join("")}Restart=always
RestartSec=2
UMask=0077
NoNewPrivileges=yes
LockPersonality=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=default.target
`
}

export function launchdPath(home: string): string {
  return join(home, "Library", "LaunchAgents", `${LAUNCHD_LABEL}.plist`)
}

export function systemdPath(home: string, env: Record<string, string | undefined>): string {
  return join(env.XDG_CONFIG_HOME || join(home, ".config"), "systemd", "user", SYSTEMD_UNIT)
}

// Runs one command for at most `timeoutMs` and waits for it; `code` is null
// when it was ended at its budget or could not start. Tests pass a fake.
export type Runner = (cmd: string[], timeoutMs: number) => { code: number | null; out: string }

export const defaultRunner: Runner = (cmd, timeoutMs) => {
  const result = spawnSync(cmd[0] as string, cmd.slice(1), { encoding: "utf8", timeout: Math.max(1, Math.round(timeoutMs)), killSignal: "SIGKILL" })
  const out = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim()
  return { code: result.error ? null : result.status, out: result.error ? `${out}${out ? " " : ""}(${result.error.message})`.trim() : out }
}

// How long stopping the service may take in all, the stop itself and the
// daemon-reload after it included: launchctl bootout and systemctl disable
// --now can return while the job is still stopping, so its state is asked
// until it settles or this ends.
export const STOP_WAIT_MS = 10_000
const STOP_POLL_MS = 100
// Less than this left is no time to start a command in.
const MIN_COMMAND_MS = 20
// What a command not started for want of time answers.
const NO_TIME = { code: null, out: "no time was left to ask" } as const

export type Waiting = { runner?: Runner; sleep?: (ms: number) => void; now?: () => number; waitMs?: number }

// One wall-clock budget for a stop and the questions after it: a command
// starts only while time is left and is given no more than what is left,
// and once it is spent nothing starts at all (NO_TIME, an unknown answer).
function budget(options: Waiting) {
  const now = options.now ?? Date.now
  const sleep = options.sleep ?? Bun.sleepSync
  const runner = options.runner ?? defaultRunner
  const deadline = now() + (options.waitMs ?? STOP_WAIT_MS)
  const left = () => deadline - now()
  return {
    left,
    hasTime: () => left() >= MIN_COMMAND_MS,
    run: (cmd: string[]): { code: number | null; out: string } => (left() >= MIN_COMMAND_MS ? runner(cmd, left()) : NO_TIME),
    // Never past the deadline, and at least 1 ms before it, so a wait
    // always moves on to an end.
    pause: () => {
      const rest = left()
      if (rest > 0) sleep(Math.max(1, Math.min(STOP_POLL_MS, rest)))
    },
  }
}

// What a state question established: the job is gone (or stopped), it is
// still there, or the question got no answer that says either.
type JobState = { state: "gone" | "there" | "unknown"; detail: string }

// launchctl print: found, or "Could not find service" (113) when it is not
// loaded; anything else is no answer.
function launchdState(answer: { code: number | null; out: string }): JobState {
  if (answer.code === 0) return { state: "there", detail: "loaded" }
  if (answer.code === 113 || /could not find (specified )?service|no such process/i.test(answer.out)) return { state: "gone", detail: "not loaded" }
  return { state: "unknown", detail: answer.out || `exit ${answer.code ?? "after its time ran out"}` }
}

// systemctl show -p LoadState -p ActiveState. ActiveState decides first:
// active and every transition (activating, deactivating, reloading,
// refreshing) is still there whatever LoadState says, since a unit whose
// file was removed and reloaded can run on as not-found. Only inactive or
// failed is gone, and `loaded` says whether systemd still knows the unit.
// A failed query (the user bus unreachable) or an unknown word is no
// answer.
const SYSTEMD_RUNNING = ["active", "activating", "deactivating", "reloading", "refreshing"]
export function systemdState(answer: { code: number | null; out: string }): JobState & { loaded: boolean } {
  const field = (name: string) => new RegExp(`^${name}=(.*)$`, "m").exec(answer.out)?.[1]?.trim()
  const load = field("LoadState")
  const active = field("ActiveState")
  if (answer.code !== 0 || load === undefined || active === undefined) return { state: "unknown", detail: answer.out || `exit ${answer.code ?? "after its time ran out"}`, loaded: true }
  if (SYSTEMD_RUNNING.includes(active)) return { state: "there", detail: `${active}${load === "loaded" ? "" : `, ${load}`}`, loaded: true }
  if (active === "inactive" || active === "failed") return { state: "gone", detail: load === "not-found" ? "not found" : active, loaded: load !== "not-found" }
  return { state: "unknown", detail: `ActiveState=${active}, LoadState=${load}`, loaded: true }
}

// Asks until the job is gone or the budget is spent; the last answer that
// was asked wins. No question starts once the budget is spent: with no
// time for even one, the answer is NO_TIME, which every reader takes as
// unknown.
function settle<S extends JobState>(ask: () => S, time: ReturnType<typeof budget>): S {
  let last: S | null = null
  while (time.hasTime()) {
    last = ask()
    if (last.state === "gone") break
    time.pause()
  }
  // With no time to ask even once, ask() answers unknown without running.
  return last ?? ask()
}

// Which kind this machine supports, unless MEHEN_SERVICE names one.
export function serviceKind(env: Record<string, string | undefined>, platform: NodeJS.Platform = process.platform, installed: boolean): ServiceKind {
  const chosen = env.MEHEN_SERVICE
  if (chosen === "launchd" || chosen === "systemd" || chosen === "process") return chosen
  if (!installed) return "process"
  if (platform === "darwin") return "launchd"
  if (platform === "linux" && defaultRunner(["systemctl", "--user", "show-environment"], 5_000).code === 0) return "systemd"
  return "process"
}

function writePrivateFile(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  writeFileSync(path, text, { mode: 0o600 })
}

function startProcess(plan: ServicePlan): void {
  mkdirSync(dirname(plan.logFile), { recursive: true, mode: 0o700 })
  const log = openSync(plan.logFile, "a", 0o600)
  const child = spawn(plan.command[0] as string, plan.command.slice(1), { detached: true, stdio: ["ignore", log, log], env: { ...process.env, ...plan.environment } })
  child.unref()
  writeFileSync(join(plan.dataDir, PID_FILE), String(child.pid), { mode: 0o600 })
}

// The pid in the data directory, if that process is still this vault's
// `mehen serve`: a pid left from before a restart may belong to anything
// by now, so its command line must be serve with this data directory as its
// last argument, exactly (startProcess puts it last), never a prefix of it.
export function servePid(dataDir: string): number | null {
  const found = serveState(dataDir, (cmd) => defaultRunner(cmd, 5_000))
  return found.state === "there" ? found.pid : null
}

// Whether the pid in the data directory is still this vault's serve: gone
// (no pid file, or ps says no such process, or another program has the
// pid), there, or unknown when ps did not answer.
function serveState(dataDir: string, ask: (cmd: string[]) => { code: number | null; out: string }): { state: "gone" | "there" | "unknown"; pid: number; detail: string } {
  const path = join(dataDir, PID_FILE)
  if (!existsSync(path)) return { state: "gone", pid: 0, detail: "no pid file" }
  const pid = Number(readFileSync(path, "utf8").trim())
  if (!Number.isInteger(pid) || pid <= 1) return { state: "gone", pid: 0, detail: "no pid in the pid file" }
  const args = ask(["ps", "-o", "args=", "-p", String(pid)])
  // ps -p with a pid that is not running prints nothing and exits 1.
  if (args.code === 1 && args.out === "") return { state: "gone", pid, detail: "not running" }
  if (args.code !== 0) return { state: "unknown", pid, detail: args.out || `ps exit ${args.code ?? "after its time ran out"}` }
  return isServeOf(args.out, dataDir) ? { state: "there", pid, detail: "running" } : { state: "gone", pid, detail: "another program" }
}

export function isServeOf(commandLine: string, dataDir: string): boolean {
  return / serve /.test(` ${commandLine} `) && commandLine.endsWith(` --data ${dataDir}`)
}

export class ServiceError extends Error {}

// Installs and starts the service, or starts the one already installed.
// The caller waits for the vault to answer.
export function installService(plan: ServicePlan, env: Record<string, string | undefined>, options: Waiting = {}): ServiceResult {
  const runner = options.runner ?? defaultRunner
  const run = (cmd: string[]) => runner(cmd, 30_000)
  if (plan.kind === "launchd") {
    const file = launchdPath(plan.home)
    writePrivateFile(file, launchdPlist(plan))
    const domain = `gui/${process.getuid?.() ?? 0}`
    const target = `${domain}/${LAUNCHD_LABEL}`
    // A job still stopping from the bootout refuses the bootstrap, which
    // then says why.
    const time = budget(options)
    time.run(["launchctl", "bootout", target])
    settle(() => launchdState(time.run(["launchctl", "print", target])), time)
    const loaded = run(["launchctl", "bootstrap", domain, file])
    if (loaded.code !== 0) throw new ServiceError(`launchctl could not load ${file}: ${loaded.out}`)
    return { kind: "launchd", file, startsAtLogin: true }
  }
  if (plan.kind === "systemd") {
    const file = systemdPath(plan.home, env)
    writePrivateFile(file, systemdUnit(plan))
    for (const cmd of [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", SYSTEMD_UNIT], ["systemctl", "--user", "restart", SYSTEMD_UNIT]]) {
      const result = run(cmd)
      if (result.code !== 0) throw new ServiceError(`${cmd.join(" ")} failed: ${result.out}`)
    }
    return { kind: "systemd", file, startsAtLogin: true }
  }
  if (servePid(plan.dataDir) === null) startProcess(plan)
  return { kind: "process", file: null, startsAtLogin: false }
}

// Stops the service and removes what installService wrote, and says what it
// could not do: a service still loaded or a vault still running is reported,
// never taken for gone. The data stays.
// Only a stop whose result is confirmed removes anything: the job not
// found, or the unit stopped after a stop that worked. A stop that failed,
// a job still there when the time is up, or a state question nobody
// answered keeps the service file (and, in the caller, local-vault.json)
// and says what to do.
export function removeService(kind: ServiceKind, dataDir: string, home: string, env: Record<string, string | undefined>, options: Waiting = {}): string[] {
  const time = budget(options)
  const seconds = `${Math.round((options.waitMs ?? STOP_WAIT_MS) / 1000)} seconds`
  if (kind === "launchd") {
    const target = `gui/${process.getuid?.() ?? 0}/${LAUNCHD_LABEL}`
    const stop = time.run(["launchctl", "bootout", target])
    const stopFailed = stop.code !== 0 && launchdState(stop).state !== "gone"
    const now = settle(() => launchdState(time.run(["launchctl", "print", target])), time)
    if (now.state === "gone") {
      rmSync(launchdPath(home), { force: true })
      return []
    }
    if (stopFailed) return [`launchctl bootout ${target} failed (${stop.out || `exit ${stop.code ?? "after its time ran out"}`}); run it yourself, then check \`launchctl print ${target}\``]
    if (now.state === "there") return [`launchctl still has ${LAUNCHD_LABEL} loaded after ${seconds}; run \`launchctl bootout ${target}\``]
    return [`could not confirm that launchd unloaded ${LAUNCHD_LABEL}: launchctl print said ${now.detail}; check \`launchctl print ${target}\``]
  }
  if (kind === "systemd") {
    const stop = time.run(["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT])
    const now = settle(() => systemdState(time.run(["systemctl", "--user", "show", "-p", "LoadState", "-p", "ActiveState", SYSTEMD_UNIT])), time)
    // A unit systemd does not know is gone whatever disable said; a known
    // one is gone only once a disable that worked has stopped it.
    if (now.state === "gone" && (!now.loaded || stop.code === 0)) {
      rmSync(systemdPath(home, env), { force: true })
      // From what is left of the same budget. Without it the stopped,
      // disabled unit stays listed until systemd next reloads; nothing runs.
      time.run(["systemctl", "--user", "daemon-reload"])
      return []
    }
    if (stop.code !== 0) return [`systemctl --user disable --now ${SYSTEMD_UNIT} failed (${stop.out || `exit ${stop.code ?? "after its time ran out"}`}); run it yourself, then check \`systemctl --user status ${SYSTEMD_UNIT}\``]
    if (now.state === "there") return [`${SYSTEMD_UNIT} is still running (${now.detail}) after ${seconds}; run \`systemctl --user disable --now ${SYSTEMD_UNIT}\``]
    return [`could not confirm that ${SYSTEMD_UNIT} stopped: systemctl said ${now.detail}; check \`systemctl --user status ${SYSTEMD_UNIT}\``]
  }
  const ask = (cmd: string[]) => time.run(cmd)
  const first = serveState(dataDir, ask)
  if (first.state === "there") process.kill(first.pid, "SIGTERM")
  const now = first.state === "there" ? settle(() => serveState(dataDir, ask), time) : first
  if (now.state === "there") return [`the vault (pid ${now.pid}) did not stop within ${seconds}; end it yourself`]
  if (now.state === "unknown") return [`could not confirm that the vault (pid ${now.pid}) stopped: ${now.detail}; check \`ps -p ${now.pid}\``]
  rmSync(join(dataDir, PID_FILE), { force: true })
  return []
}
