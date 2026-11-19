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
export type ServicePlan = { kind: ServiceKind; command: string[]; dataDir: string; home: string; logFile: string }
export type ServiceResult = { kind: ServiceKind; file: string | null; startsAtLogin: boolean }

function xml(text: string): string {
  return text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;")
}

export function launchdPlist(plan: ServicePlan): string {
  const args = plan.command.map((part) => `    <string>${xml(part)}</string>`).join("\n")
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${args}
  </array>
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

export function systemdUnit(plan: ServicePlan): string {
  return `[Unit]
Description=Mehen vault (local)
After=network-online.target

[Service]
ExecStart=${plan.command.map(systemdWord).join(" ")}
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus
Restart=always
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

function run(cmd: string[]): { code: number; out: string } {
  const result = spawnSync(cmd[0] as string, cmd.slice(1), { encoding: "utf8" })
  return { code: result.status ?? 1, out: `${result.stdout ?? ""}${result.stderr ?? ""}`.trim() }
}

// Which kind this machine supports, unless MEHEN_SERVICE names one.
export function serviceKind(env: Record<string, string | undefined>, platform: NodeJS.Platform = process.platform, installed: boolean): ServiceKind {
  const chosen = env.MEHEN_SERVICE
  if (chosen === "launchd" || chosen === "systemd" || chosen === "process") return chosen
  if (!installed) return "process"
  if (platform === "darwin") return "launchd"
  if (platform === "linux" && run(["systemctl", "--user", "show-environment"]).code === 0) return "systemd"
  return "process"
}

function writePrivateFile(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  writeFileSync(path, text, { mode: 0o600 })
}

function startProcess(plan: ServicePlan): void {
  mkdirSync(dirname(plan.logFile), { recursive: true, mode: 0o700 })
  const log = openSync(plan.logFile, "a", 0o600)
  const child = spawn(plan.command[0] as string, plan.command.slice(1), { detached: true, stdio: ["ignore", log, log] })
  child.unref()
  writeFileSync(join(plan.dataDir, PID_FILE), String(child.pid), { mode: 0o600 })
}

// The pid in the data directory, if that process is still this vault's
// `mehen serve`: a pid left from before a restart may belong to anything
// by now, so its command line must be serve with this data directory as its
// last argument, exactly (startProcess puts it last), never a prefix of it.
export function servePid(dataDir: string): number | null {
  const path = join(dataDir, PID_FILE)
  if (!existsSync(path)) return null
  const pid = Number(readFileSync(path, "utf8").trim())
  if (!Number.isInteger(pid) || pid <= 1) return null
  const args = run(["ps", "-o", "args=", "-p", String(pid)])
  if (args.code !== 0) return null
  return isServeOf(args.out, dataDir) ? pid : null
}

export function isServeOf(commandLine: string, dataDir: string): boolean {
  return / serve /.test(` ${commandLine} `) && commandLine.endsWith(` --data ${dataDir}`)
}

export class ServiceError extends Error {}

// Installs and starts the service, or starts the one already installed.
// The caller waits for the vault to answer.
export function installService(plan: ServicePlan, env: Record<string, string | undefined>): ServiceResult {
  if (plan.kind === "launchd") {
    const file = launchdPath(plan.home)
    writePrivateFile(file, launchdPlist(plan))
    const domain = `gui/${process.getuid?.() ?? 0}`
    run(["launchctl", "bootout", `${domain}/${LAUNCHD_LABEL}`])
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
export function removeService(kind: ServiceKind, dataDir: string, home: string, env: Record<string, string | undefined>): string[] {
  const problems: string[] = []
  if (kind === "launchd") {
    const target = `gui/${process.getuid?.() ?? 0}/${LAUNCHD_LABEL}`
    run(["launchctl", "bootout", target])
    if (run(["launchctl", "print", target]).code === 0) problems.push(`launchctl still has ${LAUNCHD_LABEL} loaded; run \`launchctl bootout ${target}\``)
    else rmSync(launchdPath(home), { force: true })
    return problems
  }
  if (kind === "systemd") {
    run(["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT])
    if (run(["systemctl", "--user", "is-active", "--quiet", SYSTEMD_UNIT]).code === 0) problems.push(`${SYSTEMD_UNIT} is still running; run \`systemctl --user disable --now ${SYSTEMD_UNIT}\``)
    else {
      rmSync(systemdPath(home, env), { force: true })
      run(["systemctl", "--user", "daemon-reload"])
    }
    return problems
  }
  const pid = servePid(dataDir)
  if (pid !== null) {
    process.kill(pid, "SIGTERM")
    for (let i = 0; i < 50 && servePid(dataDir) === pid; i++) Bun.sleepSync(100)
    if (servePid(dataDir) === pid) problems.push(`the vault (pid ${pid}) did not stop within 5 seconds; end it yourself`)
  }
  if (problems.length === 0) rmSync(join(dataDir, PID_FILE), { force: true })
  return problems
}
