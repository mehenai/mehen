// The command table and dispatch. Every command's failure goes through one
// renderer, so the error shape and exit codes are the same everywhere.

import { EXIT } from "@mehen/protocol/api"
import { parseArgs } from "./args.ts"
import type { Command } from "./command.ts"
import { adoptCommand } from "./commands/adopt.ts"
import { backupCommand } from "./commands/backup.ts"
import { RECIPIENTS_ENV } from "./backup/snapshot.ts"
import { checkCommand } from "./commands/check.ts"
import { freezeCommand, revokeCommand, statusCommand, whoamiCommand } from "./commands/device.ts"
import { doctorCommand } from "./commands/doctor.ts"
import { enrolCommand } from "./commands/enrol.ts"
import { fetchCommand } from "./commands/fetch.ts"
import { fillCommand } from "./commands/fill.ts"
import { MCP_HELP, MCP_SUMMARY, MCP_USAGE, guideCommand, versionCommand } from "./commands/info.ts"
import { connectCommand, requestCommand, waitCommand } from "./commands/intake.ts"
import { lsCommand, showCommand } from "./commands/items.ts"
import { mandateCommand } from "./commands/mandate.ts"
import { pendingCommand } from "./commands/pending.ts"
import { planCommand } from "./commands/plan.ts"
import { policyCommand } from "./commands/policy.ts"
import { pushCommand } from "./commands/push.ts"
import { serveCommand } from "./commands/serve.ts"
import { templatesCommand } from "./commands/templates.ts"
import { workloadCommand } from "./commands/workload.ts"
import { type Env } from "./config.ts"
import { knownVault } from "./slots.ts"
import { resolveHome } from "./home.ts"
import { runLogPath } from "./run/run-log.ts"
import { CliError, exitCodeFor, toCliError, usageError } from "./errors.ts"
import { serveMcp } from "./mcp.ts"
import { acceptResume, readResumeLine } from "./mcp/handover.ts"
import { enterRoot, migrationSummary } from "./migration.ts"
import { printBlock, printJson, printLine, reportError } from "./output.ts"
import { openSession } from "./session.ts"
import { flushCliAdvice, setCliAdviceSink } from "./http-client.ts"
import { installation, recordVaultAdvice, selfExecutable } from "./install-state.ts"
import { healInForeground, preDispatchHeal, scheduleBackgroundUpdate, updateCommand } from "./update.ts"
import { setupCommand } from "./setup/index.ts"
import { upCommand } from "./up/index.ts"
import { guardCommand, hookCommand } from "./hook/index.ts"
import { WORKSPACE_SUMMARY, workspaceCommand } from "./commands/workspace.ts"
import { VERSION } from "./version.ts"
import { shellWord } from "./shell-word.ts"

export const COMMANDS: Record<string, Command> = {
  up: upCommand,
  setup: setupCommand,
  update: updateCommand,
  enrol: enrolCommand,
  status: statusCommand,
  whoami: whoamiCommand,
  doctor: doctorCommand,
  ls: lsCommand,
  show: showCommand,
  templates: templatesCommand,
  check: checkCommand,
  request: requestCommand,
  connect: connectCommand,
  wait: waitCommand,
  pending: pendingCommand,
  policy: policyCommand,
  mandate: mandateCommand,
  fetch: fetchCommand,
  plan: planCommand,
  fill: fillCommand,
  push: pushCommand,
  adopt: adoptCommand,
  workload: workloadCommand,
  backup: backupCommand,
  serve: serveCommand,
  hook: hookCommand,
  guard: guardCommand,
  revoke: revokeCommand,
  freeze: freezeCommand,
  guide: guideCommand,
  version: versionCommand,
}

// mehen run, mehen env and mehen init (src/run) report their own failures and take
// their output streams as dependencies. Loaded on use: the local relay's
// X.509 code is only needed by them. Exported for the docs site's command
// reference, which lists their summaries as mehen --help does.
type RunModule = typeof import("./run/index.ts")
type LaneCommand = RunModule["runCommand"]
type LaneHelp = RunModule["runHelp"]
// Throws the command's usage error, if any, from the arguments alone.
type LaneParse = (argv: string[]) => unknown

export const LANE_COMMANDS: Record<string, { summary: string; load(module: RunModule): LaneCommand; help(module: RunModule): LaneHelp; parse(module: RunModule): LaneParse }> = {
  run: { summary: "run a command with the project's variables, or with --item a credential and no project (mehen run [--env <env>] [--stop-grace <seconds>] [--service] [--stream-writes] [--item <slug>[=<VAR>]] -- <command>)", load: (m) => m.runCommand, help: (m) => m.runHelp, parse: (m) => m.parseRunArgs },
  env: { summary: "list, check or set the project's variables (mehen env ls|check|set)", load: (m) => m.envCommand, help: (m) => m.envHelp, parse: (m) => m.parseEnvArgs },
  init: { summary: "create the project, or bind this checkout to the project its remote already is, and write mehen.toml", load: (m) => m.initCommand, help: (m) => m.initHelp, parse: (m) => m.parseInitArgs },
}

// Every command mehen --help lists, in its order; mehen --json gives the same list.
function helpCommands(): { name: string; summary: string }[] {
  return [
    ...Object.entries(COMMANDS).map(([name, c]) => ({ name, summary: c.summary })),
    ...Object.entries(LANE_COMMANDS).map(([name, c]) => ({ name, summary: c.summary })),
    { name: "workspace", summary: WORKSPACE_SUMMARY },
    { name: "mcp", summary: MCP_SUMMARY },
  ]
}

function helpJson(): { version: string; commands: { name: string; summary: string }[]; next: { say: string } } {
  return { version: VERSION, commands: helpCommands(), next: { say: "Run mehen <command> --help for a command's flags." } }
}

function helpText(): string {
  const commands = helpCommands()
  const width = Math.max(...commands.map((c) => c.name.length))
  const lines = [
    `mehen ${VERSION}, the Mehen command line. Access for agents: use credentials without reading them.`,
    "",
    "usage: mehen <command> [options] [--json]",
    "",
    ...commands.map(({ name, summary }) => `  ${name.padEnd(width)}  ${summary}`),
    "",
    "Start with `mehen guide`. `mehen <command> --help` (or `mehen help <command>`) shows a command's options and examples.",
    "When something fails and the error does not say why, run `mehen doctor`.",
  ]
  return lines.join("\n")
}

export { shellWord } from "./shell-word.ts"

export function commandHelp(command: Command): string {
  const lines = [`usage: ${command.spec.usage}`, `  ${command.summary}`, "", "examples:", ...command.examples.map((args) => `  mehen ${args.map(shellWord).join(" ")}`)]
  if (command.notes?.length) lines.push("", ...command.notes.map((note) => `  ${note}`))
  lines.push("", "  --json prints one JSON object per line on stdout, errors included. More: mehen guide.")
  return lines.join("\n")
}

// --json, --no-qr and --workspace <x> may come before the command
// (mehen --json status, mehen --workspace acme status).
const LEADING_GLOBAL_FLAGS = new Set(["--json", "--no-qr"])

function splitLeading(argv: string[]): { globals: string[]; rest: string[] } {
  const globals: string[] = []
  let i = 0
  for (; i < argv.length; i++) {
    const arg = argv[i] as string
    if (LEADING_GLOBAL_FLAGS.has(arg)) globals.push(arg)
    else if (arg.startsWith("--workspace=")) globals.push(arg)
    else if (arg === "--workspace" && argv[i + 1] !== undefined) globals.push(arg, argv[++i] as string)
    else break
  }
  return { globals, rest: argv.slice(i) }
}

// The --workspace selector, wherever it sits on the line, as the one value
// MEHEN_WORKSPACE carries for the command: a flag that disagrees with the
// environment is a mismatch, never a silent override.
export function workspaceEnv(argv: string[], env: Env): Env {
  let flag: string | null = null
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string
    if (arg === "--") break
    if (arg === "--workspace") flag = argv[i + 1] ?? null
    else if (arg.startsWith("--workspace=")) flag = arg.slice("--workspace=".length)
  }
  if (flag === null) return env
  if (flag === "") throw usageError("--workspace needs a workspace slug or id.")
  if (env.MEHEN_WORKSPACE && env.MEHEN_WORKSPACE !== flag) {
    throw new CliError("workspace_mismatch", `--workspace ${flag} disagrees with MEHEN_WORKSPACE=${env.MEHEN_WORKSPACE}.`, { say: "Give one selection: drop the flag or unset MEHEN_WORKSPACE." })
  }
  return { ...env, MEHEN_WORKSPACE: flag }
}

// The line without its --workspace selector, for commands with their own
// parser (mehen run, env, init) once the selector is in the environment.
export function withoutWorkspaceFlag(argv: string[]): string[] {
  const out: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string
    if (arg === "--") return [...out, ...argv.slice(i)]
    if (arg === "--workspace") {
      i++
      continue
    }
    if (arg.startsWith("--workspace=")) continue
    out.push(arg)
  }
  return out
}

// Commands that never migrate, discover slots or resolve the ceiling:
// they read no slot. doctor reads the root and the
// journal without migrating, so the diagnostic it advertises always runs.
// status and whoami only observe: they refuse a root that is not
// migrated yet rather than migrate it. backup mostly runs offline on a
// machine that may hold no enrolment at all; its export and status only
// observe, as status does.
const EXEMPT = new Set(["update", "version", "--version", "help", "--help", "-h", "guide", "doctor", "status", "whoami", "backup", "hook", "guard", "serve"])

function migrates(name: string, rest: string[], env: Env): boolean {
  if (env.MEHEN_UPDATE_CHILD === "1" || EXEMPT.has(name)) return false
  if (!Object.hasOwn(COMMANDS, name) && !Object.hasOwn(LANE_COMMANDS, name) && name !== "workspace" && name !== "mcp") return false
  if (rest.includes("--help") || rest.includes("-h")) return false
  if (name === "setup" && rest.includes("--print")) return false
  if (name === "mcp" && rest.includes("--accept-resume")) return false
  return true
}

// Commands that never talk to the vault, so a known-outdated CLI runs them
// as it is. Of backup, export and status do, and snapshot
// does when it asks for your backup keys: no --recipient and no
// MEHEN_BACKUP_RECIPIENTS.
const LOCAL_ONLY = new Set(["version", "--version", "help", "--help", "-h", "guide", "setup", "update", "templates", "mcp", "hook", "guard", "serve", "up"])
const BACKUP_VAULT_ACTIONS = new Set(["export", "status"])

function backupTalksToVault(afterName: string[], env: Env): boolean {
  const action = afterName.find((arg) => !arg.startsWith("-")) ?? ""
  if (BACKUP_VAULT_ACTIONS.has(action)) return true
  if (action !== "snapshot") return false
  const named = afterName.some((arg) => arg === "--recipient" || arg.startsWith("--recipient="))
  return !named && (env[RECIPIENTS_ENV] ?? "").split(",").every((r) => r.trim() === "")
}

function talksToVault(name: string, afterName: string[], env: Env): boolean {
  if (LOCAL_ONLY.has(name) || afterName.includes("--help") || afterName.includes("-h")) return false
  if (name === "workspace") {
    const sub = afterName.find((arg) => !arg.startsWith("-"))
    return sub !== undefined && sub !== "list" && sub !== "show"
  }
  if (name === "backup") return backupTalksToVault(afterName, env)
  return Object.hasOwn(COMMANDS, name) || Object.hasOwn(LANE_COMMANDS, name)
}

// The entry sequence and its one `migrated` line on stderr.
async function enterRootFor(env: Env, json: boolean): Promise<void> {
  const { root, migrated } = await enterRoot(env)
  if (!migrated) return
  const summary = migrationSummary(migrated)
  if (json) {
    process.stderr.write(`${JSON.stringify({ migrated: { root, ...summary } })}\n`)
    return
  }
  const left = summary.left.length ? `; ${summary.left.length} item${summary.left.length === 1 ? "" : "s"} left in place (mehen doctor names them)` : ""
  process.stderr.write(`mehen: migrated ${root} to the workspaces layout: ${summary.slots} workspace${summary.slots === 1 ? "" : "s"}, ${summary.pending} pending enrolment${summary.pending === 1 ? "" : "s"}${left}.\n`)
}

export async function main(argv: string[], parentEnv: Env): Promise<number> {
  const { globals, rest: afterGlobals } = splitLeading(argv)
  const [name, ...afterName] = afterGlobals
  const rest = [...globals, ...afterName]
  const json = rest.includes("--json")
  const noQr = rest.includes("--no-qr")
  let env = parentEnv
  let outdated = false
  // Every /v1 response's advice is recorded next to the binary this process
  // runs from, under the installation lock with zero wait.
  const self = selfExecutable(parentEnv)
  setCliAdviceSink(self === null ? null : (origin, advice) => recordVaultAdvice(installation(self), origin, advice))
  try {
    env = workspaceEnv(rest, parentEnv)
    if (name === undefined || name === "help" || name === "--help" || name === "-h") {
      const topic = name === "help" ? rest.find((arg) => !arg.startsWith("-")) : undefined
      if (topic !== undefined && topic !== "help") return await main([topic, "--help"], env)
      if (json) printJson(helpJson())
      else if (name === undefined) process.stderr.write(`${helpText()}\n`)
      else printBlock(helpText())
      return name === undefined ? EXIT.usage : EXIT.ok
    }
    if (name === "--version") return await versionCommand.run({ args: parseArgs([], versionCommand.spec), json: false, env })
    // The handover's acceptance check, run by a server on a
    // private copy of its verified replacement: it only reads, so it comes
    // before any heal or migration.
    if (name === "mcp" && afterName.length === 1 && afterName[0] === "--accept-resume") return await acceptResume(env, process.cwd(), await readResumeLine(Bun.stdin.stream()))
    // Known to be below a vault's minimum: heal and re-execute before
    // anything runs, migration included.
    if (talksToVault(name, afterName, env)) await preDispatchHeal(env, argv)
    if (migrates(name, rest, env)) await enterRootFor(env, json)
    if (name === "workspace") return await workspaceCommand(rest, env)
    if (name === "mcp") {
      if (rest.includes("--help") || rest.includes("-h")) {
        printBlock(MCP_HELP)
        return EXIT.ok
      }
      const mcpArgs = parseArgs(rest, { usage: MCP_USAGE, flags: { toolsets: { type: "string" } }, positionals: { min: 0, max: 0 } })
      if (mcpArgs.bool("json") || mcpArgs.bool("no-qr")) throw usageError(`Usage: ${MCP_USAGE} (it takes no other options)`, "mehen mcp --help")
      return await serveMcp(env, { args: rest, toolsets: mcpArgs.string("toolsets") })
    }
    const lane = LANE_COMMANDS[name]
    if (lane) {
      const module = await import("./run/index.ts")
      const laneArgs = withoutWorkspaceFlag(rest)
      // Help needs no enrolment, so it is answered before opening the vault.
      const usage = lane.help(module)(laneArgs)
      if (usage !== null) {
        printLine(`usage: ${usage}`)
        printLine(`  ${lane.summary}`)
        return EXIT.ok
      }
      // So are usage errors: a bad line is refused before any vault or slot is read.
      lane.parse(module)(laneArgs)
      const { api, config, vaultUrl } = await openSession(env)
      const command = lane.load(module)
      return await command(laneArgs, { api, config: { ...config, vault: vaultUrl }, stdout: process.stdout, stderr: process.stderr, env, runLog: runLogPath(resolveHome(env).root) })
    }
    const command = COMMANDS[name]
    if (!command) throw usageError(`Unknown command ${JSON.stringify(name)}.`)
    const args = parseArgs(rest, command.spec)
    if (args.bool("help")) {
      printBlock(commandHelp(command))
      return EXIT.ok
    }
    return await command.run({ args, json: args.bool("json"), env })
  } catch (error) {
    let failure = toCliError(error)
    // Refused mid-command: heal, then render the refusal once. The command
    // is never re-executed, since an earlier request or a local write may
    // already have happened.
    if (failure.code === "cli_outdated") {
      outdated = true
      await flushCliAdvice()
      const healed = await healInForeground(env)
      if (healed) failure = new CliError("cli_outdated", failure.message, { command: ["mehen", ...argv].map(shellWord).join(" "), say: `mehen updated itself from ${healed.from} to ${healed.to}; run the command again.` }, failure.extras)
    }
    // The renderer checks every link in the error against this vault URL.
    // `setup --print` reads nothing but the managed-host marker, refusals
    // included: its local errors carry no vault link, so
    // they are rendered without selecting a slot.
    const printOnly = name === "setup" && rest.includes("--print")
    reportError(failure, json, { env, noQr, vaultUrl: printOnly ? null : await knownVault(env) })
    return exitCodeFor(failure.code)
  } finally {
    await flushCliAdvice()
    // Previews and every help form do no installation work at all:
    // `setup --print`, `help`, `help <topic>`, `--help`, `-h`.
    const helpOrPreview = name === "help" || rest.includes("--help") || rest.includes("-h") || (name === "setup" && rest.includes("--print"))
    if (!helpOrPreview) await scheduleBackgroundUpdate(env, name, { outdated }).catch(() => "skipped")
  }
}
