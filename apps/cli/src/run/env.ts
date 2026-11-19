// mehen env ls | check | set: how the project's declared variables resolve for
// an environment. Never prints a value.

import { EXIT, type NextStep, VarName, isSlug, type Project } from "@mehen/protocol"
import { CliError, usageError } from "../errors.ts"
import { CommandError, type Deps, askVault, cwdOf, envOf, mehenLine, nextLines, reportFailure, stylerFor, wantsHelp, warningLine, writeLine } from "./deps.ts"
import { resolveEnv, writeBanner } from "./environment.ts"
import { locateProjectManifest } from "./bound-project.ts"
import { type Located, locateManifest } from "./manifest.ts"

export const ENV_USAGE =
  "mehen env ls [--env <env>] [--json] | mehen env check [--env <env>] [--json] | mehen env set <NAME> --env <env> [--item <slug> [--field <field>]] [--plain <value>]"

const ENV_VALUE_FLAGS = ["--env", "--item", "--field", "--plain"] as const
const ENV_HELP = "mehen env --help"

// The usage when `mehen env` is asked for help, else null.
export function envHelp(argv: string[]): string | null {
  return wantsHelp(argv, ENV_VALUE_FLAGS, false) ? ENV_USAGE : null
}

type Flags = { positional: string[]; values: Map<string, string>; json: boolean }

function parseFlags(argv: string[], known: readonly string[], jsonAllowed = false): Flags {
  const flags: Flags = { positional: [], values: new Map(), json: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? ""
    if (!arg.startsWith("--")) {
      flags.positional.push(arg)
      continue
    }
    if (arg === "--json" && jsonAllowed) {
      flags.json = true
      continue
    }
    const [flag = "", inline] = arg.split(/=(.*)/s)
    if (!known.includes(flag)) throw usageError(`Unknown option ${flag}.`, ENV_HELP)
    const value = inline ?? argv[++i]
    if (value === undefined) throw usageError(`${flag} needs a value.`, ENV_HELP)
    flags.values.set(flag, value)
  }
  return flags
}

// One declared variable, as `mehen env ls --json` and `mehen env check --json`
// print it. `source`: "manifest" is a plain value in mehen.toml, "plain" one in
// the vault, "item" a vault item (null when this machine may not see it).
export type EnvVariable = {
  name: string
  resolved: boolean
  source: "manifest" | "plain" | "item" | "unset"
  override?: true
  item: string | null
  field: string | null
  next: NextStep | null
}
// { project, env, ok, variables }: ok is false when any variable is unset.
export type EnvReport = { project: string; env: string; ok: boolean; variables: EnvVariable[] }

type OverrideMetadata = { environment: string; variable: string; source: { kind: "plain" } | { kind: "item"; item: string; field: string } }
type Resolution = EnvVariable & { how: string }

function unsetNext(name: string, env: string): NextStep {
  return {
    command: `mehen env set ${name} --env ${env} --item <slug>`,
    say: `${name} is unset for env=${env}: point it at a vault item; if the credential is not in the vault yet, ask a human for it with mehen request <kind> --name <slug> --reason "<why ${name} is needed>".`,
  }
}

function resolutions(located: Located, project: Project, env: string, overrides: OverrideMetadata[] = []): Resolution[] {
  if (!project.environments.some((e) => e.name === env)) {
    throw new CommandError(EXIT.usage, `project ${project.slug} has no environment ${env}`, {
      say: `Use one of: ${project.environments.map((e) => e.name).join(", ")}.`,
    })
  }
  return located.manifest.vars.map((v): Resolution => {
    const row = { name: v.name, item: null, field: null, next: null }
    if (v.source === "plain") return { ...row, resolved: true, source: "manifest", how: "plain value in mehen.toml" }
    const personal = overrides.find(row => row.environment === env && row.variable === v.name)
    if (personal?.source.kind === "plain") return { ...row, resolved: true, source: "plain", override: true, how: "override (your plain value)" }
    if (personal?.source.kind === "item") return { ...row, resolved: true, source: "item", override: true, item: personal.source.item, field: personal.source.field, how: `override (your ${personal.source.item})` }
    const set = project.vars.find((pv) => pv.name === v.name && pv.env === env)
    if (set === undefined || set.source === "unset") return { ...row, resolved: false, source: "unset", next: unsetNext(v.name, env), how: "unset in the vault" }
    if (set.source === "plain") return { ...row, resolved: true, source: "plain", how: "plain value in the vault" }
    return { ...row, resolved: true, source: "item", item: set.item, field: set.field, how: `vault item ${set.item ?? "?"}${set.field !== null ? `#${set.field}` : ""}` }
  })
}

type ListArgs = { sub: "ls" | "check"; env: string | undefined; json: boolean }
type SetArgs = { sub: "set"; name: string; env: string; item: string | undefined; field: string | undefined; plain: string | undefined }
export type EnvArgs = ListArgs | SetArgs

// The arguments of mehen env, or a usage error; cli.ts calls it before it
// opens the vault session, so a bad line needs no enrolment to be refused.
export function parseEnvArgs(argv: string[]): EnvArgs {
  const [sub, ...rest] = argv
  if (sub === "ls" || sub === "check") {
    const flags = parseFlags(rest, ["--env"], true)
    if (flags.positional.length > 0) throw usageError(`Unexpected argument ${flags.positional[0]}.`, ENV_HELP)
    return { sub, env: flags.values.get("--env"), json: flags.json }
  }
  if (sub === "set") return parseSetArgs(rest)
  throw usageError(sub === undefined ? "mehen env needs a subcommand: ls, check or set." : `Unknown subcommand ${sub}; use ls, check or set.`, ENV_HELP)
}

function parseSetArgs(argv: string[]): SetArgs {
  const flags = parseFlags(argv, ENV_VALUE_FLAGS)
  const [name, ...extra] = flags.positional
  if (name === undefined || extra.length > 0) throw usageError("mehen env set takes exactly one variable name.", ENV_HELP)
  if (!VarName.safeParse(name).success) throw usageError(`${name} is not a valid variable name.`, ENV_HELP)
  const env = flags.values.get("--env")
  if (env === undefined) throw usageError("mehen env set needs --env: say which environment you are changing.", ENV_HELP)
  const item = flags.values.get("--item")
  const field = flags.values.get("--field")
  const plain = flags.values.get("--plain")
  if (item !== undefined && plain !== undefined) throw usageError("Pass --item or --plain, not both.", ENV_HELP)
  if (field !== undefined && item === undefined) throw usageError("--field only goes with --item.", ENV_HELP)
  if (item !== undefined && !isSlug(item)) throw usageError(`${item} is not an item slug.`, ENV_HELP)
  if (item === undefined && plain === undefined) {
    throw new CliError("usage", `${name} needs a source: --item <slug> for a credential in the vault, or --plain <value> for non-secret config.`, {
      command: `mehen env set ${name} --env ${env} --item <slug>`,
      say: `Point it at a vault item; if the credential is not in the vault yet, ask a human for it first with mehen request <kind> --name <slug> --reason "<why ${name} is needed>".`,
    })
  }
  return { sub: "set", name, env, item, field, plain }
}

async function listOrCheck(args: ListArgs, deps: Deps): Promise<number> {
  const check = args.sub === "check"
  const located = await locateProjectManifest(deps.api, cwdOf(deps))
  const { env } = resolveEnv(args.env, envOf(deps), located.manifest)
  writeBanner(deps.stderr, located, env)
  const project = await deps.api.request<Project>("GET", `/v1/projects/${encodeURIComponent(located.manifest.project)}`)
  // Only workspace project projections carry access. Legacy reads stay identical.
  const overrides = "access" in project
    ? (await deps.api.request<{ overrides: OverrideMetadata[] }>("GET", `/v1/projects/${encodeURIComponent(located.manifest.project)}/overrides`)).overrides
    : []
  // A reply without the list never falls back to the shared sources.
  if (!Array.isArray(overrides)) throw new CommandError(EXIT.error, "the vault's override list could not be read", { say: "Nothing is shown as resolved. Try again; if it keeps failing, report it with this message." })
  const rows = resolutions(located, project, env, overrides)
  const unresolved = rows.filter((r) => !r.resolved)
  if (args.json) {
    const report: EnvReport = { project: located.manifest.project, env, ok: unresolved.length === 0, variables: rows.map(({ how: _how, ...v }) => v) }
    deps.stdout.write(`${JSON.stringify(report)}\n`)
    return check && !report.ok ? EXIT.human : EXIT.ok
  }
  if (!check) {
    const width = Math.max(0, ...rows.map((r) => r.name.length))
    // row.how names the item and field the vault returned.
    for (const row of rows) writeLine(deps.stdout, `${row.name.padEnd(width)}  ${row.how}`)
    if (rows.length === 0) deps.stdout.write("mehen.toml declares no variables\n")
    return EXIT.ok
  }
  if (unresolved.length === 0) {
    deps.stdout.write(`all ${rows.length} declared variables resolve for env=${env}\n`)
    return EXIT.ok
  }
  const s = stylerFor(deps, deps.stderr)
  writeLine(deps.stderr, mehenLine(s, `${unresolved.map((r) => r.name).join(", ")} ${unresolved.length === 1 ? "does" : "do"} not resolve for env=${env}`))
  const next = { say: "point each one at a vault item; if the credential is not in the vault yet, ask a human for it with mehen request." }
  const commands = unresolved.flatMap((row) => (row.next?.command === undefined ? [] : [row.next.command]))
  for (const line of nextLines(next, askVault(deps), s, commands)) writeLine(deps.stderr, line)
  return EXIT.human
}

async function setVar(args: SetArgs, deps: Deps): Promise<number> {
  const { name, env, item, field, plain } = args
  const s = stylerFor(deps, deps.stderr)
  const located = locateManifest(cwdOf(deps))
  const resolved = resolveEnv(env, envOf(deps), located.manifest)
  writeBanner(deps.stderr, located, resolved.env)
  const declared = located.manifest.vars.find((v) => v.name === name)
  if (declared === undefined) writeLine(deps.stderr, warningLine(s, `mehen.toml does not declare ${name}; add ${name} = "vault" under [vars] or mehen run will not ask for it`))
  else if (declared.source === "plain") writeLine(deps.stderr, warningLine(s, `mehen.toml gives ${name} a plain value; change it to ${name} = "vault" or mehen run will keep using the committed value`))
  await deps.api.request<Project>("PUT", `/v1/projects/${encodeURIComponent(located.manifest.project)}/vars/${name}`, {
    env: resolved.env,
    ...(item !== undefined ? { item } : {}),
    ...(field !== undefined ? { field } : {}),
    ...(plain !== undefined ? { plain } : {}),
  })
  const source = item !== undefined ? `vault item ${item}${field !== undefined ? `#${field}` : ""}` : "a plain value"
  writeLine(deps.stdout, `${name} now resolves from ${source} for env=${resolved.env}`)
  return EXIT.ok
}

export async function envCommand(argv: string[], deps: Deps): Promise<number> {
  const help = envHelp(argv)
  if (help !== null) {
    deps.stdout.write(`usage: ${help}\n`)
    return EXIT.ok
  }
  const [sub, ...rest] = argv
  const json = (sub === "ls" || sub === "check") && rest.includes("--json")
  try {
    const args = parseEnvArgs(argv)
    return args.sub === "set" ? await setVar(args, deps) : await listOrCheck(args, deps)
  } catch (error) {
    return reportFailure(deps, error, json)
  }
}
