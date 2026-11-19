// mehen init [--slug <slug>] [--env <name>]... [--json]: creates the project in the vault,
// bound to this repo's origin remote, and writes mehen.toml at the worktree root.
// Environments are created unprotected; the vault protects prod and
// production by itself, and anything else is a human's call (R5). When the
// remote is already a project this machine may use, it binds the checkout to
// that project instead and creates nothing.

import { existsSync, realpathSync, writeFileSync } from "node:fs"
import { basename, join } from "node:path"
import { EXIT, EnvName, type NextStep, isSlug, type Project, type ProjectBinding } from "@mehen/protocol"
import { usageError } from "../errors.ts"
import { boundProject, boundVariables } from "./bound-project.ts"
import { CommandError, type Deps, askVault, cwdOf, reportFailure, stylerFor, wantsHelp, warningLine, writeLine, writeNext } from "./deps.ts"
import { MANIFEST_FILE, gitFacts } from "./manifest.ts"

export const INIT_USAGE = "mehen init [--slug <slug>] [--env <name>]... [--json]"

const INIT_HELP = "mehen init --help"
const SLUG_HINT = "pass --slug <lower-case-name>"

type InitArgs = { slug?: string; envs: string[]; json: boolean }

// The arguments of mehen init, or a usage error; cli.ts calls it before it
// opens the vault session, so a bad line needs no enrolment to be refused.
export function parseInitArgs(argv: string[]): InitArgs {
  const args: InitArgs = { envs: [], json: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? ""
    if (arg === "--json") {
      args.json = true
      continue
    }
    const [flag = "", inline] = arg.split(/=(.*)/s)
    if (flag !== "--slug" && flag !== "--env") throw usageError(`Unexpected argument ${arg}. Usage: ${INIT_USAGE}`, INIT_HELP)
    const value = inline ?? argv[++i]
    if (value === undefined) throw usageError(`${flag} needs a value. Usage: ${INIT_USAGE}`, INIT_HELP)
    if (flag === "--slug") args.slug = value
    else args.envs.push(value)
  }
  if (args.slug !== undefined && !isSlug(args.slug)) throw usageError(`${args.slug} is not a valid slug; ${SLUG_HINT}.`, INIT_HELP)
  for (const env of args.envs) if (!EnvName.safeParse(env).success) throw usageError(`${env} is not an environment name.`, INIT_HELP)
  return args
}

export function slugFrom(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[^a-z]+/, "")
    .replace(/-+$/, "")
    .slice(0, 64)
    .replace(/-+$/, "")
}

// The workspace id and vault origin bind the checkout to its context
// (design 6.5); the name and slug are a comment, since only the id selects.
export function manifestText(project: Pick<Project, "id" | "defaultEnv">, context: { vault: string; tenant: string; workspaceSlug?: string; workspaceName?: string }): string {
  const label = context.workspaceSlug && context.workspaceName ? `  # workspace ${context.workspaceName.replace(/[\r\n]/g, " ")} (${context.workspaceSlug}); the id prefix is historical` : ""
  return [
    "# Mehen project manifest. No secrets, ever.",
    `project = "${project.id}"`,
    `workspace = "${context.tenant}"${label}`,
    `vault = "${context.vault}"`,
    `default_env = "${project.defaultEnv}"`,
    "",
    "[vars]",
    '# OPENAI_API_KEY = "vault"   # from the vault; the vault decides how it is delivered',
    '# LOG_LEVEL = "info"         # plain, committed, not secret',
    "",
  ].join("\n")
}

// `mehen init --json`: the project id as mehen.toml records it, and the
// absolute path of the mehen.toml it wrote. `bound` is set when the checkout
// was bound to the project its remote already is.
export type InitReport = { project: string; slug: string; path: string; remote: string | null; defaultEnv: string; next: NextStep; warning?: string; bound?: true }

// Writes mehen.toml naming the project the remote is already bound to, with
// every variable it defines declared from the vault.
function bind(args: InitArgs, deps: Deps, project: ProjectBinding, path: string, remote: string): number {
  if (args.slug !== undefined && args.slug !== project.slug) {
    throw new CommandError(EXIT.error, `this checkout's remote ${remote} is already project ${project.slug} (${project.id}); mehen init does not create ${args.slug} beside it`, {
      say: `Run mehen init without --slug to bind this checkout to project ${project.slug}.`,
      command: "mehen init",
    })
  }
  if (args.envs.length > 0) {
    throw new CommandError(EXIT.error, `this checkout's remote ${remote} is already project ${project.slug} (${project.id}); mehen init does not change its environments`, {
      say: `Run mehen init without --env to bind this checkout to project ${project.slug}; its environments are changed on the project page.`,
      command: "mehen init",
    })
  }
  const text = `${manifestText(project, deps.config)}${boundVariables(project).map((name) => `${name} = "vault"\n`).join("")}`
  try {
    writeFileSync(path, text, { flag: "wx" })
  } catch (error) {
    throw new CommandError(EXIT.error, `could not write ${path}: ${error instanceof Error ? error.message : String(error)}`, {
      say: `Write mehen.toml by hand with project = "${project.id}", workspace = "${deps.config.tenant}", vault = "${deps.config.vault}" and default_env = "${project.defaultEnv}".`,
    })
  }
  const next = { say: "commit mehen.toml so every checkout and worktree of this repo gets it, then mehen env check" }
  if (args.json) {
    const report: InitReport = { project: project.id, slug: project.slug, path, remote, defaultEnv: project.defaultEnv, next, bound: true }
    deps.stdout.write(`${JSON.stringify(report)}\n`)
    return EXIT.ok
  }
  // project.slug and project.id came from the vault.
  writeLine(deps.stdout, `bound this checkout to project ${project.slug} (${project.id}); wrote ${path}`)
  writeNext(deps.stderr, next, askVault(deps), stylerFor(deps, deps.stderr))
  return EXIT.ok
}

async function init(args: InitArgs, deps: Deps): Promise<number> {
  const cwd = realpathSync(cwdOf(deps))
  const facts = gitFacts(cwd)
  const dir = facts.root ?? cwd
  const path = join(dir, MANIFEST_FILE)
  if (existsSync(path)) {
    throw new CommandError(EXIT.error, `${path} already exists; mehen init does not overwrite it`, {
      say: "Use the project it names, or delete it first if you really mean to start again.",
    })
  }
  const bound = await boundProject(deps.api, facts.remote)
  if (bound !== null && facts.remote !== null) return bind(args, deps, bound, path, facts.remote)
  const slug = args.slug ?? slugFrom(facts.remote?.split("/").pop() ?? basename(dir))
  if (!isSlug(slug)) throw usageError(`${slug === "" ? "Could not derive a project slug from this directory" : `${slug}, derived from this directory, is not a valid slug`}; ${SLUG_HINT}.`, INIT_HELP)
  const envs = args.envs.length > 0 ? [...new Set(args.envs)] : ["dev"]
  const defaultEnv = envs[0] ?? "dev"

  const project = await deps.api.request<Project>("POST", "/v1/projects", {
    slug,
    remote: facts.remote,
    environments: envs.map((name) => ({ name, protected: false })),
    defaultEnv,
  })
  try {
    writeFileSync(path, manifestText(project, deps.config), { flag: "wx" })
  } catch (error) {
    throw new CommandError(EXIT.error, `created project ${project.slug} (${project.id}) but could not write ${path}: ${error instanceof Error ? error.message : String(error)}`, {
      say: `Write mehen.toml by hand with project = "${project.id}", workspace = "${deps.config.tenant}", vault = "${deps.config.vault}" and default_env = "${project.defaultEnv}".`,
    })
  }
  const warning = facts.remote === null ? "this directory has no origin remote, so the project is not bound to a repo" : null
  const next = { say: `declare variables under [vars] in mehen.toml, commit it, then mehen env set <NAME> --env ${defaultEnv} --item <slug>` }
  if (args.json) {
    const report: InitReport = { project: project.id, slug: project.slug, path, remote: facts.remote, defaultEnv: project.defaultEnv, next, ...(warning ? { warning } : {}) }
    deps.stdout.write(`${JSON.stringify(report)}\n`)
    return EXIT.ok
  }
  // project.slug and project.id came from the vault.
  writeLine(deps.stdout, `created project ${project.slug} (${project.id}) bound to ${facts.remote ?? "no remote"}; wrote ${path}`)
  const s = stylerFor(deps, deps.stderr)
  if (warning !== null) writeLine(deps.stderr, warningLine(s, warning))
  writeNext(deps.stderr, next, askVault(deps), s)
  return EXIT.ok
}

// The usage when `mehen init` is asked for help, else null.
export function initHelp(argv: string[]): string | null {
  return wantsHelp(argv, ["--slug", "--env"], false) ? INIT_USAGE : null
}

export async function initCommand(argv: string[], deps: Deps): Promise<number> {
  const help = initHelp(argv)
  if (help !== null) {
    deps.stdout.write(`usage: ${help}\n`)
    return EXIT.ok
  }
  const json = argv.includes("--json")
  try {
    return await init(parseInitArgs(argv), deps)
  } catch (error) {
    return reportFailure(deps, error, json)
  }
}
