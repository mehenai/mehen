// Which environment a command runs in, and the child's environment variables.

import { EXIT, EnvName } from "@mehen/protocol/api"
import { CommandError, type Writer, writeLine } from "./deps.ts"
import type { Located, Manifest } from "./manifest.ts"

export type EnvSource = "flag" | "env-var" | "default"

export type ResolvedEnv = { env: string; source: EnvSource }

// --env on this command line, then MEHEN_ENV, then the manifest's default_env.
// MEHEN_ENV may only pick an unprotected environment; the vault enforces that
// from envSource, so it is not second-guessed here.
export function resolveEnv(flag: string | undefined, parentEnv: Record<string, string | undefined>, manifest: Manifest): ResolvedEnv {
  const fromVar = parentEnv.MEHEN_ENV
  const resolved: ResolvedEnv | null =
    flag !== undefined
      ? { env: flag, source: "flag" }
      : fromVar !== undefined && fromVar !== ""
        ? { env: fromVar, source: "env-var" }
        : manifest.defaultEnv !== null
          ? { env: manifest.defaultEnv, source: "default" }
          : null
  if (resolved === null) {
    throw new CommandError(EXIT.usage, `no environment: ${manifest.path} has no default_env, and neither --env nor MEHEN_ENV is set`, {
      say: 'Pass --env <name>, or add default_env = "dev" to mehen.toml.',
    })
  }
  if (!EnvName.safeParse(resolved.env).success) {
    const origin = resolved.source === "flag" ? "--env" : resolved.source === "env-var" ? "MEHEN_ENV" : "default_env"
    throw new CommandError(EXIT.usage, `${origin} is "${resolved.env}", which is not an environment name`, {
      say: "Environment names are lower case letters, digits and dashes, starting with a letter.",
    })
  }
  return resolved
}

// The project id is whatever mehen.toml says: through the terminal boundary.
export function writeBanner(out: Writer, located: Located, env: string, service = false): void {
  writeLine(out, `mehen: ${located.manifest.project} env=${env}${service ? " service" : ""} worktree=${located.worktree} head=${located.git.head ?? "none"}`)
}

// The parent's environment minus the vault's own MEHEN_* state and minus every
// ambient variable the manifest declares or an --item sets (an inherited prod
// DATABASE_URL from another shell must not win), with a warning for each one
// overridden.
export function inheritedEnv(parentEnv: Record<string, string | undefined>, declaredNames: readonly string[], items: readonly { item: string; variable: string }[], stderr: Writer): Record<string, string> {
  const declared = new Set(declaredNames)
  const fromItem = new Map(items.map((i) => [i.variable, i.item]))
  const out: Record<string, string> = {}
  for (const [name, value] of Object.entries(parentEnv)) {
    if (value === undefined || name.startsWith("MEHEN_")) continue
    if (declared.has(name)) {
      stderr.write(`mehen: warning: ignoring ${name} from your shell; mehen.toml declares it, so this run uses the project's value\n`)
      continue
    }
    const item = fromItem.get(name)
    if (item !== undefined) {
      stderr.write(`mehen: warning: ignoring ${name} from your shell; --item ${item} sets it\n`)
      continue
    }
    out[name] = value
  }
  return out
}
