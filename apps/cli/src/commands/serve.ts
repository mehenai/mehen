// mehen serve: run a Mehen vault on this machine, or on a box other
// machines reach. The engine is the hosted vault's, unchanged.

import { EXIT } from "@mehen/protocol/api"
import { accessSync, constants } from "node:fs"
import { join } from "node:path"
import { LocalConfigError, resolveConfig } from "../../../local/src/config.ts"
import type { Command } from "../command.ts"
import type { Env } from "../config.ts"
import { CliError, usageError } from "../errors.ts"
import { resolveHome } from "../home.ts"
import { localHost } from "../local-host.ts"
import { ensureHelper, helperOverride } from "../mehen-se.ts"
import { note, printJson, printLine } from "../output.ts"
import { isCompiledBinary } from "../version.ts"

const USAGE = "mehen serve [--port <port>] [--data <dir>] [--origin https://<name>] [--bind <address>]"
const SOURCE_HELPER = join(import.meta.dir, "../../native/mehen-se/build/mehen-se")

const CUSTODY_LINE = {
  "secure-enclave": "Key: held by this Mac's Secure Enclave.",
  keyring: "Key: in your login keyring.",
  file: "Key: in a file only you can read (keys.json in the data directory).",
} as const

// The Secure Enclave helper that seals the vault's keys on a Mac, found as
// the device key's is: MEHEN_SE_PATH outside a release build, else the
// embedded helper. A run from source also takes the one build.sh leaves in
// native/mehen-se/build.
async function enclaveHelper(env: Env): Promise<string | null> {
  if (process.platform !== "darwin") return null
  try {
    const override = helperOverride(env)
    const found = await ensureHelper(env, override ? "" : resolveHome(env).root)
    if (found || override || isCompiledBinary()) return found
  } catch (error) {
    note(`The Secure Enclave helper could not be prepared (${error instanceof Error ? error.message : String(error)}).`)
    return null
  }
  try {
    accessSync(SOURCE_HELPER, constants.X_OK)
    return SOURCE_HELPER
  } catch {
    return null
  }
}

export const serveCommand: Command = {
  summary: "run a Mehen vault on this machine, or for other machines to reach with --origin (stops on Ctrl-C)",
  spec: { usage: USAGE, flags: { port: { type: "string" }, data: { type: "string" }, origin: { type: "string" }, bind: { type: "string" } }, positionals: { min: 0, max: 0 } },
  examples: [["serve"], ["serve", "--port", "7788", "--data", "/srv/mehen"], ["serve", "--origin", "https://vault.example.com"]],
  notes: [
    "Without --origin the vault answers on this machine's loopback only, at http://localhost:<port> (7787 by default).",
    "With --origin it answers that https name only; put TLS in front of it (tailscale serve, Caddy).",
    "--json prints one line, { origin, data, bootstrap, dumpable, custody }, once it is listening; custody is secure-enclave, keyring or file, what keeps the vault's root key.",
  ],
  async run({ args, json, env }) {
    // Everything the vault writes (its databases and their journals, keys,
    // backups) is this user's alone, however it was started.
    process.umask(0o077)
    let config
    try {
      config = resolveConfig({ dataDir: args.string("data") ?? undefined, port: args.string("port") ?? undefined, hostname: args.string("bind") ?? undefined, origin: args.string("origin") ?? undefined }, env)
    } catch (error) {
      if (error instanceof LocalConfigError) throw usageError(error.message, USAGE)
      throw error
    }
    const host = await localHost()
    let vault
    try {
      vault = await host.startLocalVault(config, { custody: { platform: process.platform, env, helper: await enclaveHelper(env) } })
    } catch (error) {
      if (error instanceof CliError) throw error
      // The engine is bundled with its own copy of CliError, so its refusals
      // arrive as another class: kept by their code and next step.
      const foreign = error as { code?: unknown; message?: unknown; next?: unknown }
      if (typeof foreign.code === "string" && typeof foreign.message === "string" && foreign.next !== undefined && foreign.code !== "EADDRINUSE") throw new CliError(foreign.code as ConstructorParameters<typeof CliError>[0], foreign.message, foreign.next as ConstructorParameters<typeof CliError>[2])
      if (error instanceof Error && error.name === "LocalConfigError") throw usageError(error.message, USAGE)
      const code = (error as { code?: string }).code
      if (code === "EADDRINUSE") throw new CliError("conflict", `Port ${config.port} is in use, so the vault cannot listen on it.`, { say: "Stop what is using it, or pass --port with another port." })
      throw error
    }
    const state = vault.state()
    if (json) printJson({ origin: vault.origin, data: config.dataDir, bootstrap: state.bootstrap, dumpable: vault.hardening.dumpable, custody: state.custody })
    else {
      printLine(`Mehen vault at ${vault.origin}`)
      printLine(`Data: ${config.dataDir}`)
      printLine(CUSTODY_LINE[state.custody])
      if (state.bootstrap) printLine(`No account yet: run \`mehen up\`, or open ${vault.origin}/signup#<code> with the code in ${join(config.dataDir, host.BOOTSTRAP_FILE)}.`)
      if (vault.hardening.dumpable === "failed") note(`Warning: this process could not make itself undumpable (${vault.hardening.detail}).`)
    }
    await new Promise<void>((resolve) => {
      const stop = () => resolve()
      process.once("SIGINT", stop)
      process.once("SIGTERM", stop)
    })
    await vault.stop()
    return EXIT.ok
  },
}
