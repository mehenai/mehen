// The vault engine `mehen serve` runs. A compiled build carries it as
// src/generated/local-host.js, which scripts/build.ts writes before
// compiling and deletes after. A source run bundles apps/local on the spot
// into a private folder and imports that.

import { existsSync } from "node:fs"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { LocalHost } from "../../local/src/types.ts"
import { CliError } from "./errors.ts"

let host: Promise<LocalHost> | undefined

async function fromSource(): Promise<LocalHost> {
  let bundleHost: () => Promise<string>
  let uiBuilt: string
  try {
    ;({ bundleHost, VAULT_UI: uiBuilt } = await import("../../local/src/bundle.ts"))
  } catch {
    throw new CliError("internal", "This mehen carries no vault engine, so it cannot serve one.", { say: "Install a released mehen (https://mehen.dev/install), which carries it." })
  }
  // A checkout without the vault's pages built would serve a sign-up page
  // whose passkey button never works, so they are built first.
  if (!existsSync(uiBuilt)) {
    const vault = join(import.meta.dir, "../../vault")
    const build = Bun.spawnSync([process.execPath, "scripts/build-ui.ts"], { cwd: vault, stdout: "ignore", stderr: "pipe" })
    if (build.exitCode !== 0 || !existsSync(uiBuilt)) throw new CliError("failed", "The vault's pages are not built, and building them failed.", { say: "Run `bun run --cwd apps/vault build:ui` and read what it says, then start the vault again." })
  }
  const dir = await mkdtemp(join(tmpdir(), "mehen-serve-"))
  const file = join(dir, "local-host.js")
  try {
    await writeFile(file, await bundleHost(), { mode: 0o600 })
    return (await import(file)) as LocalHost
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

export function localHost(): Promise<LocalHost> {
  host ??= import("./generated/local-host.js").then(
    (module) => module as LocalHost,
    () => fromSource(),
  )
  return host
}
