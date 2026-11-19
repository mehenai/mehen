// The local host as one JavaScript module for Bun, the vault engine, its
// migrations and its UI inside: what the CLI build compiles into `mehen`,
// and what a source run of `mehen serve` imports.

import { existsSync } from "node:fs"
import { join } from "node:path"
import { embedBuildPlugin } from "./embed-plugin.ts"

export const VAULT_UI = join(import.meta.dir, "../../vault/dist/assets/app.js")

export class BundleError extends Error {}

// Without the built UI the pages cannot run, so a bundle without it is refused.
export async function bundleHost(): Promise<string> {
  if (!existsSync(VAULT_UI)) throw new BundleError("The vault UI is not built, so the local vault would serve unstyled pages. Run: bun run --cwd apps/vault build:ui")
  const result = await Bun.build({ entrypoints: [join(import.meta.dir, "host.ts")], target: "bun", format: "esm", minify: true, plugins: [embedBuildPlugin] })
  if (!result.success) throw new BundleError(`The local host did not bundle: ${result.logs.map(String).join("; ")}`)
  const [output] = result.outputs
  if (!output || result.outputs.length !== 1) throw new BundleError(`The local host bundled into ${result.outputs.length} files, not one.`)
  return output.text()
}
