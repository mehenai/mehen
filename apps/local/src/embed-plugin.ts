// What the local host needs from the Workers build, for Bun: the
// cloudflare:workers module, Markdown imported as text, and two virtual
// modules that carry the D1 migrations and the built UI assets, so a
// compiled binary needs no files beside it. One plugin serves `bun run`
// (through preload.ts) and `bun build --compile` (through build.ts).

import type { BunPlugin } from "bun"
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import { join, relative, resolve } from "node:path"

const VAULT = resolve(import.meta.dir, "../../vault")

const WORKERS_SHIM = `export class DurableObject {
  constructor(ctx, env) {
    this.ctx = ctx
    this.env = env
  }
}
export const env = {}
`

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    return statSync(path).isDirectory() ? files(path) : [path]
  })
}

function migrationsModule(): string {
  const dir = join(VAULT, "migrations")
  const list = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort().map((name) => ({ name, sql: readFileSync(join(dir, name), "utf8") }))
  return `export const MIGRATIONS = ${JSON.stringify(list)}\n`
}

// The UI bundle apps/vault builds (bun run --cwd apps/vault build:ui). A
// tree without it embeds nothing; bundleHost refuses to bundle such a tree.
function assetsModule(): string {
  const dir = join(VAULT, "dist")
  if (!existsSync(dir)) return "export const ASSETS = {}\n"
  const entries = files(dir).map((path) => [`/${relative(dir, path)}`, readFileSync(path).toString("base64")])
  return `export const ASSETS = ${JSON.stringify(Object.fromEntries(entries))}\n`
}

// The vault Worker behind a typed seam (virtual.d.ts): this package's
// typecheck runs with Bun's types and never enters the Workers source, which
// apps/vault checks with its own.
function vaultModule(): string {
  const entry = JSON.stringify(join(VAULT, "src/index.ts"))
  return `export { default, WorkspaceVault, PlatformVault } from ${entry}\n`
}

const VIRTUAL: Record<string, () => string> = {
  "cloudflare:workers": () => WORKERS_SHIM,
  "mehen-local:vault": vaultModule,
  "mehen-local:migrations": migrationsModule,
  "mehen-local:assets": assetsModule,
}

function markdown(path: string): string {
  return `export default ${JSON.stringify(readFileSync(path, "utf8"))}`
}

// For Bun.build and --compile: resolve the virtual modules into a namespace
// of their own, keyed by the full specifier.
export const embedBuildPlugin: BunPlugin = {
  name: "mehen-local-embed",
  setup(build) {
    build.onResolve({ filter: /^(cloudflare:workers|mehen-local:(migrations|assets|vault))$/ }, (args) => ({ path: args.path, namespace: "mehen-local-virtual" }))
    build.onLoad({ filter: /.*/, namespace: "mehen-local-virtual" }, (args) => {
      const make = VIRTUAL[args.path] ?? VIRTUAL[`mehen-local:${args.path}`]
      if (!make) throw new Error(`unknown virtual module ${args.path}`)
      return { contents: make(), loader: "js" }
    })
    build.onLoad({ filter: /\.md$/ }, (args) => ({ contents: markdown(args.path), loader: "js" }))
  },
}

// For bun run and bun test, through preload.ts: the runtime's own virtual
// module API.
export const embedRuntimePlugin: BunPlugin = {
  name: "mehen-local-embed-runtime",
  setup(build) {
    for (const [specifier, make] of Object.entries(VIRTUAL)) build.module(specifier, () => ({ contents: make(), loader: "js" }))
    build.onLoad({ filter: /\.md$/ }, (args) => ({ contents: markdown(args.path), loader: "js" }))
  },
}
