// The package runs anywhere with WebCrypto and fetch: its sources import only
// the protocol, zod and each other, and reach for no runtime's own globals.

import { describe, expect, it } from "bun:test"
import { readFileSync, readdirSync } from "node:fs"
import { dirname, join, relative, resolve } from "node:path"
import { CLIENT_VERSION, createClient, createPlatformClient, deviceSigner, generateKey, platformSigner } from "../src/index.ts"
import type { MachineProject, RelayInput, RelayStream, RelayStreamOptions, RelayTarget, RunEnded, RunInput, RunRenewed, RunVar, Runs, WorkspaceRunCreated } from "../src/index.ts"

const ROOT = join(import.meta.dir, "..")
const SRC = join(ROOT, "src")
const PROTOCOL_SRC = join(ROOT, "..", "protocol", "src")

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) return sources(path)
    return entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts") ? [path] : []
  })
}

const SPECIFIER = /(?:^|\n)\s*(?:import|export)\s[^"'`]*?from\s*["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)|(?:^|\n)\s*import\s*["']([^"']+)["']/g
const ALLOWED = /^(?:@mehen\/protocol(?:\/[a-z0-9-]+)?|zod|\.\.?\/[A-Za-z0-9./-]+\.ts)$/
const RUNTIME_GLOBALS = /\b(?:Bun|Deno|process|Buffer|require|__dirname|__filename|globalThis|window|document|navigator|localStorage|XMLHttpRequest)\b/

function code(text: string): string {
  return text.replaceAll(/\/\/[^\n]*/g, "").replaceAll(/\/\*[\s\S]*?\*\//g, "")
}

function specifiers(file: string): string[] {
  return [...readFileSync(file, "utf8").matchAll(SPECIFIER)].map((match) => match[1] ?? match[2] ?? match[3] ?? "")
}

// Every module a source reaches through its imports, type-only ones too:
// files as paths relative to packages/, and bare packages by name.
function importClosure(entry: string): Set<string> {
  const reached = new Set<string>()
  const visit = (file: string) => {
    const name = relative(join(ROOT, ".."), file)
    if (reached.has(name)) return
    reached.add(name)
    for (const specifier of specifiers(file)) {
      if (specifier === "@mehen/protocol") visit(join(PROTOCOL_SRC, "index.ts"))
      else if (specifier.startsWith("@mehen/protocol/")) visit(join(PROTOCOL_SRC, `${specifier.slice("@mehen/protocol/".length)}.ts`))
      else if (specifier.startsWith(".")) visit(resolve(dirname(file), specifier))
      else reached.add(specifier)
    }
  }
  visit(entry)
  return reached
}

describe("@mehen/client sources", () => {
  const files = sources(SRC)

  it("exist", () => {
    expect(files.length).toBeGreaterThan(0)
  })

  it("import only @mehen/protocol, zod or relative paths", () => {
    for (const file of files) {
      const text = readFileSync(file, "utf8")
      for (const match of text.matchAll(SPECIFIER)) {
        const specifier = match[1] ?? match[2] ?? match[3] ?? ""
        expect(ALLOWED.test(specifier), `${file} imports ${specifier}`).toBe(true)
      }
    }
  })

  it("use no Node, Bun, Deno or DOM-only globals", () => {
    for (const file of files) {
      const found = RUNTIME_GLOBALS.exec(code(readFileSync(file, "utf8")))
      expect(found?.[0] ?? null, file).toBeNull()
    }
  })

  it("keep the browser seal entry to the protocol's seal code: no zod, no other module", () => {
    expect([...importClosure(join(SRC, "seal.ts"))].sort()).toEqual(["client/src/seal.ts", "protocol/src/bytes.ts", "protocol/src/seal.ts"])
  })

  it("vendor, in the consumer typecheck, exactly the protocol modules the sources import", () => {
    const imported = new Set(files.flatMap((file) => [...importClosure(file)]).filter((name) => name.startsWith("protocol/")))
    const config = readFileSync(join(ROOT, "tsconfig.consumer.json"), "utf8")
    const listed = [...config.matchAll(/"\.\.\/(protocol\/src\/[a-z-]+\.ts)"/g)].map((match) => match[1] as string)
    // The template folder is vendored by a wildcard, without its tests.
    expect(config).toContain('"../protocol/src/templates/*.ts"')
    expect(config).toContain('"exclude": ["../protocol/src/templates/*.test.ts"]')
    const templates = readdirSync(join(PROTOCOL_SRC, "templates"))
      .filter((name) => name.endsWith(".ts") && !name.endsWith(".test.ts"))
      .map((name) => `protocol/src/templates/${name}`)
    expect([...listed, ...templates].sort()).toEqual([...imported].sort())
  })

  it("export the root and the seal entry", () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { exports: Record<string, string> }
    expect(manifest.exports).toEqual({ ".": "./src/index.ts", "./seal": "./src/seal.ts" })
  })

  it("declare only @mehen/protocol and zod as dependencies, and the version the client sends", () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { version: string; dependencies: Record<string, string>; private: boolean }
    expect(Object.keys(manifest.dependencies).sort()).toEqual(["@mehen/protocol", "zod"])
    expect(manifest.version).toBe(CLIENT_VERSION)
    expect(manifest.private).toBe(true)
  })
})

describe("@mehen/client exports", () => {
  it("the platform client and its signer from the package root", async () => {
    const platform = createPlatformClient({ vaultUrl: "https://vault.example", signer: platformSigner("plt_globex0001", "pky_globex0001", (await generateKey()).privateKey) })
    expect([typeof platform.view, typeof platform.subjects.ensure, typeof platform.subject("globex_subject0001").connects.start]).toEqual(["function", "function", "function"])
  })

  it("runs, project and relayStream on every client, with their types from the package root", async () => {
    const client = createClient({ vaultUrl: "https://vault.example", tenant: "tn_acme0000test", signer: deviceSigner("dev_device0001", (await generateKey()).privateKey) })
    const runs: Runs = client.runs
    expect([typeof runs.create, typeof runs.renew, typeof runs.end, typeof client.project, typeof client.relayStream]).toEqual(["function", "function", "function", "function", "function"])
    // Compiled by the root typecheck: each type is reachable from the package root.
    const target: RelayTarget = { run: "run_run0001" }
    const input: RelayInput = { ...target, method: "GET", url: "https://api.openai.com/v1/models" }
    const run: RunInput = { project: "prj_project0001", env: "dev", envSource: "flag", remote: null, worktree: "/workspace", head: null, vars: [], command: "globex computer" }
    const options: RelayStreamOptions = { timeoutMs: 1000 }
    const answers: [RelayStream | null, RunRenewed | null, RunEnded | null, MachineProject | null, RunVar | null, WorkspaceRunCreated | null] = [null, null, null, null, null, null]
    expect([input.url, run.command, options.timeoutMs, answers.length]).toEqual(["https://api.openai.com/v1/models", "globex computer", 1000, 6])
  })
})
