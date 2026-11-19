// The TypeScript samples of the platform guide and @mehen/client's README,
// typechecked as a reader would paste them: each ```ts block is its own
// module, importing @mehen/client by the subpaths its package.json exports.
// A block may use a name an earlier block on the page made (`platform`,
// `forTask`); the page's prelude declares it, typed, unless the block
// declares or imports it itself.
//
// The guide's samples and the README's platform samples also run, in page
// order, against a stand-in vault (samples.test.ts): see runSamples.
//
//   bun scripts/samples.ts

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"

export const REPO_ROOT = path.resolve(import.meta.dir, "../../..")

export type Sample = { file: string; line: number; code: string }

// The names each page's blocks share, as ambient declarations.
export const PRELUDES: Record<string, Record<string, string>> = {
  "docs/site/guides/build-on-mehen.md": {
    env: "{ PLATFORM_ID: string; PLATFORM_KEY_ID: string; PLATFORM_PRIVATE_JWK: string; VAULT_URL: string }",
    platform: 'import("@mehen/client").PlatformClient',
    user: 'import("@mehen/client").SubjectClient',
    subject: "string",
    agentKey: 'import("@mehen/client").KeyPair',
    intake: 'import("@mehen/client").PlatformIntake',
    appIntake: 'import("@mehen/client").PlatformIntake',
    sealed: 'Record<string, import("@mehen/client").SealedBox>',
    callbackUrl: "URL",
    approvalId: "string",
  },
  "packages/client/README.md": {
    privateJwkText: "string",
    platformId: "string",
    keyId: "string",
    approvalId: "string",
    pkcs8: 'Awaited<ReturnType<typeof import("@mehen/client").exportPrivateKey>>',
    status: '{ status: "active"; tenant: string; device: string }',
    mehen: 'import("@mehen/client").MehenClient',
    forTask: 'import("@mehen/client").MehenClient',
    request: 'import("@mehen/client").RelayInput',
    platform: 'import("@mehen/client").PlatformClient',
    user: 'import("@mehen/client").SubjectClient',
    intake: 'import("@mehen/client").PlatformIntake',
    sealed: 'Record<string, import("@mehen/client").SealedBox>',
  },
}

// Names only the platform client and its browser entry provide.
const PLATFORM_NAMES = /createPlatformClient|platformSigner|PlatformClient|SubjectClient|PlatformIntake|SealedBox|@mehen\/client\/seal|sealFields|\buser\.|\bplatform\./

export function needsPlatformClient(sample: Sample): boolean {
  return PLATFORM_NAMES.test(sample.code)
}

// Every ```ts block of a markdown file, with the line its code starts on.
export function samplesOf(markdown: string, file: string): Sample[] {
  const out: Sample[] = []
  let open: { line: number; lines: string[] } | null = null
  markdown.split("\n").forEach((line, n) => {
    if (open === null) {
      if (/^```ts\s*$/.test(line)) open = { line: n + 2, lines: [] }
      return
    }
    if (/^```\s*$/.test(line)) {
      out.push({ file, line: open.line, code: open.lines.join("\n") })
      open = null
      return
    }
    open.lines.push(line)
  })
  return out
}

function declares(code: string, name: string): boolean {
  const word = `\\b${name}\\b`
  const named = new RegExp(word)
  if (new RegExp(`\\b(?:const|let|var|function|class)\\s+${word}`).test(code)) return true
  const destructured = [...code.matchAll(/\b(?:const|let|var)\s+\{([^}]*)\}\s*=/g)].some((m) => named.test(m[1] as string))
  const imported = [...code.matchAll(/^import\s+(?:type\s+)?\{([^}]*)\}/gm)].some((m) => named.test(m[1] as string))
  return destructured || imported
}

// The prelude for one block: the page's shared names it uses and does not
// make itself.
export function prelude(sample: Sample): string[] {
  const names = PRELUDES[sample.file] ?? {}
  return Object.entries(names)
    .filter(([name]) => new RegExp(`\\b${name}\\b`).test(sample.code) && !declares(sample.code, name))
    .map(([name, type]) => `declare const ${name}: ${type}`)
}

// `@mehen/client` and its subpaths as its package.json exports them, and
// the protocol, for the samples' tsconfig.
async function paths(): Promise<Record<string, string[]>> {
  const client = JSON.parse(await readFile(path.join(REPO_ROOT, "packages/client/package.json"), "utf8")) as { exports: Record<string, string> }
  const out: Record<string, string[]> = {}
  for (const [subpath, target] of Object.entries(client.exports)) out[path.posix.join("@mehen/client", subpath)] = [path.join(REPO_ROOT, "packages/client", target)]
  out["@mehen/protocol"] = [path.join(REPO_ROOT, "packages/protocol/src/index.ts")]
  out["@mehen/protocol/*"] = [path.join(REPO_ROOT, "packages/protocol/src/*.ts")]
  return out
}

export type SampleProblem = { file: string; line: number; message: string }

// Typechecks every sample under the repository's strict settings, as a
// consumer with the DOM and WebCrypto: the problems, each at its line in
// the markdown.
export async function typecheckSamples(samples: readonly Sample[]): Promise<SampleProblem[]> {
  if (samples.length === 0) return []
  const dir = await mkdtemp(path.join(tmpdir(), "mehen-samples-"))
  try {
    const placed = new Map<string, { sample: Sample; offset: number }>()
    for (const [i, sample] of samples.entries()) {
      const head = prelude(sample)
      const name = `sample-${i}.ts`
      await writeFile(path.join(dir, name), `${[...head, sample.code, "export {}"].join("\n")}\n`)
      placed.set(name, { sample, offset: head.length })
    }
    const tsconfig = {
      extends: path.join(REPO_ROOT, "tsconfig.base.json"),
      compilerOptions: { lib: ["ES2022", "DOM"], types: [], paths: await paths() },
      include: ["*.ts"],
    }
    await writeFile(path.join(dir, "tsconfig.json"), JSON.stringify(tsconfig, null, 2))
    const proc = Bun.spawn([path.join(REPO_ROOT, "node_modules/.bin/tsc"), "-p", dir, "--pretty", "false"], { stdout: "pipe", stderr: "pipe" })
    const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
    const problems: SampleProblem[] = []
    for (const line of `${out}\n${err}`.split("\n")) {
      const m = /([^/\\]+\.ts)\((\d+),\d+\): (error .*)$/.exec(line)
      if (!m) continue
      const at = placed.get(m[1] as string)
      if (!at) {
        problems.push({ file: m[1] as string, line: Number(m[2]), message: m[3] as string })
        continue
      }
      problems.push({ file: at.sample.file, line: at.sample.line + Number(m[2]) - 1 - at.offset, message: m[3] as string })
    }
    return problems
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

export const GUIDE = "docs/site/guides/build-on-mehen.md"
export const SAMPLE_FILES = [GUIDE, "packages/client/README.md"]

// The samples that run as well as typecheck: every block of the guide, and
// the README's platform blocks. The README's machine blocks need an
// enrolled machine and a person, so they are only typechecked.
export function runnable(sample: Sample): boolean {
  return sample.file === GUIDE || needsPlatformClient(sample)
}

// The names a block makes at its top level: `const x`, `let x`, and the
// names in `const { a, b }` or `const [a, b]`.
export function declaredNames(code: string): string[] {
  const out = new Set<string>()
  for (const m of code.matchAll(/^(?:const|let|var)\s+([A-Za-z_$][\w$]*)/gm)) out.add(m[1] as string)
  for (const m of code.matchAll(/^(?:const|let|var)\s+[{[]([^}\]]*)[}\]]\s*=/gm)) {
    for (const part of (m[1] as string).split(",")) {
      const name = part.split(":").at(-1)?.split("=")[0]?.trim() ?? ""
      if (/^[A-Za-z_$][\w$]*$/.test(name)) out.add(name)
    }
  }
  return [...out]
}

const IMPORT_LINE = /^import\s+(\{[^}]*\})\s+from\s+"([^"]+)"\s*$/

// One block as a module whose default export runs it: its imports point at
// the client's own sources, the page's shared names it uses come from
// `scope`, and it answers the names it made.
function runnableModule(sample: Sample, resolved: Record<string, string[]>, origins: { from: string; to: string }): string {
  const imports: string[] = []
  const body: string[] = []
  for (const line of sample.code.replaceAll(origins.from, origins.to).split("\n")) {
    const m = IMPORT_LINE.exec(line)
    if (!m) {
      body.push(line)
      continue
    }
    const target = resolved[m[2] as string]?.[0]
    if (target === undefined) throw new Error(`${sample.file}:${sample.line}: cannot run an import of ${m[2]}`)
    imports.push(`import ${m[1]} from ${JSON.stringify(target)}`)
  }
  // A shared name mentioned only in a string or a comment is not used.
  const code = sample.code.replaceAll(/"(?:[^"\\]|\\.)*"/g, '""').replaceAll(/(^|\s)\/\/.*$/gm, "$1")
  const shared = Object.keys(PRELUDES[sample.file] ?? {}).filter((name) => new RegExp(`\\b${name}\\b`).test(code) && !declares(sample.code, name))
  return [
    "// @ts-nocheck",
    ...imports,
    "export default async function (scope) {",
    ...shared.map((name) => `if (!(${JSON.stringify(name)} in scope)) throw new Error(${JSON.stringify(`uses ${name}, which no earlier block made and the run does not give`)})`),
    shared.length ? `const { ${shared.join(", ")} } = scope` : "",
    ...body,
    `return { ${declaredNames(sample.code).join(", ")} }`,
    "}",
  ].join("\n")
}

// Runs the samples in order, each block in its own scope, as a reader
// would run them one after another: a name a block makes is handed to the
// blocks after it, and `seeds` gives the names the page takes from the
// reader (its keys, its ids, its callback). Every `https://app.mehen.dev`
// becomes `origin`, the stand-in vault's. A failure names the block's line.
export async function runSamples(samples: readonly Sample[], seeds: Record<string, unknown>, origin: string): Promise<Record<string, unknown>> {
  const scope: Record<string, unknown> = { ...seeds }
  const resolved = await paths()
  const dir = await mkdtemp(path.join(tmpdir(), "mehen-run-"))
  try {
    // Every module is written before the first is loaded: the loader may
    // remember the directory as it first saw it.
    const files: string[] = []
    for (const [i, sample] of samples.entries()) {
      const file = path.join(dir, `sample-${i}.ts`)
      await writeFile(file, runnableModule(sample, resolved, { from: "https://app.mehen.dev", to: origin }))
      files.push(file)
    }
    for (const [i, sample] of samples.entries()) {
      const loaded = (await import(files[i] as string)) as { default: (scope: Record<string, unknown>) => Promise<Record<string, unknown>> }
      try {
        Object.assign(scope, await loaded.default(scope))
      } catch (error) {
        throw new Error(`${sample.file}:${sample.line}: ${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`)
      }
    }
    return scope
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

export async function allSamples(): Promise<Sample[]> {
  const out: Sample[] = []
  for (const file of SAMPLE_FILES) out.push(...samplesOf(await readFile(path.join(REPO_ROOT, file), "utf8"), file))
  return out
}

if (import.meta.main) {
  const problems = await typecheckSamples(await allSamples())
  for (const p of problems) console.error(`${p.file}:${p.line}: ${p.message}`)
  if (problems.length) process.exit(1)
  console.log("samples: ok")
}
