// Builds mehen as standalone binaries into apps/cli/dist/, one per target,
// each darwin binary carrying the universal mehen-se Secure Enclave helper.
//
//   bun scripts/build.ts                       every target
//   bun scripts/build.ts --target darwin-arm64 one target (repeatable)
//   bun scripts/build.ts --no-mehen-se         skip the Swift helper (a dev build)
//   bun scripts/build.ts --commit a53a3de      the commit to stamp (default: git's HEAD)
//   bun scripts/build.ts --release             a release build (clean tree, helper required)
//
// Every binary carries the short commit as MEHEN_BUILD_COMMIT and the build
// kind as MEHEN_BUILD_KIND ("release" with --release, else "dev"), which
// `mehen version --json` prints next to the package version, and the target
// it was built for as MEHEN_BUILD_TARGET, so the updater on a musl system
// fetches the musl binary again rather than the glibc one beside it.
//
// Order: (1) the helper is built once, first, when any darwin target is
// asked for (macOS only; a darwin target without it is a dev build, and
// --release refuses it); (2) for each target, src/generated/embedded-helper.ts
// is written for that target (the helper embedded on darwin, null on linux),
// the target is bundled, and a darwin binary is re-signed ad hoc with the
// identifier dev.mehen.cli; (3) the generated module is deleted, so a later
// test or source run in this checkout never sees a stale helper. The helper
// is also copied to dist/mehen-se for the 0.2.0 updater's one hop. Before
// the targets, the vault UI is built and apps/local bundled into
// src/generated/local-host.js, the engine `mehen serve` runs, deleted after.

import { copyFile, mkdir, rm, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"

// The -musl targets link musl's libc and libstdc++ (Alpine: apk add libstdc++).
export const TARGETS = ["darwin-arm64", "darwin-x64", "linux-x64", "linux-arm64", "linux-x64-musl", "linux-arm64-musl"] as const
export type Target = (typeof TARGETS)[number]

export const CLI_DIR = join(import.meta.dir, "..")
export const GENERATED_HELPER_MODULE = join(CLI_DIR, "src", "generated", "embedded-helper.ts")
export const GENERATED_LOCAL_HOST = join(CLI_DIR, "src", "generated", "local-host.js")
export const VAULT_DIR = join(CLI_DIR, "..", "vault")
export const CLI_IDENTIFIER = "dev.mehen.cli"

export class BuildError extends Error {}

export type BuildArgs = { targets: Target[]; mehenSe: boolean; release: boolean; commit: string | null }

export function parseBuildArgs(argv: string[]): BuildArgs {
  const targets: Target[] = []
  let mehenSe = true
  let release = false
  let commit: string | null = null
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === "--no-mehen-se") mehenSe = false
    else if (arg === "--release") release = true
    else if (arg === "--commit") {
      const value = argv[++i]
      if (!value || !/^[0-9a-f]{7,40}$/.test(value)) throw new BuildError("--commit must be a hex commit id")
      commit = value
    } else if (arg === "--target") {
      const value = argv[++i]
      if (!value || !(TARGETS as readonly string[]).includes(value)) throw new BuildError(`--target must be one of ${TARGETS.join(", ")}`)
      if (!targets.includes(value as Target)) targets.push(value as Target)
    } else throw new BuildError(`unknown argument ${arg}`)
  }
  return { targets: targets.length ? targets : [...TARGETS], mehenSe, release, commit }
}

const isDarwin = (target: Target) => target.startsWith("darwin-")

// Whether the helper is built for these arguments on this host, and the
// refusal a release build gets when a darwin target would go without it.
export function helperPlan(args: BuildArgs, host: { platform: NodeJS.Platform; clean: boolean }): { buildHelper: boolean } {
  const wantsHelper = args.targets.some(isDarwin)
  const buildHelper = wantsHelper && args.mehenSe && host.platform === "darwin"
  if (args.release) {
    if (!host.clean) throw new BuildError("A release build needs a clean tree, so the stamped commit says what was built. Commit or stash the changes first.")
    if (wantsHelper && !buildHelper) throw new BuildError("A release build of a darwin target embeds the mehen-se helper, which builds on macOS only; drop --no-mehen-se and build on a Mac.")
  }
  return { buildHelper }
}

// The generated module for one target: the helper as an embedded file on
// darwin when one was built, null everywhere else.
export function embeddedHelperModule(target: Target, helper: string | null): string {
  const head = `// Written by scripts/build.ts for ${target} and deleted after the build. Never commit this file.\n// @ts-nocheck\n`
  if (helper && isDarwin(target)) return `${head}import helper from ${JSON.stringify(helper)} with { type: "file" }\nexport const EMBEDDED_HELPER: string | null = helper\n`
  return `${head}export const EMBEDDED_HELPER: string | null = null\n`
}

export type Runner = (cmd: string[], cwd: string) => Promise<void>

export type BuildTargetsInput = { targets: readonly Target[]; release: boolean; commit: string; helper: string | null; dist: string; platform?: NodeJS.Platform; run: Runner }

// Step (2) and (3): one generated module per target, bundled, re-signed on
// darwin; the generated module is always deleted afterwards.
export async function buildTargets(input: BuildTargetsInput): Promise<string[]> {
  const platform = input.platform ?? process.platform
  const built: string[] = []
  await mkdir(input.dist, { recursive: true })
  await mkdir(dirname(GENERATED_HELPER_MODULE), { recursive: true })
  try {
    for (const target of input.targets) {
      const outfile = join(input.dist, `mehen-${target}`)
      await writeFile(GENERATED_HELPER_MODULE, embeddedHelperModule(target, input.helper))
      await input.run([process.execPath, "build", "--compile", "--minify", `--define=MEHEN_BUILD_COMMIT=${JSON.stringify(input.commit)}`, `--define=MEHEN_BUILD_KIND=${JSON.stringify(input.release ? "release" : "dev")}`, `--define=MEHEN_BUILD_TARGET=${JSON.stringify(target)}`, `--target=bun-${target}`, "src/main.ts", "--outfile", outfile], CLI_DIR)
      if (isDarwin(target) && platform === "darwin") await input.run(["codesign", "--force", "--sign", "-", "--identifier", CLI_IDENTIFIER, outfile], CLI_DIR)
      built.push(outfile)
    }
  } finally {
    await rm(GENERATED_HELPER_MODULE, { force: true })
  }
  return built
}

function git(args: string[]): { code: number; out: string } {
  const result = Bun.spawnSync(["git", ...args], { cwd: CLI_DIR, stdout: "pipe", stderr: "pipe" })
  return { code: result.exitCode, out: result.stdout.toString().trim() }
}

function headCommit(): string {
  const { code, out } = git(["rev-parse", "--short=7", "HEAD"])
  if (code !== 0 || !/^[0-9a-f]{7,40}$/.test(out)) throw new BuildError("could not read the commit with git rev-parse; pass --commit")
  return out
}

function cleanTree(): boolean {
  const { code, out } = git(["status", "--porcelain"])
  return code === 0 && out === ""
}

async function spawnInherit(cmd: string[], cwd: string): Promise<void> {
  const proc = Bun.spawn(cmd, { cwd, stdout: "inherit", stderr: "inherit" })
  const code = await proc.exited
  if (code !== 0) throw new BuildError(`${cmd.join(" ")} exited ${code}`)
}

export async function main(argv: string[], run: Runner = spawnInherit): Promise<void> {
  const args = parseBuildArgs(argv)
  const { buildHelper } = helperPlan(args, { platform: process.platform, clean: !args.release || cleanTree() })
  const commit = args.commit ?? headCommit()
  const dist = join(CLI_DIR, "dist")
  await mkdir(dist, { recursive: true })
  let helper: string | null = null
  if (buildHelper) {
    const native = join(CLI_DIR, "native", "mehen-se")
    await run(["bash", join(native, "build.sh")], native)
    helper = join(native, "build", "mehen-se")
    await copyFile(helper, join(dist, "mehen-se"))
    console.error(JSON.stringify({ built: join(dist, "mehen-se") }))
  } else if (args.mehenSe && args.targets.some(isDarwin)) {
    console.error(JSON.stringify({ skipped: "mehen-se", reason: "the Secure Enclave helper builds on macOS only; the darwin binaries carry no helper" }))
  }
  // The vault engine `mehen serve` runs (src/local-host.ts): the vault UI
  // built, then apps/local bundled into one module every target compiles in.
  await run([process.execPath, "scripts/build-ui.ts"], VAULT_DIR)
  const { bundleHost } = await import("../../local/src/bundle.ts")
  await writeFile(GENERATED_LOCAL_HOST, await bundleHost())
  try {
    for (const outfile of await buildTargets({ targets: args.targets, release: args.release, commit, helper, dist, run })) {
      console.error(JSON.stringify({ built: outfile, commit, build: args.release ? "release" : "dev", helper: helper && outfile.includes("-darwin-") ? "embedded" : "none" }))
    }
  } finally {
    await rm(GENERATED_LOCAL_HOST, { force: true })
  }
}

if (import.meta.main) {
  try {
    await main(process.argv.slice(2))
  } catch (error) {
    console.error(`build: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }
}
