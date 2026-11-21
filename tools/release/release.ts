// Builds a release of the mehen CLI and writes it as a tree that mirrors the
// mehen-releases R2 bucket, which mehen.dev serves under /dl:
//
//   <out>/v<version>/mehen-<os>-<arch>.gz   each binary, gzipped
//   <out>/v<version>/mehen-se.gz            the Secure Enclave helper (macOS)
//   <out>/v<version>/manifest.json          { version, commit, builtAt, files, signatures }
//   <out>/latest.json                       a copy of that manifest
//
// and, beside the tree, what the GitHub Release and the Homebrew tap get
// (never uploaded to the bucket):
//
//   <out>/github/v<version>/SHA256SUMS       sha256 of every .gz and of manifest.json
//   <out>/github/v<version>/mehen.rb         the Homebrew formula, from the signed manifest
//
//   bun tools/release/release.ts --out <dir> --release [--key <id>]            build, sign and write the release tree
//   bun tools/release/release.ts --out <dir> --release --upload-script <path>  also write the upload commands
//   bun tools/release/release.ts --out <dir> --release --upload                also print them
//   bun tools/release/release.ts --out <dir> --allow-dirty --unsigned          a local trial, never uploaded
//
// The version is `version` in apps/cli/package.json, the same string
// `mehen version --json` prints; the commit is git's short HEAD, stamped into
// every binary. It refuses a version already in <out>, a dirty tree (the
// commit would not say what was built) unless --allow-dirty, and a build
// without mehen-se. It never uploads: --upload prints the wrangler commands,
// latest.json last, then the GitHub Release mirror and (only with
// MEHEN_PUBLISH_BREW=1) the tap update, for whoever deploys. --upload and
// --upload-script need --release: their commands publish to the release
// bucket, and only a release-stamped binary ignores the MEHEN_RELEASE_KEYS
// test override.
//
// The manifest is signed with a release key (keys.ts; --key, or the only key
// in RELEASE_KEYS) through the freshly built mehen-se (or MEHEN_SE_PATH) and
// verified against RELEASE_KEYS before it is written (sign.ts). --unsigned
// skips the signature for a trial build and is accepted only with
// --allow-dirty or --partial: a public release is always signed.
//
// --release makes the release build (build.ts --release: stamped "release",
// helper embedded in every darwin binary, clean tree) and refuses to start
// while RELEASE_KEYS is empty. Before anything is assembled, the host's
// binary must print { version, commit, build, helper } as built, every
// darwin binary must pass `codesign --verify --strict`, and the host's darwin
// binary must extract its helper (`version --extract-helper`) as a signed
// file that runs `available` and equals dist/mehen-se.

import { createHash } from "node:crypto"
import { cp, mkdir, mkdtemp, readFile, rename, rm, stat, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import type { ReleaseKey, ReleaseSignature } from "../../packages/protocol/src/release-manifest.ts"
import { RELEASE_KEYS } from "../../apps/cli/src/release-keys.ts"
import { RELEASE_BINARIES, type ReleaseBinary } from "./binaries.ts"
import { readSigningKey, releaseKeyDir } from "./keys.ts"
import { type ManifestSigner, SigningError, helperSigner, signManifest, trustedEntry } from "./sign.ts"

export const REPO_ROOT = resolve(import.meta.dir, "..", "..")
const CLI_DIR = join(REPO_ROOT, "apps", "cli")
const DIST = join(CLI_DIR, "dist")
export const DEFAULT_BASE_URL = "https://mehen.dev/dl"
export const DEFAULT_BUCKET = "mehen-releases"
export const GITHUB_REPO = "mehenai/mehen"
export const TAP_REPO = "mehenai/homebrew-tap"

export { RELEASE_BINARIES, type ReleaseArch, type ReleaseBinary, type ReleaseOs } from "./binaries.ts"

export type ManifestFile = ReleaseBinary & { url: string; sha256: string; size: number; gzSha256: string; gzSize: number }

export type Manifest = { version: string; commit: string; builtAt: string; files: ManifestFile[] }
export type ReleaseManifestFile = Manifest & { signatures?: ReleaseSignature[] }

export const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?$/

export class ReleaseError extends Error {}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex")
}

async function exists(path: string): Promise<boolean> {
  return stat(path).then(
    () => true,
    () => false,
  )
}

export async function cliVersion(): Promise<string> {
  const pkg = JSON.parse(await readFile(join(CLI_DIR, "package.json"), "utf8")) as { version?: unknown }
  if (typeof pkg.version !== "string" || !VERSION_PATTERN.test(pkg.version)) throw new ReleaseError("apps/cli/package.json has no version like 1.2.3")
  return pkg.version
}

function git(args: string[]): string {
  const result = Bun.spawnSync(["git", ...args], { cwd: REPO_ROOT, stdout: "pipe", stderr: "pipe" })
  if (result.exitCode !== 0) throw new ReleaseError(`git ${args.join(" ")} failed: ${result.stderr.toString().trim()}`)
  return result.stdout.toString()
}

export type AssembleInput = {
  dist: string
  out: string
  version: string
  commit: string
  builtAt: string
  baseUrl: string
  binaries?: readonly ReleaseBinary[]
  // Signs the manifest before anything is renamed into place; absent for an
  // unsigned trial build.
  sign?: (manifest: Manifest) => Promise<Manifest & { signatures: ReleaseSignature[] }>
}

// The release tree from binaries already built in `dist`. Written to a
// partial directory and renamed into place, so a failure leaves no
// half-written v<version>; latest.json is written last.
export async function assembleRelease(input: AssembleInput): Promise<ReleaseManifestFile> {
  if (!VERSION_PATTERN.test(input.version)) throw new ReleaseError(`${input.version} is not a version like 1.2.3`)
  const versionDir = join(input.out, `v${input.version}`)
  if (await exists(versionDir)) throw new ReleaseError(`${versionDir} already exists: version ${input.version} was released. Bump "version" in apps/cli/package.json.`)
  const partial = join(input.out, `.v${input.version}.partial`)
  await rm(partial, { recursive: true, force: true })
  await mkdir(partial, { recursive: true })
  const base = input.baseUrl.replace(/\/+$/, "")
  const files: ManifestFile[] = []
  for (const binary of input.binaries ?? RELEASE_BINARIES) {
    const source = join(input.dist, binary.name)
    if (!(await exists(source))) throw new ReleaseError(`${source} was not built`)
    const raw = new Uint8Array(await readFile(source))
    const gz = Bun.gzipSync(raw, { level: 9 })
    await writeFile(join(partial, `${binary.name}.gz`), gz)
    files.push({ ...binary, url: `${base}/v${input.version}/${binary.name}.gz`, sha256: sha256(raw), size: raw.length, gzSha256: sha256(gz), gzSize: gz.length })
  }
  const unsigned: Manifest = { version: input.version, commit: input.commit, builtAt: input.builtAt, files }
  const manifest: ReleaseManifestFile = input.sign ? await input.sign(unsigned) : unsigned
  const text = `${JSON.stringify(manifest, null, 2)}\n`
  await writeFile(join(partial, "manifest.json"), text)
  await rename(partial, versionDir)
  await cp(join(versionDir, "manifest.json"), join(input.out, "latest.json"))
  return manifest
}

function shellQuote(value: string): string {
  return /^[A-Za-z0-9_./:@,=+%-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`
}

// The wrangler commands that upload a release tree: every versioned file,
// then its manifest, then latest.json, so nothing points at a file that is
// not there yet. Run from apps/web, whose wrangler is pinned.
export function uploadCommands(out: string, manifest: ReleaseManifestFile, bucket = DEFAULT_BUCKET): string[] {
  const root = resolve(out)
  const put = (key: string, file: string, type: string) => `wrangler r2 object put ${shellQuote(`${bucket}/${key}`)} --file ${shellQuote(file)} --content-type ${type} --remote`
  const prefix = `v${manifest.version}`
  return [
    ...manifest.files.map((f) => put(`${prefix}/${f.name}.gz`, join(root, prefix, `${f.name}.gz`), "application/gzip")),
    put(`${prefix}/manifest.json`, join(root, prefix, "manifest.json"), "application/json"),
    put("latest.json", join(root, "latest.json"), "application/json"),
  ]
}

// The files the GitHub Release carries: the bucket's versioned files, byte
// for byte, so each is checked against the signed manifest like a download
// from mehen.dev, and a SHA256SUMS over them for anyone without the manifest.
export function githubAssets(out: string, manifest: ReleaseManifestFile): string[] {
  const dir = join(resolve(out), `v${manifest.version}`)
  return [...manifest.files.map((f) => join(dir, `${f.name}.gz`)), join(dir, "manifest.json"), join(githubDir(out, manifest.version), "SHA256SUMS")]
}

export function githubDir(out: string, version: string): string {
  return join(resolve(out), "github", `v${version}`)
}

export async function checksums(out: string, manifest: ReleaseManifestFile): Promise<string> {
  const dir = join(out, `v${manifest.version}`)
  const lines = manifest.files.map((f) => `${f.gzSha256}  ${f.name}.gz`)
  lines.push(`${sha256(new Uint8Array(await readFile(join(dir, "manifest.json"))))}  manifest.json`)
  return `${lines.join("\n")}\n`
}

// The Homebrew formula for a release, from its manifest: each platform's
// .gz on the download base and its compressed sha256, which is what brew
// downloads and checks; brew unpacks it to mehen-<os>-<arch>. Homebrew runs
// glibc on Linux, so the musl builds are not in it.
export function homebrewFormula(manifest: Manifest): string {
  const file = (name: string) => {
    const found = manifest.files.find((f) => f.name === name)
    if (!found) throw new ReleaseError(`The manifest has no ${name}, so the Homebrew formula cannot be written. Build every target.`)
    if (!/^[0-9a-f]{64}$/.test(found.gzSha256) || !/^https:\/\/[^"\\#{}\s]+$/.test(found.url)) throw new ReleaseError(`${name}'s url or gzSha256 is not one a formula can carry.`)
    return found
  }
  const block = (os: string, name: string) => {
    const f = file(name)
    return [`    on_${os} do`, `      url "${f.url}"`, `      sha256 "${f.gzSha256}"`, "    end"]
  }
  if (!VERSION_PATTERN.test(manifest.version)) throw new ReleaseError(`${manifest.version} is not a version like 1.2.3`)
  return [
    `# Written by tools/release/release.ts for mehen ${manifest.version} (${manifest.commit}) from its signed manifest. Do not edit by hand.`,
    "class Mehen < Formula",
    '  desc "Credential vault for AI agents: they use keys without ever seeing them"',
    '  homepage "https://mehen.dev"',
    `  version "${manifest.version}"`,
    '  license "Apache-2.0"',
    "",
    "  on_macos do",
    ...block("arm", "mehen-darwin-arm64"),
    ...block("intel", "mehen-darwin-x64"),
    "  end",
    "",
    "  on_linux do",
    ...block("arm", "mehen-linux-arm64"),
    ...block("intel", "mehen-linux-x64"),
    "  end",
    "",
    "  def install",
    '    bin.install Dir["mehen-*"].first => "mehen"',
    "  end",
    "",
    "  test do",
    '    assert_match "mehen #{version}", shell_output("#{bin}/mehen --version")',
    "  end",
    "end",
    "",
  ].join("\n")
}

// What the upload script runs after latest.json, from the repository root:
// the GitHub Release v<version> on the release commit (the tag made on
// GitHub when it is missing; a tag on another commit stops the script), and
// then, only with MEHEN_PUBLISH_BREW=1, the tap's Formula/mehen.rb. Both are
// skipped when already done, so the script can run again after a failure.
export function githubCommands(out: string, manifest: ReleaseManifestFile, commit: string): string[] {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new ReleaseError(`${commit} is not a full commit id`)
  const tag = `v${manifest.version}`
  const formula = join(githubDir(out, manifest.version), "mehen.rb")
  const notes = `mehen ${manifest.version}, built from ${commit.slice(0, 7)}. Install with \`curl -fsSL https://mehen.dev/install | sh\` or \`npx @mehenai/cli\`. The binaries are the ones served from https://mehen.dev/dl/${tag}/ and manifest.json is their signed manifest. Release notes: https://docs.mehen.dev/changelog`
  return [
    `# Mirror ${tag} to GitHub Releases on ${GITHUB_REPO}, which also starts the container image build.`,
    `if gh release view ${tag} -R ${GITHUB_REPO} > /dev/null 2>&1; then`,
    `  echo "GitHub Release ${tag} already exists; left as it is."`,
    "else",
    `  if ! tagged=$(gh api repos/${GITHUB_REPO}/commits/${tag} --jq .sha 2> /dev/null); then`,
    `    gh api repos/${GITHUB_REPO}/git/refs -f ref=refs/tags/${tag} -f sha=${commit} > /dev/null`,
    `    tagged=${commit}`,
    "  fi",
    `  [ "$tagged" = ${commit} ] || { echo "Tag ${tag} on ${GITHUB_REPO} is $tagged, not the release commit ${commit}. Nothing was mirrored." >&2; exit 1; }`,
    `  gh release create ${tag} -R ${GITHUB_REPO} --verify-tag --title ${shellQuote(`mehen ${manifest.version}`)} --notes ${shellQuote(notes)} ${githubAssets(out, manifest).map(shellQuote).join(" ")}`,
    "fi",
    "",
    `# Homebrew: ${TAP_REPO}'s Formula/mehen.rb, only with MEHEN_PUBLISH_BREW=1 (docs/OPERATIONS.md, "The Homebrew tap").`,
    `if [ "\${MEHEN_PUBLISH_BREW:-0}" = 1 ]; then`,
    '  tap=$(mktemp -d)',
    `  gh repo clone ${TAP_REPO} "$tap" -- --quiet --depth 1`,
    '  mkdir -p "$tap/Formula"',
    `  cp ${shellQuote(formula)} "$tap/Formula/mehen.rb"`,
    '  if git -C "$tap" diff --quiet HEAD -- Formula/mehen.rb 2> /dev/null && git -C "$tap" ls-files --error-unmatch Formula/mehen.rb > /dev/null 2>&1; then',
    `    echo "${TAP_REPO} already has mehen ${manifest.version}."`,
    "  else",
    '    git -C "$tap" add Formula/mehen.rb',
    `    git -C "$tap" commit --quiet -m ${shellQuote(`mehen ${manifest.version}`)}`,
    '    git -C "$tap" push --quiet origin HEAD',
    "  fi",
    '  rm -rf "$tap"',
    "else",
    `  echo ${shellQuote(`Homebrew: not published (MEHEN_PUBLISH_BREW is not 1); the formula is at ${formula}`)}`,
    "fi",
  ]
}

export type NotariseResult = { notarised: false; reason: string } | { notarised: true; files: string[] }

// Apple notarisation of the macOS binaries. It needs a Developer ID
// signature and a notarytool keychain profile, which this programme does
// not have yet, so it is a no-op unless MEHEN_NOTARY_PROFILE names one.
// curl leaves no quarantine attribute, so ad-hoc signed binaries run.
export async function notarise(dist: string, env: Record<string, string | undefined>, run: (cmd: string[]) => Promise<void> = spawnChecked, binaries: readonly ReleaseBinary[] = RELEASE_BINARIES): Promise<NotariseResult> {
  const profile = env.MEHEN_NOTARY_PROFILE
  if (!profile) return { notarised: false, reason: "MEHEN_NOTARY_PROFILE is not set, so the macOS binaries are not notarised (they stay ad-hoc signed)." }
  const files = binaries.filter((b) => b.os === "darwin").map((b) => join(dist, b.name))
  for (const file of files) {
    const zip = `${file}.notarise.zip`
    await run(["ditto", "-c", "-k", "--keepParent", file, zip])
    try {
      await run(["xcrun", "notarytool", "submit", zip, "--keychain-profile", profile, "--wait"])
    } finally {
      await rm(zip, { force: true })
    }
  }
  return { notarised: true, files }
}

export async function spawnChecked(cmd: string[]): Promise<void> {
  const proc = Bun.spawn(cmd, { cwd: REPO_ROOT, stdout: "pipe", stderr: "inherit" })
  for await (const chunk of proc.stdout) process.stderr.write(chunk)
  const code = await proc.exited
  if (code !== 0) throw new ReleaseError(`${cmd.join(" ")} exited ${code}`)
}

// Not yet linux-x64-musl and linux-arm64-musl, which build.ts makes: a mehen
// from before release-client.ts accepted their names refuses a manifest that
// lists them, so they join once no active machine runs one
// (docs/OPERATIONS.md, "The musl builds").
export const TARGETS = ["darwin-arm64", "darwin-x64", "linux-x64", "linux-arm64"] as const
export type ReleaseArgs = { out: string; upload: boolean; uploadScript?: string; targets: string[]; partial: boolean; allowDirty: boolean; baseUrl: string; bucket: string; key: string | null; unsigned: boolean; release: boolean }
export function releaseBinaries(targets: string[]): readonly ReleaseBinary[] {
  return RELEASE_BINARIES.filter(b => targets.includes(b.name.slice(6)) || (b.name === "mehen-se" && targets.some(t => t.startsWith("darwin-"))))
}

export function parseReleaseArgs(argv: string[]): ReleaseArgs {
  let out: string | null = null
  const targets: string[] = []
  let partial = false
  let uploadScript: string | undefined
  let upload = false
  let allowDirty = false
  let baseUrl = DEFAULT_BASE_URL
  let bucket = DEFAULT_BUCKET
  let key: string | null = null
  let unsigned = false
  let release = false
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    const value = () => {
      const v = argv[++i]
      if (!v) throw new ReleaseError(`${arg} needs a value`)
      return v
    }
    if (arg === "--out") out = value()
    else if (arg === "--upload") upload = true
    else if (arg === "--upload-script") uploadScript = resolve(value())
    else if (arg === "--partial") partial = true
    else if (arg === "--target") {
      const target = value()
      if (!(TARGETS as readonly string[]).includes(target)) throw new ReleaseError(`--target must be one of ${TARGETS.join(", ")}`)
      if (!targets.includes(target)) targets.push(target)
    }
    else if (arg === "--allow-dirty") allowDirty = true
    else if (arg === "--base-url") baseUrl = value()
    else if (arg === "--bucket") bucket = value()
    else if (arg === "--key") key = value()
    else if (arg === "--unsigned") unsigned = true
    else if (arg === "--release") release = true
    else throw new ReleaseError(`unknown argument ${arg}. Usage: bun tools/release/release.ts --out <dir> [--release] [--key <id> | --unsigned] [--upload] [--upload-script <path>] [--target <target>]... [--partial] [--allow-dirty] [--base-url <url>] [--bucket <name>]`)
  }
  if (!out) throw new ReleaseError("--out <dir> is required")
  if (!/^https:\/\/[^/]+(\/.*)?$/.test(baseUrl)) throw new ReleaseError("--base-url must be an https URL")
  if ((upload || uploadScript) && !release) throw new ReleaseError("--upload and --upload-script write commands that publish to the release bucket, so they need --release. A trial build writes the tree without them.")
  if (targets.length && targets.length < TARGETS.length && (upload || uploadScript) && !partial) throw new ReleaseError("A partial target set needs --partial before --upload or --upload-script.")
  if (unsigned && !(allowDirty || partial)) throw new ReleaseError("--unsigned is for a trial build only and needs --allow-dirty or --partial: a public release is always signed.")
  if (unsigned && key) throw new ReleaseError("--unsigned and --key contradict each other.")
  if (release && unsigned) throw new ReleaseError("--release is always signed; --unsigned is for a trial build.")
  if (release && allowDirty) throw new ReleaseError("--release needs a clean tree, so --allow-dirty is for a trial build only.")
  return { out: resolve(out), upload, uploadScript, targets: targets.length ? targets : [...TARGETS], partial, allowDirty, baseUrl, bucket, key, unsigned, release }
}

// Runs a command against built output and captures it; injectable so the
// tests can stand in for codesign and real binaries.
export type Inspector = (cmd: string[]) => Promise<{ code: number; stdout: string; stderr: string }>

export const inspectCommand: Inspector = async (cmd) => {
  const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe", timeout: 60_000 })
  const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
  return { code, stdout: stdout.trim(), stderr: stderr.trim() }
}

export function hostTarget(): string {
  return `${process.platform}-${process.arch === "arm64" ? "arm64" : "x64"}`
}

// The binary for this machine, run once: it must exit 0 and print the
// version, commit, build kind and helper the release claims, or the manifest
// would describe something else.
export async function checkHostBinary(expected: { version: string; commit: string; build: "release" | "dev"; helper: "embedded" | "none" }, dist: string, inspect: Inspector = inspectCommand): Promise<void> {
  const name = `mehen-${hostTarget()}`
  const { code, stdout, stderr } = await inspect([join(dist, name), "version", "--json"])
  if (code !== 0) throw new ReleaseError(`${name} version --json exited ${code}${stderr ? `: ${stderr.split("\n")[0]}` : ""}`)
  let printed: Record<string, unknown> | null = null
  try {
    const value: unknown = JSON.parse(stdout)
    if (value && typeof value === "object" && !Array.isArray(value)) printed = value as Record<string, unknown>
  } catch {
    printed = null
  }
  const fields = Object.keys(expected) as (keyof typeof expected)[]
  const matches = printed !== null && Object.keys(printed).length === fields.length && fields.every((field) => printed[field] === expected[field])
  if (!matches) throw new ReleaseError(`${name} version --json printed ${stdout || "nothing"}, expected ${JSON.stringify(expected)}`)
}

// Every darwin binary must carry a valid ad hoc signature, and the host's
// darwin binary must hand out its embedded helper as a signed file that
// runs and is byte for byte dist/mehen-se.
export async function checkDarwinBinaries(dist: string, targets: readonly string[], inspect: Inspector = inspectCommand): Promise<void> {
  for (const target of targets.filter((t) => t.startsWith("darwin-"))) {
    const binary = join(dist, `mehen-${target}`)
    const verified = await inspect(["codesign", "--verify", "--strict", binary])
    if (verified.code !== 0) throw new ReleaseError(`codesign --verify refused ${binary}: ${verified.stderr || `exit ${verified.code}`}`)
  }
  if (!targets.includes(hostTarget()) || !hostTarget().startsWith("darwin-")) return
  const binary = join(dist, `mehen-${hostTarget()}`)
  const work = await mkdtemp(join(tmpdir(), "mehen-release-helper-"))
  try {
    const expected = join(work, "mehen-se")
    const extracted = await inspect([binary, "version", "--extract-helper", work])
    if (extracted.code !== 0 || extracted.stdout !== expected) throw new ReleaseError(`${binary} version --extract-helper did not extract its helper: ${extracted.stderr || extracted.stdout || `exit ${extracted.code}`}`)
    const verified = await inspect(["codesign", "--verify", "--strict", expected])
    if (verified.code !== 0) throw new ReleaseError(`The helper embedded in ${binary} fails codesign --verify: ${verified.stderr || `exit ${verified.code}`}`)
    const available = await inspect([expected, "available"])
    if (available.code !== 0) throw new ReleaseError(`The helper embedded in ${binary} does not run on this Mac (available exited ${available.code}).`)
    if (sha256(new Uint8Array(await readFile(expected))) !== sha256(new Uint8Array(await readFile(join(dist, "mehen-se"))))) throw new ReleaseError(`The helper embedded in ${binary} is not dist/mehen-se.`)
  } finally {
    await rm(work, { recursive: true, force: true })
  }
}

// The key the release is signed with, resolved before anything is built so
// a release that could not be signed never starts: --key, or the only key in
// the trusted set; its sidecar must agree with that set (sign.ts).
export async function releaseSigningKey(args: ReleaseArgs, trusted: readonly ReleaseKey[], keyDir: string): Promise<{ key: ReleaseKey; blob: string }> {
  if (trusted.length === 0) throw new SigningError("RELEASE_KEYS in packages/protocol/src/release-keys.ts is empty, so no client could verify this release. Add the release key in its own reviewed commit first, or build a trial with --unsigned and --allow-dirty or --partial.")
  const id = args.key ?? (trusted.length === 1 ? trusted[0]!.id : null)
  if (!id) throw new SigningError(`RELEASE_KEYS holds ${trusted.length} keys; name the signing key with --key <id>.`)
  const signing = await readSigningKey(keyDir, id)
  trustedEntry(signing.key, trusted)
  return signing
}

// SHA256SUMS and mehen.rb for a release, beside its tree.
export async function writeGithubFiles(out: string, manifest: ReleaseManifestFile): Promise<void> {
  const dir = githubDir(out, manifest.version)
  const formula = homebrewFormula(manifest)
  await mkdir(dir, { recursive: true })
  await writeFile(join(dir, "SHA256SUMS"), await checksums(out, manifest))
  await writeFile(join(dir, "mehen.rb"), formula)
}

export type ReleaseOptions = { trusted?: readonly ReleaseKey[]; keyDir?: string; signer?: (key: { key: ReleaseKey; blob: string }) => ManifestSigner; inspect?: Inspector; treeClean?: () => boolean }

export async function main(argv: string[], build: (cmd: string[]) => Promise<void> = spawnChecked, dist = DIST, options: ReleaseOptions = {}): Promise<void> {
  const args = parseReleaseArgs(argv)
  if (process.platform !== "darwin") throw new ReleaseError("A release includes mehen-se, the Secure Enclave helper, which builds on macOS only. Run this on a Mac.")
  const trusted = options.trusted ?? RELEASE_KEYS
  const signing = args.unsigned ? null : await releaseSigningKey(args, trusted, options.keyDir ?? releaseKeyDir(process.env))
  const version = await cliVersion()
  if (await exists(join(args.out, `v${version}`))) throw new ReleaseError(`${join(args.out, `v${version}`)} already exists: version ${version} was released. Bump "version" in apps/cli/package.json.`)
  const clean = options.treeClean ? options.treeClean() : git(["status", "--porcelain"]).trim() === ""
  if (!clean && !args.allowDirty) throw new ReleaseError("The working tree has uncommitted changes, so the commit would not say what was built. Commit them, or pass --allow-dirty for a trial build.")
  const commit = git(["rev-parse", "--short=7", "HEAD"]).trim()
  const fullCommit = git(["rev-parse", "HEAD"]).trim()
  const binaries = releaseBinaries(args.targets)
  await build([process.execPath, join(CLI_DIR, "scripts", "build.ts"), "--commit", commit, ...(args.release ? ["--release"] : []), ...args.targets.flatMap(t => ["--target", t]), ...(args.targets.some(t => t.startsWith("darwin-")) ? [] : ["--no-mehen-se"])])
  const inspect = options.inspect ?? inspectCommand
  if (args.targets.includes(hostTarget())) await checkHostBinary({ version, commit, build: args.release ? "release" : "dev", helper: hostTarget().startsWith("darwin-") ? "embedded" : "none" }, dist, inspect)
  await checkDarwinBinaries(dist, args.targets, inspect)
  const notarised = await notarise(dist, process.env, spawnChecked, binaries)
  console.error(notarised.notarised ? `notarised ${notarised.files.length} macOS binaries` : notarised.reason)
  const signer = signing ? (options.signer ?? ((key) => helperSigner(process.env.MEHEN_SE_PATH || join(dist, "mehen-se"), key)))(signing) : null
  const sign = signing && signer ? (manifest: Manifest) => signManifest(manifest, signing.key, signer, trusted) : undefined
  const manifest = await assembleRelease({ dist, binaries, out: args.out, version, commit, builtAt: new Date().toISOString(), baseUrl: args.baseUrl, sign })
  // A partial release has no full set to mirror or a formula to write.
  const mirror = !args.partial && args.baseUrl === DEFAULT_BASE_URL && args.bucket === DEFAULT_BUCKET
  if (mirror) await writeGithubFiles(args.out, manifest)
  console.error(JSON.stringify({ released: version, commit, out: join(args.out, `v${version}`), files: manifest.files.length, signedBy: signing?.key.id ?? null }))
  const script = ["set -eu", ...(args.partial ? [`# PARTIAL release: latest.json will list only ${args.targets.join(", ")}. Do not run this for a public release.`] : []), `# Upload v${version} to R2 from apps/web, in this order (latest.json last):`, "cd apps/web", ...uploadCommands(args.out, manifest, args.bucket).map(c => `bunx ${c}`), ...(mirror ? ["cd ../..", "", ...githubCommands(args.out, manifest, fullCommit)] : []), ""].join("\n")
  if (args.upload) process.stdout.write(script)
  if (args.uploadScript) await writeFile(args.uploadScript, script, { mode: 0o600 })
}

if (import.meta.main) {
  try {
    await main(process.argv.slice(2))
  } catch (error) {
    console.error(`release: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }
}
