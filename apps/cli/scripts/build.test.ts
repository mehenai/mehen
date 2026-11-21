import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { copyFile, mkdtemp, readFile, rm, stat } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { BuildError, CLI_DIR, CLI_IDENTIFIER, GENERATED_HELPER_MODULE, TARGETS, type Target, buildTargets, embeddedHelperModule, helperPlan, parseBuildArgs } from "./build.ts"

const generatedExists = () => Bun.file(GENERATED_HELPER_MODULE).exists()

describe("parseBuildArgs", () => {
  test("every target by default; repeatable targets, --no-mehen-se, --release and --commit", () => {
    expect(parseBuildArgs([])).toEqual({ targets: [...TARGETS], mehenSe: true, release: false, commit: null })
    expect(parseBuildArgs(["--target", "linux-x64", "--target", "linux-x64", "--target", "darwin-arm64", "--no-mehen-se", "--release", "--commit", "a53a3de"])).toEqual({ targets: ["linux-x64", "darwin-arm64"], mehenSe: false, release: true, commit: "a53a3de" })
    expect(TARGETS).toEqual(["darwin-arm64", "darwin-x64", "linux-x64", "linux-arm64", "linux-x64-musl", "linux-arm64-musl"])
    expect(parseBuildArgs(["--target", "linux-x64-musl"]).targets).toEqual(["linux-x64-musl"])
    for (const argv of [["--target", "windows-x64"], ["--target", "darwin-arm64-musl"], ["--target"], ["--commit", "HEAD"], ["--sign"]]) expect(() => parseBuildArgs(argv)).toThrow(BuildError)
  })
})

describe("helperPlan", () => {
  const darwinHost = { platform: "darwin" as const, clean: true }
  test("the helper is built on macOS when a darwin target is asked for", () => {
    expect(helperPlan(parseBuildArgs([]), darwinHost)).toEqual({ buildHelper: true })
    expect(helperPlan(parseBuildArgs(["--target", "linux-x64"]), darwinHost)).toEqual({ buildHelper: false })
    expect(helperPlan(parseBuildArgs(["--no-mehen-se"]), darwinHost)).toEqual({ buildHelper: false })
    expect(helperPlan(parseBuildArgs([]), { platform: "linux", clean: true })).toEqual({ buildHelper: false })
  })

  test("a dev build of a darwin target may go without the helper; --release refuses it", () => {
    expect(helperPlan(parseBuildArgs(["--target", "darwin-arm64", "--no-mehen-se"]), darwinHost)).toEqual({ buildHelper: false })
    expect(() => helperPlan(parseBuildArgs(["--target", "darwin-arm64", "--no-mehen-se", "--release"]), darwinHost)).toThrow("embeds the mehen-se helper")
    expect(() => helperPlan(parseBuildArgs(["--release"]), { platform: "linux", clean: true })).toThrow("builds on macOS only")
    expect(helperPlan(parseBuildArgs(["--target", "linux-x64", "--target", "linux-arm64", "--no-mehen-se", "--release"]), { platform: "linux", clean: true })).toEqual({ buildHelper: false })
  })

  test("--release refuses a dirty tree", () => {
    expect(() => helperPlan(parseBuildArgs(["--release"]), { platform: "darwin", clean: false })).toThrow("needs a clean tree")
    expect(helperPlan(parseBuildArgs([]), { platform: "darwin", clean: false })).toEqual({ buildHelper: true })
  })
})

describe("embeddedHelperModule", () => {
  test("darwin embeds the built helper as a file; linux, or no helper, is null", () => {
    const darwin = embeddedHelperModule("darwin-arm64", "/repo/apps/cli/native/mehen-se/build/mehen-se")
    expect(darwin).toContain('import helper from "/repo/apps/cli/native/mehen-se/build/mehen-se" with { type: "file" }')
    expect(darwin).toContain("export const EMBEDDED_HELPER: string | null = helper")
    for (const [target, helper] of [["linux-x64", "/repo/helper"], ["linux-arm64", "/repo/helper"], ["darwin-x64", null]] as const) {
      const module = embeddedHelperModule(target, helper)
      expect(module).toContain("export const EMBEDDED_HELPER: string | null = null")
      expect(module).not.toContain("import")
    }
  })
})

describe("buildTargets", () => {
  test("writes the right module before each target, re-signs darwin on macOS, and removes the module afterwards", async () => {
    const dist = await mkdtemp(join(tmpdir(), "mehen-build-"))
    const seen: { cmd: string[]; module: string | null }[] = []
    const run = async (cmd: string[], cwd: string) => {
      expect(cwd).toBe(CLI_DIR)
      seen.push({ cmd, module: cmd[1] === "build" ? await readFile(GENERATED_HELPER_MODULE, "utf8") : null })
    }
    const targets: Target[] = ["darwin-arm64", "linux-x64", "darwin-x64", "linux-arm64-musl"]
    const built = await buildTargets({ targets, release: true, commit: "a53a3de", helper: "/abs/mehen-se", dist, platform: "darwin", run })
    expect(built).toEqual(targets.map((t) => join(dist, `mehen-${t}`)))
    expect(seen.map((s) => s.cmd[0] === "codesign" ? `sign ${s.cmd.at(-1)}` : `build ${s.cmd.find((a) => a.startsWith("--target="))}`)).toEqual([
      "build --target=bun-darwin-arm64", `sign ${join(dist, "mehen-darwin-arm64")}`,
      "build --target=bun-linux-x64",
      "build --target=bun-darwin-x64", `sign ${join(dist, "mehen-darwin-x64")}`,
      "build --target=bun-linux-arm64-musl",
    ])
    const builds = seen.filter((s) => s.cmd[1] === "build")
    expect(builds[0]!.module).toBe(embeddedHelperModule("darwin-arm64", "/abs/mehen-se"))
    expect(builds[1]!.module).toBe(embeddedHelperModule("linux-x64", "/abs/mehen-se"))
    expect(builds[1]!.module).toContain("= null")
    for (const b of builds) expect(b.cmd).toEqual(expect.arrayContaining(['--define=MEHEN_BUILD_COMMIT="a53a3de"', '--define=MEHEN_BUILD_KIND="release"']))
    // Each binary knows the target it is, so a musl one updates to musl.
    expect(builds.map((b) => b.cmd.find((a) => a.startsWith("--define=MEHEN_BUILD_TARGET=")))).toEqual(targets.map((t) => `--define=MEHEN_BUILD_TARGET="${t}"`))
    expect(builds[3]!.module).toContain("= null")
    expect(seen.find((s) => s.cmd[0] === "codesign")!.cmd).toEqual(["codesign", "--force", "--sign", "-", "--identifier", CLI_IDENTIFIER, join(dist, "mehen-darwin-arm64")])
    expect(await generatedExists()).toBe(false)
    await rm(dist, { recursive: true, force: true })
  })

  test("a dev build is stamped dev; off macOS nothing is re-signed; a failed bundle still removes the module", async () => {
    const dist = await mkdtemp(join(tmpdir(), "mehen-build-"))
    const cmds: string[][] = []
    await buildTargets({ targets: ["darwin-arm64"], release: false, commit: "a53a3de", helper: null, dist, platform: "linux", run: async (cmd) => void cmds.push(cmd) })
    expect(cmds).toHaveLength(1)
    expect(cmds[0]).toContain('--define=MEHEN_BUILD_KIND="dev"')
    await expect(buildTargets({ targets: ["linux-x64"], release: false, commit: "a53a3de", helper: null, dist, platform: "linux", run: async () => { expect(await generatedExists()).toBe(true); throw new Error("bundle failed") } })).rejects.toThrow("bundle failed")
    expect(await generatedExists()).toBe(false)
    await rm(dist, { recursive: true, force: true })
  })
})

// The adapter end to end on a Mac: a real helper built from the repository's
// source into a temp directory, one darwin binary compiled with it, then
// the release checks `version --extract-helper` and `codesign --verify`
// make. `available` only asks whether the Secure Enclave can be used; no
// key is made. Skipped where the helper cannot be built.
const host = process.platform === "darwin" && process.arch === "arm64" && Bun.which("swiftc") ? ("darwin-arm64" as const) : null
describe.skipIf(host === null)("a darwin build with the embedded helper", () => {
  let work = ""
  let helper = ""
  beforeAll(async () => {
    work = await mkdtemp(join(tmpdir(), "mehen-build-se-"))
    const native = join(CLI_DIR, "native", "mehen-se")
    await copyFile(join(native, "mehen-se.swift"), join(work, "mehen-se.swift"))
    await copyFile(join(native, "build.sh"), join(work, "build.sh"))
    const build = Bun.spawn(["bash", join(work, "build.sh"), "--native"], { stdout: "pipe", stderr: "pipe", timeout: 240_000 })
    const [code, err] = await Promise.all([build.exited, new Response(build.stderr).text()])
    if (code !== 0) throw new Error(`mehen-se build failed: ${err}`)
    helper = join(work, "build", "mehen-se")
  }, 300_000)
  afterAll(async () => {
    if (work) await rm(work, { recursive: true, force: true })
  })

  test("embeds, stamps, extracts a helper that is signed and runs, and leaves no generated module", async () => {
    const dist = join(work, "dist")
    const run = async (cmd: string[], cwd: string) => {
      const proc = Bun.spawn(cmd, { cwd, stdout: "pipe", stderr: "pipe" })
      const [code, err] = await Promise.all([proc.exited, new Response(proc.stderr).text()])
      if (code !== 0) throw new Error(`${cmd.join(" ")} exited ${code}: ${err}`)
    }
    const [binary] = await buildTargets({ targets: [host!], release: true, commit: "a53a3de", helper, dist, run })
    expect(await generatedExists()).toBe(false)
    const exec = (args: string[]) => {
      const result = Bun.spawnSync([binary!, ...args], { stdout: "pipe", stderr: "pipe", env: { HOME: work, PATH: process.env.PATH } })
      return { code: result.exitCode, stdout: result.stdout.toString().trim(), stderr: result.stderr.toString() }
    }
    const pkg = (await Bun.file(join(CLI_DIR, "package.json")).json()) as { version: string }
    expect(JSON.parse(exec(["version", "--json"]).stdout)).toEqual({ version: pkg.version, commit: "a53a3de", build: "release", helper: "embedded" })
    const out = join(work, "extract")
    const extracted = exec(["version", "--extract-helper", out])
    expect(extracted.code).toBe(0)
    expect(extracted.stdout).toBe(join(out, "mehen-se"))
    expect(await Bun.file(extracted.stdout).bytes()).toEqual(await Bun.file(helper).bytes())
    expect((await stat(extracted.stdout)).mode & 0o777).toBe(0o755)
    expect(Bun.spawnSync(["codesign", "--verify", "--strict", extracted.stdout]).exitCode).toBe(0)
    expect(Bun.spawnSync(["codesign", "--verify", "--strict", binary!]).exitCode).toBe(0)
    expect(Bun.spawnSync(["codesign", "--display", "--verbose=2", binary!], { stderr: "pipe" }).stderr.toString()).toContain(`Identifier=${CLI_IDENTIFIER}`)
    // It runs (macOS kills a binary whose signature broke in transit); 0 where the enclave is usable, 1 on a Mac without one.
    const available = Bun.spawnSync([extracted.stdout, "available"])
    expect(available.signalCode ?? null).toBeNull()
    expect([0, 1]).toContain(available.exitCode)
  }, 120_000)
})

test("a source checkout has no generated module", async () => {
  expect(await generatedExists()).toBe(false)
})
