import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import { installedPath, installUrl, isNative, run, unsupported } from "./lib.mjs"

let dir: string
beforeEach(() => {
  dir = mkdtempSync(join(process.env.TMPDIR && process.env.TMPDIR !== "/tmp" ? tmpdir() : join(homedir(), ".cache"), "mehen-npm-"))
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

const env = (extra: Record<string, string>) => ({ PATH: process.env.PATH ?? "", HOME: dir, ...extra })

describe("where and what", () => {
  test("the installer's folder: MEHEN_INSTALL_DIR, else ~/.local/bin", () => {
    expect(installedPath({ HOME: "/home/a" })).toBe("/home/a/.local/bin/mehen")
    expect(installedPath({ HOME: "/home/a", MEHEN_INSTALL_DIR: "/opt/bin" })).toBe("/opt/bin/mehen")
  })

  test("macOS and Linux on x64 and arm64 only", () => {
    expect(unsupported("darwin", "arm64")).toBeNull()
    expect(unsupported("linux", "x64")).toBeNull()
    expect(unsupported("win32", "x64")).toContain("WSL")
    expect(unsupported("linux", "ia32")).toContain("not ia32")
  })

  test("a native program is told from a script", () => {
    writeFileSync(join(dir, "elf"), Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1]))
    writeFileSync(join(dir, "macho"), Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 7, 0]))
    writeFileSync(join(dir, "script"), "#!/usr/bin/env node\n")
    expect([isNative(join(dir, "elf")), isNative(join(dir, "macho")), isNative(join(dir, "script")), isNative(join(dir, "missing"))]).toEqual([true, true, false, false])
  })

  test("the installer comes over https, or loopback http for tests", () => {
    expect(installUrl({})).toBe("https://mehen.dev/install")
    expect(installUrl({ MEHEN_INSTALL_URL: "http://127.0.0.1:9999/install" })).toBe("http://127.0.0.1:9999/install")
    expect(() => installUrl({ MEHEN_INSTALL_URL: "http://evil.example/install" })).toThrow(/https/)
  })
})

describe("run", () => {
  test("runs the installed mehen with the arguments and returns its exit code", async () => {
    symlinkSync(realpathSync(Bun.which("sh")!), join(dir, "mehen"))
    expect(await run(["-c", "exit 7"], env({ MEHEN_INSTALL_DIR: dir }))).toBe(7)
  })

  test("refuses a mehen in the install folder that is not the program, and installs nothing", async () => {
    writeFileSync(join(dir, "mehen"), "#!/usr/bin/env node\n")
    chmodSync(join(dir, "mehen"), 0o755)
    expect(await run(["up"], env({ MEHEN_INSTALL_DIR: dir, MEHEN_INSTALL_URL: "http://127.0.0.1:1/never" }))).toBe(1)
  })

  test("with no mehen, fetches the installer, runs it with --yes, then runs what it installed", async () => {
    const native = realpathSync(Bun.which("sh")!)
    const installer = `#!/bin/sh\nprintf '%s' "$*" > "${dir}/installer-args"\nln -s "${native}" "$MEHEN_INSTALL_DIR/mehen"\n`
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response(installer, { headers: { "content-type": "text/plain" } }) })
    try {
      const code = await run(["-c", "exit 3"], env({ MEHEN_INSTALL_DIR: dir, MEHEN_INSTALL_URL: `http://127.0.0.1:${server.port}/install` }))
      expect(code).toBe(3)
      expect(readFileSync(join(dir, "installer-args"), "utf8")).toBe("--yes")
    } finally {
      server.stop(true)
    }
  })

  test("an installer that fails stops the run with its message and runs nothing", async () => {
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("#!/bin/sh\nexit 2\n") })
    try {
      expect(await run(["up"], env({ MEHEN_INSTALL_DIR: dir, MEHEN_INSTALL_URL: `http://127.0.0.1:${server.port}/install` }))).toBe(1)
      expect(existsSync(join(dir, "mehen"))).toBe(false)
    } finally {
      server.stop(true)
    }
  })

  test("an installer the server will not give is refused", async () => {
    const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("no", { status: 404 }) })
    try {
      expect(await run(["up"], env({ MEHEN_INSTALL_DIR: dir, MEHEN_INSTALL_URL: `http://127.0.0.1:${server.port}/install` }))).toBe(1)
    } finally {
      server.stop(true)
    }
  })
})

test("both packages carry the CLI's version, and create-mehen depends on exactly this launcher", async () => {
  const cli = (await Bun.file(join(import.meta.dir, "../../../apps/cli/package.json")).json()) as { version: string }
  const launcher = (await Bun.file(join(import.meta.dir, "package.json")).json()) as { version: string }
  const create = (await Bun.file(join(import.meta.dir, "../create-mehen/package.json")).json()) as { version: string; dependencies: Record<string, string> }
  expect([launcher.version, create.version, create.dependencies["@mehenai/cli"]]).toEqual([cli.version, cli.version, cli.version])
})
