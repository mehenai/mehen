import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { canonicalJson } from "../../../packages/protocol/src/canonical-json.ts"
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

  // The real installer, served as mehen.dev serves it, with a release
  // signed by a test key it trusts only on loopback: verified, installed,
  // then run; and a manifest changed after signing installs nothing.
  async function realRelease(tampered: boolean) {
    const native = new Uint8Array(readFileSync(realpathSync(Bun.which("true")!)))
    const gz = Bun.gzipSync(native)
    const sha = (b: Uint8Array) => new Bun.CryptoHasher("sha256").update(b).digest("hex")
    const key = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair
    const spki = Buffer.from(await crypto.subtle.exportKey("spki", key.publicKey)).toString("base64")
    const os = process.platform === "darwin" ? "darwin" : "linux"
    const files = ["arm64", "x64"].map((arch) => ({ name: `mehen-${os}-${arch}`, os, arch, url: `https://mehen.dev/dl/v9.9.9/mehen-${os}-${arch}.gz`, sha256: sha(native), size: native.length, gzSha256: sha(gz), gzSize: gz.length }))
    const unsigned = { version: "9.9.9", commit: "c0ffee0", builtAt: "2026-11-19T00:00:00.000Z", files }
    const signature = Buffer.from(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, new TextEncoder().encode(canonicalJson(unsigned)))).toString("base64url")
    const served = tampered ? { ...unsigned, commit: "deadbee" } : unsigned
    const manifest = JSON.stringify({ ...served, signatures: [{ keyId: "rk-test", alg: "ES256", signature }] }, null, 2)
    // In a process of its own: the launcher runs the installer with
    // spawnSync, which would hold up a server in this one.
    writeFileSync(join(dir, "manifest.json"), manifest)
    writeFileSync(join(dir, "binary.gz"), gz)
    const log = join(dir, "asked.log")
    const serverScript = join(dir, "server.ts")
    const installer = join(import.meta.dir, "../../../tools/release/install.sh")
    writeFileSync(serverScript, [
      'import { appendFileSync, readFileSync } from "node:fs"',
      "const server = Bun.serve({ port: 0, hostname: \"127.0.0.1\", fetch: (request) => {",
      "  const path = new URL(request.url).pathname",
      `  appendFileSync(${JSON.stringify(log)}, path + "\\n")`,
      `  const file = path === "/install" ? ${JSON.stringify(installer)} : path.endsWith(".json") ? ${JSON.stringify(join(dir, "manifest.json"))} : ${JSON.stringify(join(dir, "binary.gz"))}`,
      "  return new Response(readFileSync(file))",
      "} })",
      "console.log(server.port)",
      "",
    ].join("\n"))
    const proc = Bun.spawn([process.execPath, serverScript], { stdout: "pipe", stderr: "inherit" })
    const port = new TextDecoder().decode((await proc.stdout.getReader().read()).value).trim()
    const server = { stop: () => proc.kill() }
    const asked = () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : [])
    const base = `http://127.0.0.1:${port}`
    return { server, asked, env: env({ MEHEN_INSTALL_DIR: join(dir, "bin"), MEHEN_INSTALL_URL: `${base}/install`, MEHEN_DL_BASE: base, MEHEN_INSTALL_TEST_RELEASE_KEY: `rk-test ${spki}`, MEHEN_NO_RC: "1", SHELL: "/bin/sh" }) }
  }

  test("runs the real installer, which verifies the signed release before installing what it then runs", async () => {
    const release = await realRelease(false)
    try {
      expect(await run([], release.env)).toBe(0)
      expect(isNative(join(dir, "bin", "mehen"))).toBe(true)
      expect(release.asked().some((p) => p.endsWith(".gz"))).toBe(true)
    } finally {
      release.server.stop()
    }
  })

  test("with the real installer, a release changed after signing installs and runs nothing", async () => {
    const release = await realRelease(true)
    try {
      expect(await run([], release.env)).toBe(1)
      expect(existsSync(join(dir, "bin", "mehen"))).toBe(false)
      expect(release.asked().some((p) => p.endsWith(".gz"))).toBe(false)
    } finally {
      release.server.stop()
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
