import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { realpathSync } from "node:fs"
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, symlink, utimes, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

// Every run gets a private temporary HOME and install directory and a
// minimal environment: the real HOME, ZDOTDIR and shell files are never
// visible to the script under test.
let root: string
let server: ReturnType<typeof Bun.serve>
let mode = "ok"
let delay = 0
let requests: string[] = []
let raw = new TextEncoder().encode("#!/bin/sh\necho mehen fixture\n")
let gz = Bun.gzipSync(raw)
const hash = (b: Uint8Array) => createHash("sha256").update(b).digest("hex")
const shells = ["sh", ...(Bun.which("dash") ? ["dash"] : [])]
beforeEach(async () => {
  root = realpathSync(await mkdtemp(join(tmpdir(), "mehen-install-")))
  await chmod(root, 0o700)
  mode = "ok"
  delay = 0
  requests = []
  raw = new TextEncoder().encode("#!/bin/sh\necho mehen fixture\n")
  gz = Bun.gzipSync(raw)
  server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(req) {
    const path = new URL(req.url).pathname
    requests.push(path)
    if (mode === "manifest-http") return new Response("No", { status: 404 })
    if (path.endsWith(".json") && mode === "null") return new Response("null")
    if (path.endsWith(".json") && mode === "escaped") return new Response('{"version":"1.2.\\u0033"}')
    if (!path.endsWith(".json") && mode === "binary-http") return new Response("No", { status: 404 })
    if (path.endsWith(".json")) return Response.json({ version: "1.2.3", commit: "a53a3de", builtAt: "2026-10-27", files: ["mehen-linux-x64", "mehen-linux-arm64", "mehen-darwin-arm64", "mehen-darwin-x64", "mehen-se"].map(name => ({ name, os: name.includes("linux") ? "linux" : "darwin", arch: "arm64", url: `https://mehen.dev/dl/v1.2.3/${name}.gz`, sha256: mode === "invalid-checksum" ? "bad" : mode === "raw" ? "0".repeat(64) : hash(raw), size: mode === "empty-size" ? "" : mode === "bad-size" ? "2x" : raw.length, gzSha256: mode === "checksum" ? "0".repeat(64) : hash(gz), gzSize: mode === "empty-gzsize" ? "" : gz.length })), signatures: [{ keyId: "rk-test", alg: "ES256", signature: "A".repeat(86) }] })
    if (delay) await Bun.sleep(delay)
    return new Response(mode === "truncated" ? gz.slice(0, 8) : gz)
  } })
})
afterEach(async () => { server.stop(true); await rm(root, { recursive: true, force: true }) })
async function run(shell = "sh", env: Record<string, string> = {}, args: string[] = []) {
  const proc = Bun.spawn([Bun.which(shell)!, resolve(import.meta.dir, "install.sh"), ...args], { env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: root, SHELL: "/bin/sh", MEHEN_INSTALL_DIR: join(root, "bin"), MEHEN_DL_BASE: `http://127.0.0.1:${server.port}`, ...env }, stdout: "pipe", stderr: "pipe" })
  const stdout = await new Response(proc.stdout).text()
  const stderr = await new Response(proc.stderr).text()
  return { code: await proc.exited, stdout, stderr }
}
type Receipt = { v: 1; result: string; version: string | null; path: string; onPath: boolean; env: string | null; rc: { written: string[]; unchanged: string[]; skipped: { path: string; reason: string }[]; advice: string | null } }
function receipt(stdout: string): Receipt {
  const line = stdout.trim().split("\n").at(-1) ?? ""
  expect(line.startsWith("mehen-install: ")).toBe(true)
  return JSON.parse(line.slice("mehen-install: ".length)) as Receipt
}
const bin = () => join(root, "bin")
const left = async () => (await readdir(bin()).catch(() => [] as string[])).filter((n) => n.startsWith(".mehen-update.") || n === ".mehen.update.lock")

for (const shell of shells) {
  test(`${shell}: installs; a second run over the verified install is already-installed and downloads nothing; quiet prints only the receipt`, async () => {
    const first = await run(shell, { MEHEN_VERSION: "1.2.3" })
    expect(first.code).toBe(0)
    expect(first.stdout).toContain("Next: mehen up")
    expect(first.stdout).toContain("PATH:")
    expect(await readFile(join(bin(), "mehen"))).toEqual(Buffer.from(raw))
    expect(await readFile(join(bin(), ".mehen.sha256"), "utf8")).toBe(`${hash(raw)}\n`)
    expect(receipt(first.stdout)).toMatchObject({ v: 1, result: "installed", version: "1.2.3", path: join(bin(), "mehen"), onPath: false })
    requests = []
    const second = await run(shell, { MEHEN_QUIET: "1" })
    expect(second.code).toBe(0)
    expect(second.stdout.trim().split("\n")).toHaveLength(1)
    expect(receipt(second.stdout)).toMatchObject({ result: "already-installed", version: null, path: join(bin(), "mehen") })
    expect(requests).toEqual([])
    const loud = await run(shell)
    expect(loud.stdout).toContain(`Already installed: mehen at ${join(bin(), "mehen")}. It keeps itself current; ${join(bin(), "mehen")} update --json brings it to the current release now.`)
    expect(await left()).toEqual([])
  })
  for (const failure of ["checksum", "raw", "truncated"]) test(`${shell}: ${failure} leaves the old binary untouched, even forced, and a fresh directory empty`, async () => {
    mode = failure
    expect((await run(shell)).code).toBe(2)
    expect(await readdir(bin())).toEqual([])
    mode = "ok"
    expect((await run(shell)).code).toBe(0)
    mode = failure
    expect((await run(shell, { MEHEN_FORCE: "1" })).code).toBe(2)
    expect(await readFile(join(bin(), "mehen"))).toEqual(Buffer.from(raw))
    expect(await left()).toEqual([])
  })
  test(`${shell}: refuses a foreign target unless forced`, async () => {
    await run(shell)
    await writeFile(join(bin(), "mehen"), "foreign")
    const refused = await run(shell)
    expect(refused.code).toBe(2)
    expect(refused.stderr).toContain("not a verified Mehen install")
    expect(await readFile(join(bin(), "mehen"), "utf8")).toBe("foreign")
    const forced = await run(shell, { MEHEN_FORCE: "1" })
    expect(forced.code).toBe(0)
    expect(receipt(forced.stdout).result).toBe("forced")
    expect(await readFile(join(bin(), ".mehen.previous"), "utf8")).toBe("foreign")
  })
  test(`${shell}: --force replaces a verified install and says forced; the old binary becomes .mehen.previous`, async () => {
    await run(shell)
    const before = new Uint8Array(raw)
    raw = new TextEncoder().encode("#!/bin/sh\necho newer fixture\n")
    gz = Bun.gzipSync(raw)
    const forced = await run(shell, {}, ["--force"])
    expect(forced.code).toBe(0)
    expect(receipt(forced.stdout)).toMatchObject({ result: "forced", version: "1.2.3" })
    expect(await readFile(join(bin(), "mehen"))).toEqual(Buffer.from(raw))
    expect(await readFile(join(bin(), ".mehen.previous"))).toEqual(Buffer.from(before))
    // The installer never writes .mehen.previous.json.
    expect(await readdir(bin())).not.toContain(".mehen.previous.json")
  })
  test(`${shell}: refuses unsupported platform and architecture and missing hash tool`, async () => {
    const tools = join(root, "tools")
    await Bun.$`mkdir -p ${tools}`.quiet()
    const uname = join(tools, "uname")
    await writeFile(uname, "#!/bin/sh\necho Windows_NT\n"); await chmod(uname, 0o755)
    expect((await run(shell, { PATH: tools })).stderr).toContain("Unsupported platform")
    await writeFile(uname, '#!/bin/sh\nif [ "$1" = -s ]; then echo Linux; else echo riscv; fi\n')
    expect((await run(shell, { PATH: tools })).stderr).toContain("Unsupported architecture")
    await writeFile(uname, '#!/bin/sh\nif [ "$1" = -s ]; then echo Linux; else echo x86_64; fi\n')
    expect((await run(shell, { PATH: tools })).stderr).toContain("checksum tool is required")
  })
  test(`${shell}: Rosetta installs the arm64 binary, one file, no helper`, async () => {
    const tools = join(root, "tools")
    await Bun.$`mkdir -p ${tools}`.quiet()
    await writeFile(join(tools, "uname"), '#!/bin/sh\nif [ "$1" = -s ]; then echo Darwin; else echo x86_64; fi\n')
    await writeFile(join(tools, "sysctl"), '#!/bin/sh\necho 1\n')
    await chmod(join(tools, "uname"), 0o755); await chmod(join(tools, "sysctl"), 0o755)
    expect((await run(shell, { PATH: `${tools}:${process.env.PATH}` })).code).toBe(0)
    expect(requests.filter((p) => p.endsWith(".gz"))).toEqual(["/v1.2.3/mehen-darwin-arm64.gz"])
    expect(await readdir(bin())).not.toContain("mehen-se")
  })
}

test("installer JSON escapes an install directory containing shell and JSON metacharacters", async () => {
  const path = join(root, "a'b\\c\"d bin")
  const result = await run("sh", { MEHEN_INSTALL_DIR: path, MEHEN_QUIET: "1" })
  expect(result.stderr).toBe("")
  expect(result.code).toBe(0)
  expect(receipt(result.stdout)).toMatchObject({ result: "installed", version: "1.2.3", path: join(path, "mehen"), env: join(path, ".mehen.env") })
  // The env file quotes the directory so a sourcing shell gets it verbatim.
  const sourced = Bun.spawnSync(["/bin/sh", "-c", `. '${join(path, ".mehen.env").replaceAll("'", "'\\''")}'; printf '%s' "$PATH"`], { env: { PATH: "/usr/bin:/bin" } })
  expect(sourced.stdout.toString()).toBe(`${path}:/usr/bin:/bin`)
})
test("a directory target is refused even with force", async () => {
  await mkdir(join(root, "bin/mehen"), { recursive: true })
  expect((await run("sh", { MEHEN_FORCE: "1" })).stderr).toContain("is a directory")
})

for (const shell of shells) {
  test(`${shell}: refuses no curl, unsafe base, bad version and relative destination`, async () => {
    const tools = join(root, "tools")
    await mkdir(tools)
    await writeFile(join(tools, "uname"), '#!/bin/sh\nif [ "$1" = -s ]; then echo Darwin; else echo arm64; fi\n')
    await chmod(join(tools, "uname"), 0o755)
    await symlink(Bun.which("shasum")!, join(tools, "shasum"))
    expect((await run(shell, { PATH: tools })).stderr).toContain("curl is required")
    expect((await run(shell, { MEHEN_DL_BASE: "http://example.com" })).stderr).toContain("must use https")
    expect((await run(shell, { MEHEN_VERSION: "1.0;rm" })).stderr).toContain("Invalid MEHEN_VERSION")
    expect((await run(shell, { MEHEN_VERSION: "1.2.4" })).stderr).toContain("does not match")
    expect((await run(shell, { MEHEN_INSTALL_DIR: "relative" })).stderr).toContain("must be absolute")
    expect((await run(shell, {}, ["--bogus"])).stderr).toContain("Unknown option --bogus")
  })
  for (const [failure, message] of [
    ["null", "Invalid release manifest"], ["escaped", "Invalid release manifest"],
    ["empty-size", "Invalid release size"], ["bad-size", "Invalid release size"], ["empty-gzsize", "Invalid release size"],
    ["invalid-checksum", "Invalid release checksum"], ["manifest-http", "Manifest download failed"], ["binary-http", "Binary download failed"],
  ]) test(`${shell}: ${failure} is a refusal before changing the destination`, async () => {
    expect((await run(shell)).code).toBe(0)
    mode = failure!
    const result = await run(shell, { MEHEN_FORCE: "1" })
    expect(result.code).toBe(2)
    expect(result.stderr).toContain(message!)
    expect(await readFile(join(bin(), "mehen"))).toEqual(Buffer.from(raw))
    expect(await left()).toEqual([])
  })
  test(`${shell}: musl is refused before downloading`, async () => {
    const tools = join(root, "tools")
    await mkdir(tools)
    await writeFile(join(tools, "uname"), '#!/bin/sh\nif [ "$1" = -s ]; then echo Linux; else echo x86_64; fi\n')
    await writeFile(join(tools, "ldd"), '#!/bin/sh\necho "musl libc" >&2\n')
    await writeFile(join(tools, "getconf"), '#!/bin/sh\nexit 1\n')
    for (const name of ["uname", "ldd", "getconf"]) await chmod(join(tools, name), 0o755)
    const result = await run(shell, { PATH: `${tools}:${process.env.PATH}` })
    expect(result.code).toBe(2)
    expect(result.stderr).toContain("musl is not supported")
    expect(await Bun.file(join(root, "bin/mehen")).exists()).toBe(false)
  })
  test(`${shell}: glibc with the musl package installed is not refused`, async () => {
    const tools = join(root, "tools")
    await mkdir(tools)
    await writeFile(join(tools, "uname"), '#!/bin/sh\nif [ "$1" = -s ]; then echo Linux; else echo x86_64; fi\n')
    await writeFile(join(tools, "ldd"), '#!/bin/sh\necho "musl libc" >&2\n')
    await writeFile(join(tools, "getconf"), '#!/bin/sh\n[ "$1" = GNU_LIBC_VERSION ] && echo "glibc 2.39"\n')
    for (const name of ["uname", "ldd", "getconf"]) await chmod(join(tools, name), 0o755)
    const result = await run(shell, { PATH: `${tools}:${process.env.PATH}` })
    expect(result.code).toBe(0)
    expect(result.stderr).not.toContain("musl is not supported")
    expect(await Bun.file(join(root, "bin/mehen")).exists()).toBe(true)
  })
}

// The lock first, the decision under it, two rollback
// branches, the previous pair restored byte for byte.
describe("the lock and rollback", () => {
  for (const shell of shells) {
    test(`${shell}: two installers on an absent directory serialise and leave one binary and one receipt`, async () => {
      delay = 300
      const [a, b] = await Promise.all([run(shell), run(shell)])
      const codes = [a.code, b.code].sort()
      expect(codes[0]).toBe(0)
      expect([0, 2]).toContain(codes[1]!)
      if (codes[1] === 2) expect([a, b].find((r) => r.code === 2)!.stderr).toContain("Another mehen update is running")
      expect(await readFile(join(bin(), "mehen"))).toEqual(Buffer.from(raw))
      expect(await readFile(join(bin(), ".mehen.sha256"), "utf8")).toBe(`${hash(raw)}\n`)
      expect(await left()).toEqual([])
    })

    test(`${shell}: an updater holding the lock before the decision makes the installer refuse; nothing is downloaded`, async () => {
      const holder = Bun.spawn(["sleep", "30"])
      try {
        await mkdir(join(bin(), ".mehen.update.lock"), { recursive: true })
        await writeFile(join(bin(), ".mehen.update.lock/owner.json"), JSON.stringify({ pid: holder.pid, boot: "", at: "2020-01-01T00:00:00Z", by: "auto" }))
        const result = await run(shell)
        expect(result.code).toBe(2)
        expect(result.stderr).toContain(`Another mehen update is running (pid ${holder.pid})`)
        expect(requests).toEqual([])
        expect(await readdir(bin())).toEqual([".mehen.update.lock"])
      } finally {
        holder.kill()
      }
    })

    // Kill -0 fails with EPERM for a live process of another
    // user; that pid is alive and its lock is never taken.
    test(`${shell}: a lock held by a live pid of another user (kill -0 says EPERM) is refused, not reaped`, async () => {
      expect(Bun.spawnSync(["/bin/sh", "-c", "kill -0 1"]).exitCode).not.toBe(0)
      await mkdir(join(bin(), ".mehen.update.lock"), { recursive: true })
      const owner = JSON.stringify({ pid: 1, boot: "", at: "2026-10-28T00:00:00Z", by: "auto" })
      await writeFile(join(bin(), ".mehen.update.lock/owner.json"), owner)
      const result = await run(shell)
      expect(result.code).toBe(2)
      expect(result.stderr).toContain("Another mehen update is running (pid 1)")
      expect(await readFile(join(bin(), ".mehen.update.lock/owner.json"), "utf8")).toBe(owner)
      expect(requests).toEqual([])
    })

    test(`${shell}: the installer's lock is a 0700 directory with a 0600 owner file, whatever the umask`, async () => {
      delay = 800
      const installer = Bun.spawn([Bun.which(shell)!, "-c", `umask 000; exec '${Bun.which(shell)}' '${resolve(import.meta.dir, "install.sh")}'`], { env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: root, SHELL: "/bin/sh", MEHEN_INSTALL_DIR: bin(), MEHEN_DL_BASE: `http://127.0.0.1:${server.port}` }, stdout: "pipe", stderr: "pipe" })
      const lock = join(bin(), ".mehen.update.lock")
      for (let i = 0; i < 300 && !(await Bun.file(join(lock, "owner.json")).exists()); i++) await Bun.sleep(10)
      const { stat } = await import("node:fs/promises")
      expect((await stat(lock)).mode & 0o777).toBe(0o700)
      expect((await stat(join(lock, "owner.json"))).mode & 0o777).toBe(0o600)
      expect(await installer.exited).toBe(0)
    })

    test(`${shell}: a lock whose holder is gone is reaped and the install proceeds`, async () => {
      const gone = Bun.spawn(["true"])
      await gone.exited
      await mkdir(join(bin(), ".mehen.update.lock"), { recursive: true })
      await writeFile(join(bin(), ".mehen.update.lock/owner.json"), JSON.stringify({ pid: gone.pid, boot: "", at: new Date().toISOString(), by: "auto" }))
      expect((await run(shell)).code).toBe(0)
      expect(await left()).toEqual([])
    })

    // A lock with no readable owner was left by a process killed between its
    // mkdir and its owner write: taken over once it has stayed so for ten
    // minutes, by the younger of the directory's and owner.json's mtimes.
    test(`${shell}: a lock with no owner older than ten minutes is taken over and the install proceeds`, async () => {
      const lock = join(bin(), ".mehen.update.lock")
      await mkdir(lock, { recursive: true, mode: 0o700 })
      await aged(lock)
      const result = await run(shell)
      expect(result.code).toBe(0)
      expect(receipt(result.stdout).result).toBe("installed")
      expect(await readFile(join(bin(), "mehen"))).toEqual(Buffer.from(raw))
      expect(await left()).toEqual([])
    })

    test(`${shell}: an owner file that does not parse is taken over once it and the lock are older than ten minutes`, async () => {
      const lock = join(bin(), ".mehen.update.lock")
      await mkdir(lock, { recursive: true, mode: 0o700 })
      await writeFile(join(lock, "owner.json"), '{"pid":12')
      await aged(lock)
      const young = await run(shell)
      expect(young.code).toBe(2)
      expect(young.stderr).toContain("Another mehen update is running (pid 12)")
      expect(await readFile(join(lock, "owner.json"), "utf8")).toBe('{"pid":12')
      await aged(join(lock, "owner.json"))
      await aged(lock)
      expect((await run(shell)).code).toBe(0)
      expect(await left()).toEqual([])
    })

    test(`${shell}: a fresh lock with no owner still fails as held, and is left as it is`, async () => {
      const lock = join(bin(), ".mehen.update.lock")
      await mkdir(lock, { recursive: true, mode: 0o700 })
      const result = await run(shell)
      expect(result.code).toBe(2)
      expect(result.stderr).toContain("Another mehen update is running (pid unknown)")
      expect(await readdir(lock)).toEqual([])
      expect(requests).toEqual([])
    })

    test(`${shell}: an old lock with no owner and a reclamation guard still fails as held`, async () => {
      const lock = join(bin(), ".mehen.update.lock")
      await mkdir(join(lock, "reap"), { recursive: true, mode: 0o700 })
      await aged(join(lock, "reap"))
      await aged(lock)
      const result = await run(shell)
      expect(result.code).toBe(2)
      expect(result.stderr).toContain("Another mehen update is running (pid unknown)")
      expect(await readdir(lock)).toEqual(["reap"])
      expect(requests).toEqual([])
    })

    test(`${shell}: an old lock with no owner removed and made again after the installer observed it is held, and left to its new holder`, async () => {
      const lock = join(bin(), ".mehen.update.lock")
      await mkdir(lock, { recursive: true, mode: 0o700 })
      await aged(lock)
      // The new holder's mkdir is made beside the old lock first, so it cannot reuse its inode.
      const hook = `mkdir '${lock}.fresh' && rm -rf '${lock}' && mv '${lock}.fresh' '${lock}'`
      const result = await run(shell, { MEHEN_INSTALL_TEST_AFTER_OBSERVE: hook })
      expect(result.code).toBe(2)
      expect(result.stderr).toContain("Another mehen update is running (pid unknown)")
      expect(await readdir(lock)).toEqual([])
      expect(requests).toEqual([])
    })

    // The reclamation guard is one protocol for the CLI and the
    // installer; an old observation of a dead owner never displaces whoever
    // reclaimed the lock, in either direction.
    test(`${shell}: a CLI that reclaims after the installer observed a stale owner keeps the lock; the installer refuses and a third contender finds it held`, async () => {
      const helper = await lockHelper()
      await staleLock()
      const marker = join(root, "holder-pid")
      const hook = `'${process.execPath}' '${helper}' hold '${bin()}' '${marker}' >/dev/null 2>&1 & while [ ! -s '${marker}' ]; do sleep 0.05; done`
      const result = await run(shell, { MEHEN_INSTALL_TEST_AFTER_OBSERVE: hook })
      const holder = await readFile(marker, "utf8")
      expect(result.code).toBe(2)
      expect(result.stderr).toContain(`Another mehen update is running (pid ${holder})`)
      expect(JSON.parse(await readFile(join(bin(), ".mehen.update.lock/owner.json"), "utf8")).pid).toBe(Number(holder))
      expect(await helperRun(helper, "try")).toBe("held")
      expect(requests).toEqual([])
    })

    test(`${shell}: an installer that reclaimed a stale lock keeps it against a CLI acting on its old observation`, async () => {
      const helper = await lockHelper()
      const observed = await staleLock()
      delay = 1500
      const installer = run(shell)
      const ownerPath = join(bin(), ".mehen.update.lock/owner.json")
      const stale = JSON.parse(await readFile(observed, "utf8")).pid
      for (let i = 0; i < 200; i++) {
        const pid = await readFile(ownerPath, "utf8").then((t) => JSON.parse(t).pid as number, () => null)
        if (pid !== null && pid !== stale) break
        await Bun.sleep(10)
      }
      const before = await readFile(ownerPath, "utf8")
      expect(JSON.parse(before).by).toBe("install")
      expect(await helperRun(helper, "reclaim", observed)).toBe("refused")
      expect(await readFile(ownerPath, "utf8")).toBe(before)
      expect(await helperRun(helper, "try")).toBe("held")
      expect((await installer).code).toBe(0)
      expect(await left()).toEqual([])
    })

    test(`${shell}: a receipt-write failure on a fresh install removes this install's binary and receipt`, async () => {
      const result = await run(shell, { MEHEN_INSTALL_TEST_FAULT: "receipt" })
      expect(result.code).toBe(2)
      expect(result.stderr).toContain("binary and receipt are removed")
      expect(await readdir(bin())).toEqual([])
    })

    test(`${shell}: the same failure over a previous install restores it, its receipt and the pre-transaction previous pair byte for byte`, async () => {
      expect((await run(shell)).code).toBe(0)
      const installedBytes = new Uint8Array(raw)
      await writeFile(join(bin(), ".mehen.previous"), "pre-transaction previous binary")
      await writeFile(join(bin(), ".mehen.previous.json"), '{"version":"0.9.0","keyId":"rk-test"}')
      raw = new TextEncoder().encode("#!/bin/sh\necho newer fixture\n")
      gz = Bun.gzipSync(raw)
      const result = await run(shell, { MEHEN_FORCE: "1", MEHEN_INSTALL_TEST_FAULT: "receipt" })
      expect(result.code).toBe(2)
      expect(result.stderr).toContain("previous mehen and its receipt are restored")
      expect(await readFile(join(bin(), "mehen"))).toEqual(Buffer.from(installedBytes))
      expect(await readFile(join(bin(), ".mehen.sha256"), "utf8")).toBe(`${hash(installedBytes)}\n`)
      expect(await readFile(join(bin(), ".mehen.previous"), "utf8")).toBe("pre-transaction previous binary")
      expect(await readFile(join(bin(), ".mehen.previous.json"), "utf8")).toBe('{"version":"0.9.0","keyId":"rk-test"}')
      expect(await left()).toEqual([])
      // The test fault is honoured only for a loopback base: a refusal for an https base never reaches it.
      const https = await run(shell, { MEHEN_DL_BASE: "https://127.0.0.1:1", MEHEN_FORCE: "1", MEHEN_INSTALL_TEST_FAULT: "receipt" })
      expect(https.stderr).toContain("Manifest download failed")
    })

    test(`${shell}: a directory containing ':' and a HOME with a newline are refused before any write`, async () => {
      const colon = await run(shell, { MEHEN_INSTALL_DIR: join(root, "a:b") })
      expect(colon.code).toBe(2)
      expect(colon.stderr).toContain("must not contain ':'")
      const newline = await run(shell, { MEHEN_INSTALL_DIR: join(root, "x\ny") })
      expect(newline.stderr).toContain("newline")
      expect(await readdir(root)).toEqual([])
      expect(requests).toEqual([])
    })
  }
})

// The CLI side of the lock, run as its own process against the test's
// install directory: `hold <marker>` takes it and holds 2 s, `reclaim
// <observed owner file>` acts on an old observation, `try` takes it once.
async function lockHelper(): Promise<string> {
  const path = join(root, "lock-helper.ts")
  const state = resolve(import.meta.dir, "../../apps/cli/src/install-state.ts")
  await writeFile(path, `import { installation, observeLock, reclaimStale, withInstallLock } from ${JSON.stringify(state)}
const [mode, dir, arg] = process.argv.slice(2)
const install = installation(dir + "/mehen")
if (mode === "hold") process.exit((await withInstallLock(install, "auto", async () => { await Bun.write(arg!, String(process.pid)); await Bun.sleep(2000) }, { wait: false })).ok ? 0 : 3)
if (mode === "reclaim") console.log((await reclaimStale(install, { ...(await observeLock(install))!, text: await Bun.file(arg!).text() }, "auto", "old-observation")) ? "took" : "refused")
if (mode === "try") console.log((await withInstallLock(install, "auto", async () => 1, { wait: false })).ok ? "entered" : "held")
`)
  return path
}
async function helperRun(helper: string, mode: string, arg = ""): Promise<string> {
  const proc = Bun.spawn([process.execPath, helper, mode, bin(), arg], { stdout: "pipe", stderr: "pipe" })
  const out = await new Response(proc.stdout).text()
  await proc.exited
  return out.trim()
}
// Sets a path's mtime eleven minutes back, past the ownerless grace period.
async function aged(path: string): Promise<void> {
  const when = new Date(Date.now() - 11 * 60_000)
  await utimes(path, when, when)
}

// A lock left by a process that is gone; returns a file holding the owner
// record exactly as a contender observed it.
async function staleLock(): Promise<string> {
  const gone = Bun.spawn(["true"])
  await gone.exited
  await mkdir(join(bin(), ".mehen.update.lock"), { recursive: true, mode: 0o700 })
  const text = `${JSON.stringify({ pid: gone.pid, boot: "", at: "2026-10-28T00:00:00Z", by: "auto" })}\n`
  await writeFile(join(bin(), ".mehen.update.lock/owner.json"), text)
  await writeFile(join(root, "observed-owner"), text)
  return join(root, "observed-owner")
}

// Zsh and bash only; every other shell gets advice and no rc file.
describe("PATH persistence", () => {
  const line = () => `[ -f '${join(bin(), ".mehen.env")}' ] && . '${join(bin(), ".mehen.env")}' # mehen`
  for (const shell of shells) {
    test(`${shell}: zsh writes ~/.zshenv, or ZDOTDIR's, once; the env file puts the directory on PATH`, async () => {
      const first = receipt((await run(shell, { SHELL: "/bin/zsh" })).stdout)
      expect(first.rc).toEqual({ written: [join(root, ".zshenv")], unchanged: [], skipped: [], advice: null })
      expect(first.env).toBe(join(bin(), ".mehen.env"))
      expect(await readFile(join(root, ".zshenv"), "utf8")).toBe(`${line()}\n`)
      expect((await readFile(join(bin(), ".mehen.env"), "utf8")).split("\n")[0]).toBe("# mehen env: adds the Mehen install directory to PATH. Written by the Mehen installer; safe to delete.")
      const again = receipt((await run(shell, { SHELL: "/bin/zsh" })).stdout)
      expect(again).toMatchObject({ result: "already-installed", rc: { written: [], unchanged: [join(root, ".zshenv")] } })
      expect(await readFile(join(root, ".zshenv"), "utf8")).toBe(`${line()}\n`)
      const sourced = Bun.spawnSync(["/bin/sh", "-c", `. '${join(root, ".zshenv")}'; printf '%s' "$PATH"`], { env: { PATH: "/usr/bin" } })
      expect(sourced.stdout.toString()).toBe(`${bin()}:/usr/bin`)
      const zdot = join(root, ".config/zsh")
      await mkdir(zdot, { recursive: true, mode: 0o700 })
      expect(receipt((await run(shell, { SHELL: "/bin/zsh", ZDOTDIR: zdot })).stdout).rc.written).toEqual([join(zdot, ".zshenv")])
    })

    test(`${shell}: bash writes ~/.bashrc and the first existing login file, creating only ~/.profile`, async () => {
      const cases: [string[], string][] = [[[".bash_profile", ".profile"], ".bash_profile"], [[".bash_login", ".profile"], ".bash_login"], [[".profile"], ".profile"], [[], ".profile"]]
      for (const [present, chosen] of cases) {
        for (const name of [".bashrc", ".bash_profile", ".bash_login", ".profile"]) await rm(join(root, name), { force: true })
        await rm(bin(), { recursive: true, force: true })
        for (const name of present) await writeFile(join(root, name), "# mine")
        const r = receipt((await run(shell, { SHELL: "/bin/bash" })).stdout)
        expect(r.rc.written).toEqual([join(root, ".bashrc"), join(root, chosen)])
        // An existing file keeps its content; the line goes on its own line.
        if (present.includes(chosen)) expect(await readFile(join(root, chosen), "utf8")).toBe(`# mine\n${line()}\n`)
        for (const other of [".bash_profile", ".bash_login"]) if (!present.includes(other)) expect(await Bun.file(join(root, other)).exists()).toBe(false)
      }
    })

    test(`${shell}: fish and plain sh get one advice line and no rc file`, async () => {
      const fish = receipt((await run(shell, { SHELL: "/usr/bin/fish" })).stdout)
      expect(fish.rc).toEqual({ written: [], unchanged: [], skipped: [], advice: `fish: fish_add_path '${bin()}'` })
      await rm(bin(), { recursive: true, force: true })
      const sh = receipt((await run(shell, { SHELL: "/bin/sh" })).stdout)
      expect(sh.rc).toMatchObject({ written: [], skipped: [], advice: `add . '${join(bin(), ".mehen.env")}' to your shell's start-up file` })
      const files = await readdir(root)
      for (const name of [".zshenv", ".bashrc", ".profile", ".bash_profile", ".config"]) expect(files).not.toContain(name)
    })

    test(`${shell}: --no-rc writes no env or rc file`, async () => {
      const r = receipt((await run(shell, { SHELL: "/bin/zsh" }, ["--no-rc", "--quiet"])).stdout)
      expect(r).toMatchObject({ env: null, rc: { written: [], unchanged: [], skipped: [], advice: null } })
      expect(await readdir(root)).toEqual(["bin"])
      expect((await readdir(bin())).sort()).toEqual([".mehen.sha256", "mehen"])
    })

    test(`${shell}: a symlinked HOME and a symlinked directory inside HOME are unsafe ancestors; the binary still installs`, async () => {
      const real = join(root, "real-home")
      await mkdir(real, { mode: 0o700 })
      const link = join(root, "home-link")
      await symlink(real, link)
      const viaLink = receipt((await run(shell, { HOME: link, SHELL: "/bin/zsh", MEHEN_INSTALL_DIR: join(root, "bin") })).stdout)
      expect(viaLink.rc.skipped).toEqual([{ path: join(link, ".zshenv"), reason: "unsafe ancestor" }])
      expect(await Bun.file(join(real, ".zshenv")).exists()).toBe(false)
      expect(viaLink.result).toBe("installed")
      await mkdir(join(root, "zdot-real"), { mode: 0o700 })
      await symlink(join(root, "zdot-real"), join(root, "zdot-link"))
      const inner = receipt((await run(shell, { SHELL: "/bin/zsh", ZDOTDIR: join(root, "zdot-link") })).stdout)
      expect(inner.rc.skipped).toEqual([{ path: join(root, "zdot-link/.zshenv"), reason: "unsafe ancestor" }])
      expect(await Bun.file(join(root, "zdot-real/.zshenv")).exists()).toBe(false)
    })

    // On macOS a temporary HOME sits under /var, a link to
    // /private/var. HOME's ancestors are walked and written at their real path.
    test(`${shell}: a HOME under a symlinked ancestor gets its shell file at the real path`, async () => {
      const parent = join(root, "parent")
      await mkdir(join(parent, "home"), { recursive: true, mode: 0o700 })
      await symlink(parent, join(root, "parent-link"))
      const home = join(root, "parent-link/home")
      const ok = receipt((await run(shell, { HOME: home, SHELL: "/bin/zsh" })).stdout)
      expect(ok.rc).toEqual({ written: [join(home, ".zshenv")], unchanged: [], skipped: [], advice: null })
      expect(await readFile(join(parent, "home/.zshenv"), "utf8")).toBe(`${line()}\n`)
    })
    test(`${shell}: a HOME under a symlinked ancestor that resolves into a world-writable directory is still refused`, async () => {
      const shared = join(root, "shared")
      await mkdir(join(shared, "home"), { recursive: true, mode: 0o700 })
      await chmod(shared, 0o777)
      await symlink(shared, join(root, "shared-link"))
      const refused = receipt((await run(shell, { HOME: join(root, "shared-link/home"), SHELL: "/bin/zsh" })).stdout)
      expect(refused.result).toBe("installed")
      expect(refused.rc.skipped).toEqual([{ path: join(root, "shared-link/home/.zshenv"), reason: "unsafe ancestor" }])
      expect(await Bun.file(join(shared, "home/.zshenv")).exists()).toBe(false)
    })

    // An external ZDOTDIR's own directory must be this user's and
    // writable by nobody else; the root-owned allowance covers ancestors only.
    test(`${shell}: an external ZDOTDIR: a private user-owned parent is written; root's sticky /tmp, a foreign parent and an unwritable one are skipped and the binary installs`, async () => {
      const outside = realpathSync(await mkdtemp(join(tmpdir(), "mehen-zdot-")))
      try {
        await chmod(outside, 0o700)
        const ok = receipt((await run(shell, { SHELL: "/bin/zsh", ZDOTDIR: outside })).stdout)
        expect(ok.rc.written).toEqual([join(outside, ".zshenv")])
        const shared = realpathSync("/tmp")
        const existed = await Bun.file(join(shared, ".zshenv")).exists()
        const locked = join(outside, "locked")
        await mkdir(locked, { mode: 0o500 })
        for (const [dir, reason] of [[shared, "parent not owned"], ["/usr", "parent not owned"], [locked, "not writable"]] as const) {
          await rm(bin(), { recursive: true, force: true })
          const r = receipt((await run(shell, { SHELL: "/bin/zsh", ZDOTDIR: dir })).stdout)
          expect(r.result).toBe("installed")
          expect(r.rc).toMatchObject({ written: [], skipped: [{ path: join(dir, ".zshenv"), reason }] })
          expect(await readFile(join(bin(), "mehen"))).toEqual(Buffer.from(raw))
        }
        expect(await Bun.file(join(shared, ".zshenv")).exists()).toBe(existed)
        expect(await Bun.file(join(locked, ".zshenv")).exists()).toBe(false)
        await chmod(locked, 0o700)
      } finally {
        await rm(outside, { recursive: true, force: true })
      }
    })

    test(`${shell}: never overwrites a foreign rc or env file: a symlinked rc, a group-writable HOME and a foreign env file are skipped`, async () => {
      await writeFile(join(root, "target"), "# not yours")
      await symlink(join(root, "target"), join(root, ".zshenv"))
      expect(receipt((await run(shell, { SHELL: "/bin/zsh" })).stdout).rc.skipped).toEqual([{ path: join(root, ".zshenv"), reason: "symlink" }])
      expect(await readFile(join(root, "target"), "utf8")).toBe("# not yours")
      await rm(join(root, ".zshenv"))
      await chmod(root, 0o770)
      try {
        expect(receipt((await run(shell, { SHELL: "/bin/zsh" })).stdout).rc.skipped).toEqual([{ path: join(root, ".zshenv"), reason: "unsafe ancestor" }])
      } finally {
        await chmod(root, 0o700)
      }
      await writeFile(join(bin(), ".mehen.env"), "echo someone else's file\n")
      const foreign = receipt((await run(shell, { SHELL: "/bin/zsh" })).stdout)
      expect(foreign).toMatchObject({ env: null, rc: { written: [], skipped: [{ path: join(bin(), ".mehen.env"), reason: "not written by the Mehen installer" }] } })
      expect(await readFile(join(bin(), ".mehen.env"), "utf8")).toBe("echo someone else's file\n")
      expect(await Bun.file(join(root, ".zshenv")).exists()).toBe(false)
    })
  }
})
