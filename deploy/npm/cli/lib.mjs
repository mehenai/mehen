// The npm route to Mehen, with no dependencies. It runs the signed mehen the
// installer put in place, installing it first with the same installer as
// `curl -fsSL https://mehen.dev/install | sh`, so a machine set up through
// npm updates itself from signed releases like any other.

import { spawn, spawnSync } from "node:child_process"
import { closeSync, existsSync, mkdtempSync, openSync, readSync, rmSync, writeFileSync } from "node:fs"
import { constants, homedir, tmpdir } from "node:os"
import { join } from "node:path"

export const INSTALL_URL = "https://mehen.dev/install"
const NATIVE = [
  [0x7f, 0x45, 0x4c, 0x46], // ELF
  [0xcf, 0xfa, 0xed, 0xfe], // Mach-O 64-bit
  [0xca, 0xfe, 0xba, 0xbe], // Mach-O universal
]

// Where the installer puts mehen: MEHEN_INSTALL_DIR, else ~/.local/bin.
export function installedPath(env = process.env) {
  return join(env.MEHEN_INSTALL_DIR || join(env.HOME || homedir(), ".local", "bin"), "mehen")
}

// The platforms mehen is released for.
export function unsupported(platform = process.platform, arch = process.arch) {
  if (platform === "win32") return "Mehen does not run on Windows yet. Use WSL: https://docs.mehen.dev/start"
  if (platform !== "darwin" && platform !== "linux") return `Mehen runs on macOS and Linux, not ${platform}.`
  if (arch !== "x64" && arch !== "arm64") return `Mehen runs on x64 and arm64, not ${arch}.`
  return null
}

// A native executable (the released mehen), not a script such as this
// package's own launcher installed into the same folder.
export function isNative(path) {
  let fd
  try {
    fd = openSync(path, "r")
    const head = Buffer.alloc(4)
    if (readSync(fd, head, 0, 4, 0) !== 4) return false
    return NATIVE.some((magic) => magic.every((byte, i) => head[i] === byte))
  } catch {
    return false
  } finally {
    if (fd !== undefined) closeSync(fd)
  }
}

// The installer's address: https://mehen.dev/install, or for tests a
// loopback http address in MEHEN_INSTALL_URL.
export function installUrl(env = process.env) {
  const chosen = env.MEHEN_INSTALL_URL
  if (!chosen) return INSTALL_URL
  const url = new URL(chosen)
  if (url.protocol === "https:" || (url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "localhost"))) return url.href
  throw new Error("MEHEN_INSTALL_URL must use https, or plain http on 127.0.0.1 or localhost.")
}

async function install(env) {
  const response = await fetch(installUrl(env), { redirect: "error" })
  if (!response.ok) throw new Error(`Could not download the installer (HTTP ${response.status}). Try again, or run: curl -fsSL ${INSTALL_URL} | sh`)
  const script = await response.text()
  const dir = mkdtempSync(join(tmpdir(), "mehen-install-"))
  try {
    const file = join(dir, "install.sh")
    writeFileSync(file, script, { mode: 0o600 })
    const ran = spawnSync("sh", [file, "--yes"], { stdio: "inherit", env })
    if (ran.status !== 0) throw new Error(`The installer stopped (exit ${ran.status ?? ran.signal}); what it printed above says why.`)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

function fail(message) {
  process.stderr.write(`mehen: ${message}\n`)
  return 1
}

// Runs mehen with these arguments, installing it first when it is missing.
// Resolves with the exit code to leave with.
export async function run(args, env = process.env) {
  const why = unsupported()
  if (why) return fail(why)
  const target = installedPath(env)
  if (existsSync(target) && !isNative(target)) {
    return fail(`${target} is not the mehen program (perhaps this npm package was installed globally into the same folder). Set MEHEN_INSTALL_DIR to another folder, or run: curl -fsSL ${INSTALL_URL} | sh`)
  }
  if (!existsSync(target)) {
    try {
      await install(env)
    } catch (error) {
      return fail(error instanceof Error ? error.message : String(error))
    }
    if (!isNative(target)) return fail(`The installer finished but ${target} is not there. Run: curl -fsSL ${INSTALL_URL} | sh`)
  }
  return await new Promise((resolve) => {
    const child = spawn(target, args, { stdio: "inherit", env })
    const forward = (signal) => child.kill(signal)
    for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, forward)
    child.on("error", (error) => resolve(fail(`could not start ${target}: ${error.message}`)))
    child.on("exit", (code, signal) => resolve(code ?? 128 + (signal ? constants.signals[signal] ?? 15 : 1)))
  })
}
