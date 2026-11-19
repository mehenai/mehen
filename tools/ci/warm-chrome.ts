// Reads a Chrome installation's files once, so a fresh CI runner's slow
// first read of its disk is paid here, in the background, and not by the
// first Chrome start (tools/ci/chrome.ts says why). Only the browser's own
// installation directory is read, found by the file every Chrome and
// Chromium build keeps beside its binary; an unknown layout is skipped.
//
//   bun tools/ci/warm-chrome.ts <chrome or chromium as found on PATH>

import { closeSync, existsSync, lstatSync, openSync, readSync, readdirSync, realpathSync } from "node:fs"
import { basename, dirname, join } from "node:path"

const MARKER = "icudtl.dat"

// Where the packages put the browser behind a wrapper script on PATH.
export const WRAPPED_DIRS = ["/usr/lib/chromium", "/usr/lib/chromium-browser", "/usr/lib64/chromium-browser", "/usr/lib64/chromium"]

function isInstallDir(dir: string): boolean {
  try {
    return lstatSync(join(dir, MARKER)).isFile()
  } catch {
    return false
  }
}

// The directory the browser runs from, or null when it cannot be told.
export function chromeInstallDir(binary: string, wrapped: readonly string[] = WRAPPED_DIRS): string | null {
  let real: string
  try {
    real = realpathSync(binary)
  } catch {
    return null
  }
  if (isInstallDir(dirname(real))) return dirname(real)
  // A wrapper: the package's own directory, when it is there and named for it.
  const name = basename(real)
  return wrapped.find((dir) => basename(dir).startsWith(name.replace(/-browser$/, "")) && isInstallDir(dir)) ?? null
}

// Every regular file under `dir`, read through and dropped; links are not
// followed, so nothing outside the installation is read.
export function readAhead(dir: string): { files: number; bytes: number } {
  const buffer = Buffer.alloc(1 << 20)
  let files = 0
  let bytes = 0
  const walk = (at: string): void => {
    for (const entry of readdirSync(at, { withFileTypes: true })) {
      const path = join(at, entry.name)
      if (entry.isDirectory()) walk(path)
      else if (entry.isFile()) {
        const fd = openSync(path, "r")
        try {
          for (let n = readSync(fd, buffer); n > 0; n = readSync(fd, buffer)) bytes += n
        } finally {
          closeSync(fd)
        }
        files++
      }
    }
  }
  walk(dir)
  return { files, bytes }
}

if (import.meta.main) {
  const binary = process.argv[2]
  const dir = binary !== undefined && existsSync(binary) ? chromeInstallDir(binary) : null
  if (dir === null) {
    console.log(`warm-chrome: no Chrome installation found for ${binary ?? "(none given)"}; nothing read`)
  } else {
    const started = Date.now()
    const read = readAhead(dir)
    console.log(`warm-chrome: read ${read.files} files, ${Math.round(read.bytes / 1e6)} MB, in ${dir} in ${Date.now() - started} ms`)
  }
}
