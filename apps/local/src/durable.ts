// Writes of the vault's keys that survive a crash or a power cut. A file is
// written whole to a temporary name and synced, renamed into place, and its
// directory synced; a file is removed and its directory synced. On a Mac
// fsync hands the data to the drive, which may keep it in its cache, so
// F_FULLFSYNC (fcntl 51, through libSystem) is used to have the drive write
// it out, and fsync where that is refused. On Linux fsync already does.
//
// The steps are a Disk so a test can record their order.

import { dlopen, FFIType } from "bun:ffi"
import { closeSync, fchmodSync, fsyncSync, openSync, renameSync, rmSync, writeSync } from "node:fs"
import { dirname } from "node:path"

const F_FULLFSYNC = 51

export type Disk = {
  write(path: string, text: string): void
  rename(from: string, to: string): void
  remove(path: string): void
  syncDir(dir: string): void
}

let fullSync: ((fd: number) => number) | null | undefined

// fcntl is variadic; F_FULLFSYNC reads no third argument, and the first two
// are passed as fixed arguments on every Apple ABI, so two are declared.
function fcntlFullSync(): ((fd: number) => number) | null {
  if (fullSync !== undefined) return fullSync
  fullSync = null
  if (process.platform === "darwin") {
    try {
      const lib = dlopen("/usr/lib/libSystem.B.dylib", { fcntl: { args: [FFIType.i32, FFIType.i32], returns: FFIType.i32 } })
      fullSync = (fd) => lib.symbols.fcntl(fd, F_FULLFSYNC)
    } catch {
      fullSync = null
    }
  }
  return fullSync
}

function syncFd(fd: number): void {
  const full = fcntlFullSync()
  if (full && full(fd) === 0) return
  fsyncSync(fd)
}

export const DISK: Disk = {
  write(path, text) {
    const fd = openSync(path, "wx", 0o600)
    try {
      fchmodSync(fd, 0o600)
      const bytes = Buffer.from(text)
      let at = 0
      while (at < bytes.length) at += writeSync(fd, bytes, at)
      syncFd(fd)
    } finally {
      closeSync(fd)
    }
  },
  rename(from, to) {
    renameSync(from, to)
  },
  remove(path) {
    rmSync(path, { force: true })
  },
  syncDir(dir) {
    const fd = openSync(dir, "r")
    try {
      syncFd(fd)
    } finally {
      closeSync(fd)
    }
  },
}

export function replaceDurably(disk: Disk, path: string, text: string): void {
  const temp = `${path}.${crypto.randomUUID()}.tmp`
  try {
    disk.write(temp, text)
    disk.rename(temp, path)
    disk.syncDir(dirname(path))
  } finally {
    rmSync(temp, { force: true })
  }
}

export function removeDurably(disk: Disk, path: string): void {
  disk.remove(path)
  disk.syncDir(dirname(path))
}
