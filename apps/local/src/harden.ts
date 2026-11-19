// Process hardening for the local vault, which holds the root key in memory.
// On Linux, PR_SET_DUMPABLE 0 stops a process of the same user attaching
// with ptrace or reading /proc/<pid>/mem (Yama or not), and keeps the key
// out of core dumps. On a Mac the signed binary's hardened runtime already
// refuses task_for_pid to ordinary processes.

import { dlopen, FFIType } from "bun:ffi"

const PR_SET_DUMPABLE = 4
const PR_GET_DUMPABLE = 3
const LIBC = ["libc.so.6", "libc.musl-x86_64.so.1", "libc.musl-aarch64.so.1"]

export type Hardening = { dumpable: "off" | "unsupported" | "failed"; detail: string | null }

function prctl(): ((option: number, arg: number) => number) | null {
  for (const name of LIBC) {
    try {
      const lib = dlopen(name, { prctl: { args: [FFIType.i32, FFIType.u64, FFIType.u64, FFIType.u64, FFIType.u64], returns: FFIType.i32 } })
      return (option, arg) => lib.symbols.prctl(option, arg, 0, 0, 0)
    } catch {
      continue
    }
  }
  return null
}

export function hardenProcess(platform: NodeJS.Platform = process.platform): Hardening {
  if (platform !== "linux") return { dumpable: "unsupported", detail: `not needed on ${platform}` }
  const call = prctl()
  if (!call) return { dumpable: "failed", detail: "libc could not be loaded" }
  if (call(PR_SET_DUMPABLE, 0) !== 0 || call(PR_GET_DUMPABLE, 0) !== 0) return { dumpable: "failed", detail: "prctl refused" }
  return { dumpable: "off", detail: null }
}
