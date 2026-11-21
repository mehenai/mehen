// The one source of the CLI's version: `version` in apps/cli/package.json.
// The build (scripts/build.ts) also defines MEHEN_BUILD_COMMIT, the short
// commit it was built from, and MEHEN_BUILD_KIND, "release" for a
// `--release` build and "dev" otherwise, and MEHEN_BUILD_TARGET, the target
// it compiled (such as linux-x64-musl); a run from source has none of them.

import cliPackage from "../package.json" with { type: "json" }

declare const MEHEN_BUILD_COMMIT: string | undefined
declare const MEHEN_BUILD_KIND: string | undefined
declare const MEHEN_BUILD_TARGET: string | undefined

export type BuildKind = "release" | "dev" | null

export const VERSION: string = cliPackage.version

export const BUILD_COMMIT: string | null = typeof MEHEN_BUILD_COMMIT === "string" ? MEHEN_BUILD_COMMIT : null

export const BUILD_KIND: BuildKind = typeof MEHEN_BUILD_KIND === "string" ? (MEHEN_BUILD_KIND === "release" ? "release" : "dev") : null

export type Libc = "musl" | "glibc"

// Which Linux libc this binary links, from its build target: a musl build
// must update to the musl binary. Everything else, a binary built before
// targets were stamped and a run from source included, is the glibc build.
export const BUILD_LIBC: Libc = typeof MEHEN_BUILD_TARGET === "string" && MEHEN_BUILD_TARGET.endsWith("-musl") ? "musl" : "glibc"

// A binary from `bun build --compile` runs its entry from Bun's embedded
// file system; a run from source names a real file.
export function isCompiledBinary(): boolean {
  return Bun.main.startsWith("/$bunfs/") || Bun.main.includes("~BUN")
}
