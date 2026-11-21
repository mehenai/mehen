// A mehen that Homebrew installed. Brew keeps each version in its own keg,
// <prefix>/Cellar/mehen/<version>/bin/mehen, and deletes the old keg after
// `brew upgrade` and `brew cleanup`, so a path recorded for later runs (an
// agent's MCP entry, a guard hook, the vault's service) must be one of the
// links brew moves to the new keg instead. Brew also owns the keg's files,
// so the self-updater leaves it alone and `brew upgrade mehen` updates it.
//
// Decided from where the binary really is, never from an environment
// variable alone: HOMEBREW_PREFIX and HOMEBREW_CELLAR only say where to look
// when brew keeps its kegs somewhere other than <prefix>/Cellar.

import { realpathSync } from "node:fs"
import { basename, dirname, join, resolve } from "node:path"
import type { Env } from "./config.ts"

export type Homebrew = { prefix: string; version: string; keg: string; stable: string }

export const BREW_UPGRADE = "brew upgrade mehen"

export type RealPath = (path: string) => string | null

function realPath(path: string): string | null {
  try {
    return realpathSync(path)
  } catch {
    return null
  }
}

// <cellar>/mehen/<version>/bin/mehen: the version folder, then the cellar.
function kegParts(binary: string): { cellar: string; version: string } | null {
  const bin = dirname(binary)
  const keg = dirname(bin)
  const formula = dirname(keg)
  if (basename(binary) !== "mehen" || basename(bin) !== "bin" || basename(formula) !== "mehen") return null
  const version = basename(keg)
  if (!/^[0-9A-Za-z][0-9A-Za-z._+-]*$/.test(version)) return null
  return { cellar: dirname(formula), version }
}

export function homebrewInstall(binary: string, env: Env, real: RealPath = realPath): Homebrew | null {
  const resolved = real(binary) ?? resolve(binary)
  const parts = kegParts(resolved)
  if (parts === null) return null
  const prefixes: string[] = []
  const named = env.HOMEBREW_PREFIX ? resolve(env.HOMEBREW_PREFIX) : null
  const cellar = env.HOMEBREW_CELLAR ? resolve(env.HOMEBREW_CELLAR) : named ? join(named, "Cellar") : null
  if (named && cellar && (real(cellar) ?? cellar) === parts.cellar) prefixes.push(named)
  if (basename(parts.cellar) === "Cellar") prefixes.push(dirname(parts.cellar))
  if (prefixes.length === 0) return null
  const keg = dirname(dirname(resolved))
  // opt/mehen follows the linked keg through every upgrade; bin/mehen is
  // the link brew puts on PATH, the fallback when opt is missing or names
  // another version.
  for (const prefix of prefixes) {
    const opt = join(prefix, "opt", "mehen", "bin", "mehen")
    if (real(opt) === resolved) return { prefix, version: parts.version, keg, stable: opt }
  }
  const prefix = prefixes[0]!
  return { prefix, version: parts.version, keg, stable: join(prefix, "bin", "mehen") }
}

// The path to record for a later run of `binary`: the Homebrew link for a
// keg, the binary itself otherwise.
export function launchPath(binary: string, env: Env, real: RealPath = realPath): string {
  return homebrewInstall(binary, env, real)?.stable ?? binary
}
