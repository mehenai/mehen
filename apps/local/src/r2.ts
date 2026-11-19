// The vault's daily dumps on one machine: an R2 bucket's get and put on a
// folder in the data directory. Like the hosted bucket's lock, an object is
// written once and never overwritten. Old dailies are pruned as the hosted
// lifecycle rule does (35 days), monthlies kept for a year.

import { existsSync, mkdirSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs"
import { dirname, join, relative, sep } from "node:path"

const DAILY_DAYS = 35
const MONTHLY_DAYS = 366
const DAY_MS = 86_400_000

type StoredObject = { key: string; size: number; body: ReadableStream<Uint8Array>; arrayBuffer(): Promise<ArrayBuffer> }

export class LocalBucket {
  private readonly dir: string

  constructor(dir: string) {
    this.dir = dir
    mkdirSync(dir, { recursive: true, mode: 0o700 })
  }

  private path(key: string): string {
    const path = join(this.dir, key)
    const rel = relative(this.dir, path)
    if (rel === "" || rel.startsWith("..") || rel.includes(`${sep}..${sep}`)) throw new Error(`backup key ${key} is outside the backup folder`)
    return path
  }

  async get(key: string): Promise<StoredObject | null> {
    const path = this.path(key)
    if (!existsSync(path)) return null
    const file = Bun.file(path)
    return { key, size: file.size, body: file.stream(), arrayBuffer: () => file.arrayBuffer() }
  }

  async put(key: string, value: Uint8Array | ArrayBuffer, _options?: unknown): Promise<{ key: string; size: number }> {
    const path = this.path(key)
    if (existsSync(path)) throw new Error(`backup ${key} already exists and is never overwritten`)
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : value
    const temporary = `${path}.partial`
    writeFileSync(temporary, bytes, { mode: 0o600 })
    renameSync(temporary, path)
    return { key, size: bytes.length }
  }

  // Removes dailies older than 35 days and monthlies older than a year,
  // judged by when the file was written.
  prune(now = Date.now()): number {
    let removed = 0
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name)
        const info = statSync(path)
        if (info.isDirectory()) walk(path)
        else if (now - info.mtimeMs > (relative(this.dir, path).split(sep).includes("monthly") ? MONTHLY_DAYS : DAILY_DAYS) * DAY_MS) {
          rmSync(path)
          removed++
        }
      }
    }
    walk(this.dir)
    return removed
  }
}
