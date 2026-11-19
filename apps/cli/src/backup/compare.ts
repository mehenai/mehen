// mehen backup compare <snp>.age <bkx>.age --identity <file|-> --map <file>:
// on the key machine, offline, whether every adopted source still matches
// what Mehen holds. The snapshot carries the files adopt read and the plan
// itself; the map is `mehen adopt status <adp_id> --json`, which says the
// slug each planned item was stored as. Each source variable is compared
// in memory with its item's field in the export, and the answer names
// paths and variables only, never a value.

import type { BackupBundle } from "@mehen/protocol/backup"
import { fromUtf8 } from "@mehen/protocol/bytes"
import { z } from "zod"
import { parseSource } from "../adopt/parse.ts"
import type { SourceType } from "../adopt/sources.ts"
import { backupFailure, readRegularFile } from "./files.ts"
import { openBundle } from "./open.ts"
import { type Opened, openSnapshot } from "./restore.ts"

const SOURCE_TYPES = ["dotenv", "envrc", "json", "secrets-file", "plist", "systemd", "gh-hosts", "kubeconfig", "talosconfig", "gcloud-adc", "wrangler", "docker"] as const satisfies readonly SourceType[]

// What compare needs from the plan the snapshot holds: each item's secret
// fields and their sources.
const ComparePlanSchema = z.looseObject({
  items: z.array(z.looseObject({ ref: z.string(), include: z.boolean().optional(), slug: z.string(), exists: z.boolean().optional(), fields: z.record(z.string(), z.looseObject({ from: z.array(z.string()) })).optional() })),
  sources: z.record(z.string(), z.looseObject({ path: z.string(), type: z.enum(SOURCE_TYPES), variable: z.string().nullable().optional(), pointer: z.string().nullable().optional() })),
})

// `mehen adopt status --json`: the refs the vault stored, and as which slug.
const AdoptMapSchema = z.looseObject({ created: z.array(z.looseObject({ ref: z.string(), slug: z.string() })).optional() })

export type CompareSource = { path: string; variable: string | null; pointer: string | null; item: string; field: string }
export type CompareResult = {
  snapshot: string
  export: string
  // When the export was taken, so `mehen adopt retire` can tell it is newer
  // than the batch it checks.
  exportedAt: string
  sources: number
  matched: number
  // Every source that matched, by path and variable: no value.
  matching: CompareSource[]
  different: CompareSource[]
  missing: (CompareSource & { why: string })[]
}

export type CompareOptions = { snapshotPath: string; exportPath: string; mapPath: string; identities: readonly string[] }

async function readMap(path: string): Promise<Map<string, string>> {
  const read = await readRegularFile(path, { maxBytes: 4 * 1_048_576, ownOnly: false })
  if (read === null) throw backupFailure(`There is no map at ${path}.`, "Save `mehen adopt status <adp_id> --json` to a file and name it with --map.")
  let parsed: z.infer<typeof AdoptMapSchema>
  try {
    parsed = AdoptMapSchema.parse(JSON.parse(fromUtf8(new Uint8Array(read.bytes))))
  } catch {
    throw backupFailure(`The map ${path} is not the output of \`mehen adopt status --json\`.`, "Save `mehen adopt status <adp_id> --json` to a file and name it with --map.")
  }
  return new Map((parsed.created ?? []).map((c) => [c.ref, c.slug]))
}

function jsonOrNull(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(fromUtf8(new Uint8Array(bytes)))
  } catch {
    return null
  }
}

function planOf(snapshotId: string, planDigest: string, files: readonly Opened[]): z.infer<typeof ComparePlanSchema> {
  const file = files.find((f) => f.file.sha256 === planDigest)
  const parsed = file === undefined ? null : ComparePlanSchema.safeParse(jsonOrNull(file.bytes))
  if (!parsed?.success) throw backupFailure(`Snapshot ${snapshotId} does not hold an adopt plan with its items and sources.`, "Compare a snapshot `mehen backup snapshot --plan` took before `mehen adopt submit`.")
  return parsed.data
}

function exportedValue(bundle: BackupBundle, slug: string, field: string): { ok: true; value: string } | { ok: false; why: string } {
  const item = bundle.items.find((i) => i.slug === slug)
  const excluded = bundle.excluded.find((e) => e.slug === slug)
  if (item === undefined) return { ok: false, why: excluded?.reason ?? "not in this export" }
  const value = item.secretFields[field]
  return value === undefined ? { ok: false, why: excluded?.reason ?? `the export holds no field ${field} for it` } : { ok: true, value }
}

export async function compareBackups(options: CompareOptions): Promise<CompareResult> {
  const created = await readMap(options.mapPath)
  const { snapshot, files } = await openSnapshot(options.snapshotPath, options.identities)
  const bundle = await openBundle(options.exportPath, options.identities)
  try {
    const plan = planOf(snapshot.id, snapshot.planDigest, files)
    const byPath = new Map(files.map((f) => [f.file.path, f]))
    const parsed = new Map<string, ReturnType<typeof parseSource> | null>()
    const result: CompareResult = { snapshot: snapshot.id, export: bundle.id, exportedAt: bundle.exportedAt, sources: 0, matched: 0, matching: [], different: [], missing: [] }
    for (const item of plan.items) {
      const slug = item.include === false ? null : (created.get(item.ref) ?? (item.exists ? item.slug : null))
      if (slug === null) continue
      for (const [field, { from }] of Object.entries(item.fields ?? {})) {
        for (const id of from) {
          const source = plan.sources[id]
          if (source === undefined) continue
          const at: CompareSource = { path: source.path, variable: source.variable ?? null, pointer: source.pointer ?? null, item: slug, field }
          result.sources += 1
          if (!parsed.has(source.path)) {
            const opened = byPath.get(source.path)
            parsed.set(source.path, opened === undefined ? null : parseSource(source.type, fromUtf8(new Uint8Array(opened.bytes)), ""))
          }
          const entries = parsed.get(source.path)
          const entry = entries?.entries.find((e) => e.variable === at.variable && e.pointer === at.pointer)
          if (entry === undefined || entry.value === null) {
            result.missing.push({ ...at, why: entries ? "the snapshot's copy of the file does not hold it" : "the snapshot does not hold the file" })
            continue
          }
          const exported = exportedValue(bundle, slug, field)
          if (!exported.ok) result.missing.push({ ...at, why: exported.why })
          else if (exported.value === entry.value) {
            result.matched += 1
            result.matching.push(at)
          }
          else result.different.push(at)
        }
      }
    }
    return result
  } finally {
    for (const f of files) f.bytes.fill(0)
    for (const item of bundle.items) item.secretFields = {}
  }
}

export function compareLines(r: CompareResult): string[] {
  const where = (s: CompareSource) => `${s.path} ${s.variable ?? s.pointer ?? ""}`.trimEnd()
  return [
    ...r.different.map((s) => `different  ${where(s)} (${s.item}.${s.field})`),
    ...r.missing.map((s) => `missing    ${where(s)} (${s.item}.${s.field}): ${s.why}`),
    `${r.matched}/${r.sources} source${r.sources === 1 ? "" : "s"} match Mehen (snapshot ${r.snapshot}, export ${r.export})`,
  ]
}
