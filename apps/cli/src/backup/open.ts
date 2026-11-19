// mehen backup open <bkx>.age --identity <file|->: opens an export from the
// vault with the backup identity, offline, and says what it holds: counts
// per kind and home, the slugs and what was left out and why, never a
// value. restore --env and compare open it the same way.

import { type BackupBundle, BackupBundleSchema } from "@mehen/protocol/backup"
import { fromUtf8 } from "@mehen/protocol/bytes"
import { ageDecrypt } from "./age.ts"
import { MAX_EXPORT_BYTES } from "./check.ts"
import { backupFailure, readRegularFile } from "./files.ts"

export async function openBundle(archivePath: string, identities: readonly string[]): Promise<BackupBundle> {
  const archive = await readRegularFile(archivePath, { maxBytes: MAX_EXPORT_BYTES, ownOnly: false })
  if (archive === null) throw backupFailure(`There is no export at ${archivePath}.`, "Name the .age file `mehen backup export` or the Settings page wrote.")
  let plaintext: Uint8Array
  try {
    plaintext = await ageDecrypt(archive.bytes, identities)
  } catch {
    throw backupFailure(`The identity does not open ${archivePath}, or the export is damaged.`, `Check it with \`mehen backup check ${archivePath}\`, then try the identity of the key its sidecar names.`)
  }
  try {
    return BackupBundleSchema.parse(JSON.parse(fromUtf8(new Uint8Array(plaintext))))
  } catch {
    throw backupFailure(`${archivePath} opens, but not to a mehen-backup/v1 export.`, "Use an export `mehen backup export` or the Settings page wrote; a snapshot opens with `mehen backup restore`.")
  } finally {
    plaintext.fill(0)
  }
}

export type BundleSummary = {
  id: string
  workspace: BackupBundle["workspace"]
  exportedAt: string
  registrant: string
  items: number
  byKind: Record<string, number>
  byHome: Record<string, number>
  slugs: string[]
  projects: { slug: string; environments: string[] }[]
  excluded: BackupBundle["excluded"]
  auditHead: BackupBundle["auditHead"]
}

// "project <slug>" when the bundle holds the project, else its id.
function homeName(home: BackupBundle["items"][number]["home"], projects: ReadonlyMap<string, string>): string {
  if (home.kind === "project") return `project ${projects.get(home.project) ?? home.project}`
  return home.kind === "member" ? "private" : home.kind
}

function count(into: Record<string, number>, key: string): void {
  into[key] = (into[key] ?? 0) + 1
}

// Everything about the bundle but its values.
export function bundleSummary(bundle: BackupBundle): BundleSummary {
  const byKind: Record<string, number> = {}
  const byHome: Record<string, number> = {}
  const projects = new Map(bundle.projects.map((p) => [p.id, p.slug]))
  for (const item of bundle.items) {
    count(byKind, item.kind)
    count(byHome, homeName(item.home, projects))
  }
  return {
    id: bundle.id,
    workspace: bundle.workspace,
    exportedAt: bundle.exportedAt,
    registrant: bundle.registrant.name,
    items: bundle.items.length,
    byKind,
    byHome,
    slugs: bundle.items.map((i) => i.slug).sort(),
    projects: bundle.projects.map((p) => ({ slug: p.slug, environments: p.environments.map((e) => e.name) })),
    excluded: bundle.excluded,
    auditHead: bundle.auditHead,
  }
}

export function summaryLines(s: BundleSummary): string[] {
  const counts = (by: Record<string, number>) => Object.entries(by).sort(([a], [b]) => a.localeCompare(b)).map(([k, n]) => `${n} ${k}`).join(", ") || "none"
  return [
    `${s.id}: ${s.workspace.name} (${s.workspace.slug}), exported ${s.exportedAt} by ${s.registrant}`,
    `${s.items} credential${s.items === 1 ? "" : "s"}: ${counts(s.byKind)}`,
    `homes: ${counts(s.byHome)}`,
    ...s.slugs.map((slug) => `  ${slug}`),
    `${s.projects.length} project${s.projects.length === 1 ? "" : "s"}${s.projects.length ? `: ${s.projects.map((p) => `${p.slug} (${p.environments.join(", ")})`).join("; ")}` : ""}`,
    ...(s.excluded.length ? [`left out ${s.excluded.length}:`, ...s.excluded.map((e) => `  ${e.slug}: ${e.reason}`)] : ["nothing left out"]),
    ...(s.auditHead ? [`audit head: ${s.auditHead.seq} ${s.auditHead.hash}`] : []),
  ]
}
