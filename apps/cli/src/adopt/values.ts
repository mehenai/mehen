// Reading the values a plan names, for submit (to seal them) and apply (to
// set plain config). Each file is read once with the scan's guarantees, and
// every value goes into the output guard the moment it is read. A source
// whose name is gone, or whose value no longer classifies as the plan says,
// is "changed since scan"; nothing about the value is reported.

import { classify } from "./classify.ts"
import type { OutputGuard } from "./output-guard.ts"
import { type ParsedEntry, parseSource } from "./parse.ts"
import type { AdoptPlan, PlanSource } from "./plan.ts"
import { type SourceType, readSource } from "./sources.ts"

export const CHANGED = "changed since scan"

export type SourceValue = { ok: true; value: string } | { ok: false; why: string }

function sameClass(source: PlanSource, value: string): boolean {
  const now = classify({ type: source.type, variable: source.variable, pointer: source.pointer, value, path: source.path })
  return now.class === source.class && now.kind === source.kind && now.field === source.field && now.status === source.status
}

// A file just read: its path and every value in it, with the value's class,
// go into the output guard before anything else happens.
export function guardFile(guard: OutputGuard, path: string, type: SourceType, entries: ParsedEntry[]): void {
  guard.addPath(path)
  for (const e of entries) {
    guard.addName(e.variable)
    guard.addName(e.pointer)
    if (e.value !== null) guard.add(e.value, classify({ type, variable: e.variable, pointer: e.pointer, value: e.value, path }).class)
  }
}

// The names a plan's output may show, from files this run need not read.
export function guardPlan(guard: OutputGuard, plan: AdoptPlan): void {
  for (const source of Object.values(plan.sources)) {
    guard.addPath(source.path)
    guard.addName(source.variable)
    guard.addName(source.pointer)
  }
  for (const item of plan.items) guard.addName(item.slug)
}

export async function readSourceValues(plan: AdoptPlan, ids: Iterable<string>, home: string, guard: OutputGuard): Promise<Map<string, SourceValue>> {
  guardPlan(guard, plan)
  const wanted = new Map<string, Set<string>>()
  for (const id of ids) {
    const source = plan.sources[id]
    if (!source) continue
    wanted.set(source.path, (wanted.get(source.path) ?? new Set()).add(id))
  }
  const values = new Map<string, SourceValue>()
  for (const [path, list] of wanted) {
    const read = await readSource(path)
    if (!read.ok) {
      for (const id of list) values.set(id, { ok: false, why: read.why })
      continue
    }
    const first = plan.sources[[...list][0] as string] as PlanSource
    const parsed = parseSource(first.type, read.text, home)
    guardFile(guard, path, first.type, parsed.entries)
    for (const id of list) {
      const source = plan.sources[id] as PlanSource
      const entry = parsed.entries.find((e) => e.variable === source.variable && e.pointer === source.pointer)
      if (!entry || entry.value === null || entry.value === "") values.set(id, { ok: false, why: CHANGED })
      else if (!sameClass(source, entry.value)) values.set(id, { ok: false, why: CHANGED })
      else values.set(id, { ok: true, value: entry.value })
    }
  }
  return values
}
