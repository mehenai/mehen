// mehen adopt verify: prove the vault copy works without the local files,
// in three parts (design section 16.2). Coverage: every name in each source
// of a repo or service is provided by Mehen for that environment or skipped
// in the plan, so a framework that loads .env by itself cannot hide a gap.
// The env check: `mehen env check` per target and environment. Live checks:
// one read-only call through relay per item whose template defines one.
// Results are names, slugs, statuses and reasons; never a value.

import { join } from "node:path"
import { getTemplate } from "@mehen/protocol/templates"
import { relayRequest } from "../operations.ts"
import { VaultApiError } from "../vault-api.ts"
import { type ApplyContext, type CheckResult, type StoredItems, envCheck, mappedItem } from "./apply.ts"
import type { OutputGuard } from "./output-guard.ts"
import { type ParseError, parseSource } from "./parse.ts"
import { type AdoptPlan, type PlanItem, type VarMapping, usesAdoptedItem } from "./plan.ts"
import { readSource, sourceType } from "./sources.ts"
import type { VerifyResult } from "./state.ts"
import { guardFile, guardPlan } from "./values.ts"

export type CoverageRow = { file: string; env: string; variable: string; state: "covered" | "skipped" | "gap"; why: string | null }
export type TargetVerify = { target: string; kind: "repo" | "service"; checks: CheckResult[]; coverage: CoverageRow[] }
export type ItemVerify = VerifyResult & { ref: string; why: string | null }
export type VerifyReport = { ok: boolean; targets: TargetVerify[]; items: ItemVerify[] }

export type VerifyOptions = { repos: string[] | null; session: string | null; now: Date }

type Source = { file: string; env: string; vars: Record<string, VarMapping> }

// The names in one source file as it is now, and the lines that did not
// parse; values are only added to the guard.
export async function namesIn(plan: AdoptPlan, path: string, home: string, guard: OutputGuard): Promise<{ names: string[]; errors: ParseError[]; why: string | null }> {
  const type = Object.values(plan.sources).find((s) => s.path === path)?.type ?? sourceType(path)
  if (type === null) return { names: [], errors: [], why: "not a file adopt reads" }
  const read = await readSource(path)
  if (!read.ok) return { names: [], errors: [], why: read.why }
  const parsed = parseSource(type, read.text, home)
  guardFile(guard, path, type, parsed.entries)
  return { names: [...new Set(parsed.entries.flatMap((e) => (e.variable === null ? [] : [e.variable])))], errors: parsed.errors, why: null }
}

// An item the plan leaves out on purpose: a variable mapped to it is skipped, not a gap.
function unticked(plan: AdoptPlan, ref: string): boolean {
  const item = plan.items.find((i) => i.ref === ref)
  return item !== undefined && !item.include && !item.exists
}

async function verifyTarget(plan: AdoptPlan, stored: StoredItems, kind: "repo" | "service", target: string, dir: string, sources: Source[], ctx: ApplyContext): Promise<TargetVerify> {
  const checks = new Map<string, CheckResult>()
  for (const env of new Set(sources.map((s) => s.env))) checks.set(env, await envCheck(dir, env, ctx))
  const coverage: CoverageRow[] = []
  for (const source of sources) {
    const check = checks.get(source.env) as CheckResult
    const { names, errors, why } = await namesIn(plan, source.file, ctx.home, ctx.guard)
    if (why !== null) coverage.push({ file: source.file, env: source.env, variable: "*", state: "gap", why: `the file ${why}` })
    // A line dotenv may load but this parser rejected could hide a name.
    for (const e of errors) coverage.push({ file: source.file, env: source.env, variable: `line ${e.line}`, state: "gap", why: e.why })
    for (const variable of names) {
      const mapping = source.vars[variable]
      const row = { file: source.file, env: source.env, variable }
      if (mapping === undefined) coverage.push({ ...row, state: "gap", why: "not in the plan" })
      else if ("skip" in mapping) coverage.push({ ...row, state: "skipped", why: mapping.skip })
      else if ("item" in mapping && unticked(plan, mapping.item)) coverage.push({ ...row, state: "skipped", why: (mappedItem(plan, stored, mapping.item) as { why: string }).why })
      else if (check.why !== null) coverage.push({ ...row, state: "gap", why: check.why })
      else if (!check.declared.includes(variable)) coverage.push({ ...row, state: "gap", why: "not declared in mehen.toml" })
      else if (check.unresolved.includes(variable)) coverage.push({ ...row, state: "gap", why: `does not resolve for env=${source.env}` })
      else coverage.push({ ...row, state: "covered", why: null })
    }
  }
  return { target, kind, checks: [...checks.values()], coverage }
}

// The project and environment a project credential is used for: the first
// mapping of it in the plan.
function useContext(plan: AdoptPlan, item: PlanItem, ctx: ApplyContext): { project: string; environment: string } | null {
  if (item.home.kind !== "project") return null
  const mapped = (vars: Record<string, VarMapping>) => Object.values(vars).some((m) => "item" in m && m.item === item.ref)
  const targets = [
    ...plan.repos.flatMap((r) => r.files.filter((f) => mapped(f.vars)).map((f) => ({ project: r.project, env: f.env }))),
    ...plan.services.filter((s) => mapped(s.vars)).map((s) => ({ project: s.project, env: s.env })),
  ]
  for (const t of targets) {
    const id = t.project.id ?? ctx.projects[t.project.slug]
    if (id && (item.home.project === t.project.slug || item.home.project === id)) return { project: id, environment: t.env }
  }
  return null
}

async function liveCheck(plan: AdoptPlan, item: PlanItem, slug: string, ctx: ApplyContext, options: VerifyOptions): Promise<ItemVerify> {
  const row = { ref: item.ref, slug, at: options.now.toISOString() }
  const template = item.provider ? getTemplate(item.provider) : null
  const host = template?.binding.hosts?.[0]
  if (!template?.check || !host || /[*{]/.test(host)) return { ...row, check: "none", status: null, why: "its template has no read-only check" }
  const request = relayRequest({ item: slug, run: null, method: template.check.method, url: `https://${host}${template.check.path}`, headers: template.check.headers ?? [], body: null, approval: null, session: options.session, context: useContext(plan, item, ctx) })
  try {
    const response = await ctx.api.relay(request)
    await response.body?.cancel()
    const ok = response.status >= 200 && response.status < 300
    return { ...row, check: ok ? "ok" : "failed", status: response.status, why: ok ? null : `${template.check.method} ${template.check.path} answered ${response.status}` }
  } catch (error) {
    if (error instanceof VaultApiError) return { ...row, check: "refused", status: null, why: `the vault refused the call: ${error.body.error}` }
    return { ...row, check: "failed", status: null, why: "the call did not complete" }
  }
}

export async function verifyPlan(plan: AdoptPlan, stored: StoredItems, ctx: ApplyContext, options: VerifyOptions): Promise<VerifyReport> {
  guardPlan(ctx.guard, plan)
  const targets: TargetVerify[] = []
  for (const repo of plan.repos) {
    if (options.repos !== null && !options.repos.includes(repo.root)) continue
    // Apply binds only these (no mehen.toml elsewhere), so the names of a
    // repo it left alone are not gaps; retire still holds its files.
    if (!repo.files.some((f) => usesAdoptedItem(plan, f.vars))) continue
    targets.push(await verifyTarget(plan, stored, "repo", repo.root, repo.root, repo.files.map((f) => ({ file: join(repo.root, f.path), env: f.env, vars: f.vars })), ctx))
  }
  if (options.repos === null) {
    for (const service of plan.services) {
      if (!usesAdoptedItem(plan, service.vars)) continue
      const files = [service.unit, ...(service.envFile ? [service.envFile] : [])]
      targets.push(await verifyTarget(plan, stored, "service", service.unit, service.dir, files.map((file) => ({ file, env: service.env, vars: service.vars })), ctx))
    }
  }
  const items: ItemVerify[] = []
  for (const item of plan.items) {
    if (!item.include && !item.exists) continue
    const mapped = mappedItem(plan, stored, item.ref)
    if ("why" in mapped) continue
    items.push(await liveCheck(plan, item, mapped.slug, ctx, options))
  }
  const ok = targets.every((t) => t.checks.every((c) => c.ok) && t.coverage.every((c) => c.state !== "gap")) && items.every((i) => i.check === "ok" || i.check === "none")
  return { ok, targets, items }
}
