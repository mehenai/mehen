import { isLeaseOnly } from "@mehen/protocol/binding"
import type { ItemSummary } from "@mehen/protocol/api"
import { z } from "zod"
import { type CliErrorCode, toCliError } from "../errors.ts"
import { listItems } from "../operations.ts"
import { notEnrolled } from "../session.ts"
import type { ItemWorkspace } from "../commands/items.ts"
import { READS, WORKSPACE_ARG, outputSchema, plain, tool } from "./shared.ts"

export const LIST_PAGE_DEFAULT = 100
export const LIST_PAGE_MAX = 200

// One item as vault_list answers it: what an agent picks an item by, and
// nothing a host would pay for on every row. vault_show has the rest.
// `workspace` is the id, since two workspaces may share a slug; the answer
// names each workspace once.
export type ListRow = {
  slug: string
  workspace: string
  kind: ItemSummary["kind"]
  provider?: string
  account?: string
  status: ItemSummary["status"]
  ceiling: ItemSummary["ceiling"]
  hosts: string[]
  leaseOnly?: true
  review?: { reason: string; since: string }
}

export function listRow(item: ItemSummary, workspace: string): ListRow {
  const leaseOnly = isLeaseOnly(item)
  return {
    slug: item.slug,
    workspace,
    kind: item.kind,
    ...(item.provider ? { provider: item.provider } : {}),
    ...(item.account ? { account: item.account } : {}),
    status: item.status,
    ceiling: item.ceiling,
    hosts: leaseOnly ? [] : item.hosts,
    ...(leaseOnly ? { leaseOnly: true as const } : {}),
    ...(item.review ? { review: item.review } : {}),
  }
}

function matches(row: ListRow, search: string | undefined): boolean {
  if (!search) return true
  const wanted = search.toLowerCase()
  return row.slug.toLowerCase().includes(wanted) || (row.account?.toLowerCase().includes(wanted) ?? false)
}

export const vaultList = tool({
  name: "vault_list",
  title: "List credentials",
  description:
    `List the credentials (items) this machine may use, across every workspace this server may use (or the one named), ${LIST_PAGE_DEFAULT} at a time, one short row each, with \`review\` when a human should look at one. vault_show gives one item in full. Never returns values.`,
  input: z.object({
    tag: z.string().optional().describe("only items with this tag"),
    kind: z.string().optional().describe("only items of this kind, e.g. api-key"),
    provider: z.string().optional().describe("only items from this provider template, e.g. openai"),
    search: z.string().optional().describe("only items whose slug or account contains this text"),
    offset: z.number().int().min(0).optional().describe("skip this many items: the last answer's nextOffset"),
    limit: z.number().int().min(1).max(LIST_PAGE_MAX).optional().describe(`at most this many items; default ${LIST_PAGE_DEFAULT}`),
    workspace: WORKSPACE_ARG,
  }),
  annotations: READS,
  output: outputSchema({ workspaces: "array", items: "array", total: "integer", nextOffset: "integer", unavailable: "array" }),
  async call(args, deps) {
    const { workspace, search, offset = 0, limit = LIST_PAGE_DEFAULT, ...filters } = args
    const span = await deps.span(workspace ?? null)
    if (span.active.length === 0) throw notEnrolled()
    // As mehen ls: a workspace whose vault cannot be asked is left out and
    // named; when every one fails, the first failure is the answer.
    const rows: ListRow[] = []
    const workspaces: ItemWorkspace[] = []
    const unavailable: { slot: string; error: CliErrorCode; message: string }[] = []
    let firstFailure: unknown = null
    for (const slot of span.active) {
      try {
        const { api, config } = await deps.open(slot)
        const { items } = await listItems(api, filters)
        workspaces.push({ id: config.tenant, slug: config.workspaceSlug ?? null, name: config.workspaceName ?? null })
        for (const item of items) {
          const row = listRow(item, config.tenant)
          if (matches(row, search)) rows.push(row)
        }
      } catch (error) {
        firstFailure ??= error
        const failure = toCliError(error)
        unavailable.push({ slot: slot.dir, error: failure.code, message: failure.message })
      }
    }
    if (unavailable.length === span.active.length) throw firstFailure
    const end = offset + limit
    return plain({ workspaces, items: rows.slice(offset, end), total: rows.length, ...(end < rows.length ? { nextOffset: end } : {}), ...(unavailable.length ? { unavailable } : {}) })
  },
})
