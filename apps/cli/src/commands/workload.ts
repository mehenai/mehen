// mehen workload ls and mehen workload revoke <id>: this machine's live
// workloads (short-lived child keys its harness created, each scoped
// narrower than the machine) and the way to end one. Both are signed by the
// device key, the only key that may manage workloads.
//
// There is no create: a workload's key must live with the process that runs
// the task, so a harness creates it with a client library (@mehen/client),
// never a second key on this machine's disk.
//
// A label is chosen by the program that created the workload, never checked
// by the vault, so every line that shows one marks it as the machine's words.

import { EXIT } from "@mehen/protocol/api"
import { type WorkloadList, WorkloadListSchema, type WorkloadScope, type WorkloadView, WorkloadIdSchema, WorkloadViewSchema } from "@mehen/protocol/workload"
import type { Command } from "../command.ts"
import { CliError, usageError } from "../errors.ts"
import { printJson, printLine, table } from "../output.ts"
import { openSession } from "../session.ts"
import { type Text, segments } from "../tty.ts"

export const HARNESS_GUIDE_URL = "https://docs.mehen.dev/guides/harnesses#one-workload-per-task"

const USAGE = "mehen workload ls | revoke <wl_id>"

// What a workload may use, in words: each field narrows the machine's scope,
// and a workload that names none has the machine's whole scope.
export function workloadScopeWords(scope: WorkloadScope): string {
  const parts = [
    ...(scope.items ? [`only ${scope.items.join(", ")}`] : []),
    ...(scope.tags ? [`items tagged ${scope.tags.join(", ")}`] : []),
    ...(scope.projects ? [`projects ${scope.projects.join(", ")}`] : []),
    ...(scope.modes ? [`modes ${scope.modes.join(", ")}`] : []),
  ]
  return parts.length ? parts.join("; ") : "everything this machine may use"
}

export const LABEL_NOTE = "Labels are this machine's own words: the program that created each workload chose them, and the vault does not check them."

// WORKLOAD, LABEL, SCOPE, EXPIRES, LAST SEEN, then the label note.
export function workloadLines(list: WorkloadList): Text[] {
  if (list.workloads.length === 0) return ["No live workloads on this machine."]
  const rows: Text[][] = [["WORKLOAD", "LABEL", "SCOPE", "EXPIRES", "LAST SEEN"]]
  for (const w of list.workloads) rows.push([w.workload, w.label, workloadScopeWords(w.scope), w.expiresAt, w.lastSeenAt ?? "never"])
  return [...table(rows), "", LABEL_NOTE]
}

const REVOKED_BY: Record<NonNullable<WorkloadView["revokedBy"]>, string> = {
  device: "by this machine",
  member: "by a person on the machine's page",
  device_revoked: "because its machine was revoked",
  owner_inactive: "because its owner lost access",
}

export function revokedLine(view: WorkloadView): string {
  const who = `${view.workload} (${view.label}, as this machine named it)`
  if (view.state === "expired") return `Workload ${who} had already expired; it can do nothing.`
  const by = view.revokedBy ? ` ${REVOKED_BY[view.revokedBy]}` : ""
  return `Workload ${who} is revoked${by}${view.revokedAt ? ` at ${view.revokedAt}` : ""}; it can do nothing.`
}

function unexpected(what: string): CliError {
  return new CliError("internal", `The vault's answer to ${what} did not have the shape mehen expects.`, { command: "mehen doctor", say: "Check the vault URL with `mehen doctor`; if it is right, the vault may be newer or older than this mehen." })
}

export async function listWorkloads(env: Record<string, string | undefined>): Promise<WorkloadList> {
  const { api } = await openSession(env)
  const parsed = WorkloadListSchema.safeParse(await api.request<unknown>("GET", "/v1/workloads"))
  if (!parsed.success) throw unexpected("GET /v1/workloads")
  return parsed.data
}

// DELETE /v1/workloads/:id, idempotent at the vault: a workload that has
// already ended answers as it ended.
export async function revokeWorkload(env: Record<string, string | undefined>, id: string): Promise<WorkloadView> {
  const { api } = await openSession(env)
  const parsed = WorkloadViewSchema.safeParse(await api.request<unknown>("DELETE", `/v1/workloads/${encodeURIComponent(id)}`))
  if (!parsed.success || parsed.data.workload !== id) throw unexpected(`DELETE /v1/workloads/${id}`)
  if (parsed.data.state === "active") throw new CliError("internal", `The vault answered that workload ${id} is still active after revoking it.`, { say: "Run `mehen workload ls` to see whether it is still live, and tell the human." })
  return parsed.data
}

export const workloadCommand: Command = {
  summary: "list this machine's live workloads, or revoke one (a harness creates them with @mehen/client)",
  spec: { usage: USAGE, flags: {}, positionals: { min: 1, max: 2 } },
  examples: [["workload", "ls"], ["workload", "ls", "--json"], ["workload", "revoke", "wl_example1234"]],
  notes: [
    "A workload is a short-lived child key this machine's harness created for one task, scoped narrower than the machine. ls lists the live ones: id, label (the machine's own words), scope, expiry and last use.",
    "revoke ends one at once and is safe to repeat. Both are signed by this machine's own key.",
    `mehen does not create workloads: a workload's key must stay with the process that runs the task, so a harness creates one with @mehen/client (${HARNESS_GUIDE_URL}).`,
  ],
  async run({ args, json, env }) {
    const [action, id] = args.positionals
    if (action === "create") throw usageError(`mehen does not create workloads: a workload's key must stay with the process that runs the task. A harness creates one with @mehen/client; see ${HARNESS_GUIDE_URL}.`, "mehen workload --help")
    if (action === "ls") {
      if (id !== undefined) throw usageError(`Usage: ${USAGE}`, "mehen workload --help")
      const list = await listWorkloads(env)
      if (json) printJson(list)
      else for (const line of workloadLines(list)) printLine(line)
      return EXIT.ok
    }
    if (action === "revoke") {
      if (id === undefined) throw usageError(`Usage: ${USAGE}`, "mehen workload --help")
      if (!WorkloadIdSchema.safeParse(id).success) throw usageError(`${JSON.stringify(id)} is not a workload id (wl_ followed by 8 to 64 letters, digits, '_' or '-'); \`mehen workload ls\` lists them.`, "mehen workload --help")
      const view = await revokeWorkload(env, id)
      if (json) printJson(view)
      else printLine(segments(revokedLine(view)))
      return EXIT.ok
    }
    throw usageError(`Unknown workload action ${JSON.stringify(action)}. Usage: ${USAGE}`, "mehen workload --help")
  },
}
