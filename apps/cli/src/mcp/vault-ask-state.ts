import { z } from "zod"
import { CliError, toCliError, usageError } from "../errors.ts"
import { findLedgerEntry, readLedger } from "../ledger.ts"
import { type WaitKind, waitFor, waitTarget } from "../operations.ts"
import { pollIntervalMs } from "../session.ts"
import { READS, WORKSPACE_ARG, plain, tool } from "./shared.ts"
import { waitSlot } from "./vault-wait.ts"

export const ASK_STATE_MAX_SECONDS = 25

export type AskState = "waiting" | "done" | "declined" | "expired" | "cancelled" | "stale" | "failed" | "mismatch"

// A refusal settle throws, as the state the card shows.
const STATE_FOR_CODE: ReadonlyMap<CliError["code"], AskState> = new Map<CliError["code"], AskState>([
  ["timeout", "waiting"],
  ["denied", "declined"],
  ["expired", "expired"],
  ["cancelled", "cancelled"],
  ["stale", "stale"],
  // What the vault said for a replaced approval before mehen 0.3.17.
  ["superseded", "stale"],
  ["failed", "failed"],
  ["provider_refused", "failed"],
  ["mismatch", "mismatch"],
])

const DONE: Record<Exclude<WaitKind, "enrol">, string> = {
  intake: "The credential was added to the vault.",
  approval: "The request was approved.",
  connect: "The account was connected.",
  policy: "The policy change was approved.",
  adoption: "The adoption batch was approved.",
  bundle: "Every request in the bundle was approved.",
  mandate: "A mandate was signed for this machine.",
}

// The card's own read of an ask (MCP Apps, visibility ["app"]: never listed
// to the model). vault_wait would not do: it drops a settled ask from the
// ledger, which the agent's own later vault_wait needs to find the
// workspace, and an enr_ wait finishes an enrolment. This only reads: the
// ledger is never written and the vault's status object is not passed on.
export const vaultAskState = tool({
  name: "vault_ask_state",
  title: "An ask's state",
  description:
    "For Mehen's ask card: the state of an intake (int_), approval (apr_), connection (con_), policy proposal (pol_), adoption batch (adp_) or bundle (bnd_) this machine asked for: waiting, done, declined, expired, cancelled, stale, failed or mismatch. " +
    `Reads only; waits up to waitSeconds (at most ${ASK_STATE_MAX_SECONDS}, default 0) for a change. Decides nothing.`,
  input: z.object({
    id: z.string().describe("int_..., apr_..., con_..., pol_..., adp_... or bnd_..."),
    workspace: WORKSPACE_ARG,
    waitSeconds: z.number().int().min(0).max(ASK_STATE_MAX_SECONDS).optional(),
  }),
  annotations: READS,
  async call(args, deps, call) {
    const target = waitTarget(args.id)
    if (target.kind === "enrol") throw usageError(`vault_ask_state follows intake, approval, connection, policy proposal, adoption and bundle ids, not an enrolment (${args.id}).`)
    const kind = target.kind
    const { api, configDir: dir, ledger: scope } = await deps.open(await waitSlot(deps, args.id, args.workspace ?? null))
    const entry = findLedgerEntry(await readLedger(dir, scope, new Date()), args.id)
    const known = entry && entry.ask.id === args.id ? entry : null
    let expiresAt = known?.ask.expiresAt ?? null
    const state = (state: AskState, message: string) => plain({ id: args.id, kind, state, expiresAt, message })
    try {
      const result = await waitFor(api, args.id, {
        timeoutMs: (args.waitSeconds ?? 0) * 1000,
        intervalMs: pollIntervalMs(deps.env),
        ledger: { reissueCommand: known?.command ?? null, replacedBy: null },
        expiresAt,
        onPending: (pending) => {
          expiresAt = pending.expiresAt
        },
        signal: call.signal,
      })
      const settledAt = (result.status as { expiresAt?: unknown }).expiresAt
      if (typeof settledAt === "string") expiresAt = settledAt
      return state("done", DONE[kind])
    } catch (error) {
      if (call.signal.aborted) throw error
      const thrown = toCliError(error)
      const mapped = STATE_FOR_CODE.get(thrown.code)
      if (mapped === undefined) throw thrown
      return state(mapped, thrown.message)
    }
  },
})
