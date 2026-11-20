import { basename } from "node:path"
import { normaliseWorkspaceSlug } from "@mehen/protocol/workspace"
import { z } from "zod"
import { relativeExpiry } from "../ask.ts"
import { followAttempt } from "../commands/activate.ts"
import { SETTLED_CODES, enrolmentResult, waitOutput } from "../commands/intake.ts"
import { type Config, workspaceLabel } from "../config.ts"
import { readEnrolmentRecord } from "../enrolment-record.ts"
import { CliError, toCliError } from "../errors.ts"
import { rootAboveSlot } from "../home.ts"
import { findLedgerEntry, ledgerOrigins, readLedger, readLegacyEnrolments, removeLedgerEntry } from "../ledger.ts"
import { type WaitLedger, type WaitTarget, waitFor, waitTarget } from "../operations.ts"
import { notEnrolled, openEnrolmentSession, pollIntervalMs } from "../session.ts"
import { contextMatches, workspaceMismatch, workspaceUnbound } from "../slots.ts"
import { isPinned, latchActivated, resolveSlot, spanSlots, workspaceArgument } from "./binding.ts"
import { type JsonRpcNotification, type ProgressToken, type SpanSlot, type ToolCall, type ToolDeps, type ToolOutput, WORKSPACE_ARG, plain, tool } from "./shared.ts"
import { WAIT_DEFAULT_SECONDS, WAIT_MAX_SECONDS, PROGRESS_INTERVAL_MS } from "./constants.ts"

// "waiting for approval apr_7Hq2; the link expires in 48 min": ids, fixed
// words and a relative time only. The id was checked by waitTarget.
export function progressMessage(target: WaitTarget, id: string, expiresAt: string | null, now: Date): string {
  const base = `waiting for ${target.label.toLowerCase()} ${id}`
  const relative = expiresAt ? relativeExpiry(expiresAt, now) : null
  if (relative === "expired") return `${base}; the link has expired`
  return relative ? `${base}; the link expires ${relative}` : base
}

// notifications/progress for a vault_wait that carried a progressToken: once
// when the vault first says the ask is still open, then every 10 s. With no
// token nothing is sent. Carries elapsed and total seconds and the message;
// never a value, a body or a header.
class WaitProgress {
  private timer: ReturnType<typeof setInterval> | null = null
  private sent = false
  private stopped = false
  private expiresAt: string | null
  private readonly startedAt = Date.now()

  constructor(
    private readonly target: WaitTarget,
    private readonly id: string,
    private readonly options: { token: ProgressToken | null; totalSeconds: number; expiresAt: string | null; notify: (notification: JsonRpcNotification) => void },
  ) {
    this.expiresAt = options.expiresAt
  }

  // Nothing is sent without a token, and nothing once the call is cancelled.
  start(signal: AbortSignal): void {
    if (this.options.token === null) return
    this.timer = setInterval(() => this.send(), PROGRESS_INTERVAL_MS)
    signal.addEventListener("abort", () => this.stop(), { once: true })
  }

  pending(expiresAt: string | null): void {
    if (expiresAt) this.expiresAt = expiresAt
    if (this.options.token !== null && !this.sent && !this.stopped) this.send()
  }

  private send(): void {
    this.sent = true
    const now = Date.now()
    this.options.notify({
      jsonrpc: "2.0",
      method: "notifications/progress",
      params: {
        progressToken: this.options.token,
        progress: Math.floor((now - this.startedAt) / 1000),
        total: this.options.totalSeconds,
        message: progressMessage(this.target, this.id, this.expiresAt, new Date(now)),
      },
    })
  }

  stop(): void {
    this.stopped = true
    if (this.timer) clearInterval(this.timer)
    this.timer = null
  }
}

export const vaultWait = tool({
  name: "vault_wait",
  title: "Wait for a human",
  description:
    `Wait for a human to finish an ask: intake (int_), approval (apr_), connection (con_), policy (pol_), adoption (adp_), bundle (bnd_), mandate proposal (mdp_) or an enrolment begun at the terminal (enr_). \`timeout\` means not yet: call again, reminding the human of the link if needed. ` +
    `Default ${WAIT_DEFAULT_SECONDS} s, at most ${WAIT_MAX_SECONDS} s. Decides nothing itself.`,
  input: z.object({
    id: z.string().describe("int_..., apr_..., con_..., pol_..., adp_..., bnd_..., mdp_... or enr_..."),
    timeoutSeconds: z.number().int().min(0).max(WAIT_MAX_SECONDS).optional(),
    workspace: WORKSPACE_ARG,
  }),
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  async call(args, deps, call) {
    const target = waitTarget(args.id)
    const now = new Date()
    const timeoutSeconds = args.timeoutSeconds ?? WAIT_DEFAULT_SECONDS
    if (target.kind === "enrol") return waitEnrolment(args.id, args.workspace ?? null, timeoutSeconds, deps, call)
    const { api, configDir: dir, ledger: scope } = await deps.open(await waitSlot(deps, args.id, args.workspace ?? null))
    const ledger = await readLedger(dir, scope, now)
    const entry = findLedgerEntry(ledger, args.id)
    const known = entry && entry.ask.id === args.id ? entry : null
    const newer = known?.slug ? ledger.slice(ledger.indexOf(known) + 1).filter((e) => e.slug === known.slug && e.ask.kind === known.ask.kind).at(-1) : undefined
    const waitLedger: WaitLedger = { reissueCommand: known?.command ?? null, replacedBy: newer?.ask.id ?? null }
    const progress = new WaitProgress(target, args.id, { token: call.progressToken, totalSeconds: timeoutSeconds, expiresAt: known?.ask.expiresAt ?? null, notify: deps.notify })
    let settled = false
    try {
      progress.start(call.signal)
      const result = await waitFor(api, args.id, {
        timeoutMs: timeoutSeconds * 1000,
        intervalMs: pollIntervalMs(deps.env),
        ledger: waitLedger,
        expiresAt: known?.ask.expiresAt ?? null,
        onPending: (pending) => progress.pending(pending.expiresAt),
        signal: call.signal,
      })
      settled = true
      return plain(waitOutput(args.id, result, scope))
    } catch (error) {
      // Cancelled by the host: nothing settled, nothing to render.
      if (call.signal.aborted) throw error
      const thrown = toCliError(error)
      if (SETTLED_CODES.has(thrown.code)) settled = true
      // A link that is still live goes out again with the error, so the
      // agent can re-hand it.
      const live = thrown.code === "timeout" || thrown.code === "mismatch"
      throw live && known && !thrown.extras.ask ? new CliError(thrown.code, thrown.message, thrown.next, { ...thrown.extras, ask: known.ask }) : thrown
    } finally {
      progress.stop()
      if (settled) await removeLedgerEntry(dir, scope, args.id).catch(() => undefined)
    }
  },
})

function slotNames(slots: { dir: string; config: Config }[]): string {
  return slots.map((s) => `${workspaceLabel(s.config)} at ${s.config.vault} (${s.dir})`).join("; ")
}

// The slot a wait id (int_, apr_, con_, pol_) is followed in: the one active slot this server may use whose ledger
// records it; with none, the only active slot (the vault answers, as
// today). A workspace argument or the pin holds the call to that slot,
// and an id recorded in another one refuses rather than being asked there.
export async function waitSlot(deps: ToolDeps, id: string, workspace: string | null): Promise<SpanSlot> {
  const server = deps.server
  const span = await spanSlots(server)
  if (server.manifest && server.manifest.workspace === null && span.active.length > 1) throw workspaceUnbound(server.manifest.path)
  const hits: SpanSlot[] = []
  for (const slot of span.active) {
    const c = slot.config
    const entries = await readLedger(slot.dir, { vaultUrl: c.vault, workspace: c.tenant, device: c.device, workspaceSlug: c.workspaceSlug ?? null }).catch(() => [])
    if (entries.some((e) => e.ask.id === id)) hits.push(slot)
  }
  if (workspace !== null || server.pin !== null) {
    const chosen = await resolveSlot(server, workspace, { manifest: null })
    if (hits.length > 0 && !hits.some((h) => h.dir === chosen.dir)) {
      throw workspaceMismatch(`${id} is recorded in ${slotNames(hits)}, not in ${workspaceLabel(chosen.config)} at ${chosen.config.vault}, which this call uses.`, {
        say: "Call vault_wait with the workspace the ask was made in (`mehen pending` shows each ask's workspace), or leave workspace out.",
      })
    }
    return chosen
  }
  if (hits.length > 1) {
    throw new CliError("context_ambiguous", `${id} is recorded in ${hits.length} workspaces this server may use: ${slotNames(hits)}.`, { say: "Pass workspace in the call to name the one the ask was made in; `mehen pending` shows each ask's workspace." })
  }
  const only = hits[0] ?? (span.active.length === 1 ? span.active[0] : undefined)
  if (only) return only
  if (span.active.length === 0) throw notEnrolled()
  throw new CliError("not_found", `${id} is not recorded in any workspace this server may use.`, { say: id.startsWith("mdp_") ? "Pass workspace to ask that workspace's vault; `mehen mandate ls` with workspace lists its open mandate proposals." : "`mehen pending` shows what is open and in which workspace; or pass workspace to ask that workspace's vault." })
}

// Does a slot under pending/ that reads as active (the interim form of an
// older activation) still record enrolment `id`?
async function recordsEnrolment(dir: string, id: string): Promise<boolean> {
  const read = await readEnrolmentRecord(dir).catch(() => null)
  if (read && "record" in read && read.record.id === id) return true
  for (const origin of await ledgerOrigins(dir).catch(() => [])) {
    if ((await readLegacyEnrolments(dir, origin).catch(() => [])).some((e) => e.ask.id === id)) return true
  }
  return false
}

// The pending slot that records enrolment `id`, among the slots this server
// may use: one, or the refusal. A slot that already holds an enrolment is
// returned with its config, so the open below refuses it.
async function enrolmentSlot(deps: ToolDeps, id: string, workspace: string | null): Promise<{ dir: string; config: Config | null; slug: string }> {
  const server = deps.server
  const span = await spanSlots(server)
  const hits: { dir: string; config: Config | null; slug: string }[] = span.pending.filter((p) => p.record.id === id).map((p) => ({ dir: p.dir, config: null, slug: p.slug }))
  for (const slot of span.active) {
    if (slot.onDisk && rootAboveSlot(slot.dir)?.kind === "pending" && (await recordsEnrolment(slot.dir, id))) hits.push({ dir: slot.dir, config: slot.config, slug: basename(slot.dir) })
  }
  if (hits.length > 1) {
    throw new CliError("context_ambiguous", `Enrolment ${id} is recorded in ${hits.length} slots this server may use: ${hits.map((h) => h.dir).join("; ")}.`, { say: "Pass workspace in the call to name the one it enrols in." })
  }
  const hit = hits[0]
  // An argument is checked against the ceiling and the pin first.
  if (workspace !== null) await deps.span(workspace)
  const pin = server.pin
  if (hit && pin !== null) {
    // A pinned server finishes only an enrolment that already is its pinned
    // workspace by origin and id; a pending slug proves neither.
    if (!hit.config || !isPinned(server, { dir: hit.dir, config: hit.config, onDisk: true })) {
      throw workspaceMismatch(`Enrolment ${id} is for workspace ${hit.slug} (${hit.dir}), not the workspace this server is pinned to (MEHEN_WORKSPACE=${pin.text}: ${pin.tenant} at ${pin.vault}).`, {
        say: `Wait on the enrolment from a server that may use ${hit.slug}, or at the terminal with \`mehen wait ${id}\`.`,
      })
    }
  } else if (hit && workspace !== null) {
    const selector = workspaceArgument(workspace)
    const answers = hit.config ? contextMatches({ dir: hit.dir, config: hit.config }, selector) : hit.slug === normaliseWorkspaceSlug(selector)
    if (!answers) {
      throw workspaceMismatch(`Enrolment ${id} is for workspace ${hit.slug} (${hit.dir}), not ${selector}, which this call is held to.`, {
        say: "Leave workspace out of the call, or name the workspace the enrolment is for.",
      })
    }
  }
  if (!hit) {
    throw new CliError("not_found", `No open enrolment ${id} is recorded in any workspace this server may use.`, {
      command: "mehen enrol --workspace <slug>",
      say: "Only the machine that started an enrolment can wait on it; run `mehen enrol --workspace <slug>` to start again.",
    })
  }
  return hit
}

// vault_wait enr_...: an enrolment this machine started, in the one
// pending slot this server may use that records it (no other selection),
// followed and finished exactly as mehen wait does. A slot that
// already holds an enrolment refuses before anything is signed.
// The finish step renames the pending slot into workspaces/, and the
// identity it activated is latched for that slot before success is
// reported; later calls use it.
async function waitEnrolment(id: string, workspace: string | null, timeoutSeconds: number, deps: ToolDeps, call: ToolCall): Promise<ToolOutput> {
  const target = waitTarget(id)
  const slot = await enrolmentSlot(deps, id, workspace)
  const opened = await openEnrolmentSession(deps.env, id, { bound: { dir: slot.dir, config: slot.config } })
  deps.used = { vaultUrl: opened.vaultUrl, workspaceSlug: slot.slug }
  const { attempt } = opened
  const progress = new WaitProgress(target, id, { token: call.progressToken, totalSeconds: timeoutSeconds, expiresAt: attempt.record.expiresAt, notify: deps.notify })
  try {
    progress.start(call.signal)
    const followed = await followAttempt(attempt, {
      deadline: Date.now() + timeoutSeconds * 1000,
      intervalMs: pollIntervalMs(deps.env),
      renew: true,
      signal: call.signal,
      onPending: (a) => progress.pending(a.record.expiresAt),
    })
    if (followed.kind === "waiting") {
      throw new CliError("timeout", `Enrolment ${id} is still waiting for a human after ${timeoutSeconds} s; the link stays alive while this machine waits.`, { command: `mehen wait ${id}`, say: "A human has not accepted it yet; call vault_wait again, and remind the human of the link if needed." }, { ask: { ...opened.ask, expiresAt: attempt.record.expiresAt } })
    }
    const { finished } = followed
    await deps.barriers?.afterActivation?.()
    await latchActivated(deps.env, deps.server, finished.slot, finished.config)
    return plain(waitOutput(id, enrolmentResult(finished)))
  } catch (error) {
    if (call.signal.aborted) throw error
    throw toCliError(error)
  } finally {
    progress.stop()
  }
}
