import { z } from "zod"
import { refusedLinkWarning } from "../ask.ts"
import { listPending, pendingGroupText, pendingNoticeText } from "../commands/pending.ts"
import { READS, WORKSPACE_ARG, mcpThen, outputSchema, tool } from "./shared.ts"

export const vaultPending = tool({
  name: "vault_pending",
  title: "Open asks",
  description: "Everything this machine has asked a human for that is still open, across every workspace this server may use (or the one named): intakes, connections, approvals, policy proposals and enrolments it started. Approvals a human can review together carry `group`, listed in `groups`. Each has an ask with its checked link, so a conversation that lost the link can hand it over again. Asks from an unreachable vault carry `stale: true`, never handed over. Member-only policy reviews are not included. Creates and extends nothing.",
  input: z.object({ workspace: WORKSPACE_ARG }),
  annotations: READS,
  output: outputSchema({ pending: "array", groups: "array", notices: "array", warning: "string" }),
  async call(args, deps) {
    const span = await deps.span(args.workspace ?? null)
    const { items, notices, groups, vaultUrl, refusedLinks, unavailable } = await listPending(deps.env, new Date(), { active: span.active, pending: span.pending, open: (slot) => deps.open({ ...slot, onDisk: true }) })
    const pending = items.map((i) => (i.stale ? { ...i.ask, stale: true } : i.ask))
    const warnings = [
      ...unavailable.map((gone) => `the vault for ${gone.slot} could not be asked (${gone.error}: ${gone.message}); its asks are listed from this machine's record${gone.error === "network" ? ", marked stale: the vault may have settled them, so do not hand their links over as live" : ""}.`),
      ...(refusedLinks > 0 ? [`${refusedLinks === 1 ? "one pending entry" : `${refusedLinks} pending entries`} came with a link not on the vault or an id mehen does not know; ${refusedLinkWarning(vaultUrl)}`] : []),
    ]
    const warning = warnings.length ? warnings.join(" ") : null
    return {
      structured: { pending, ...(groups.length ? { groups } : {}), ...(notices.length ? { notices } : {}), ...(warning ? { warning } : {}) },
      text: [...notices.map(pendingNoticeText), ...groups.map((group) => pendingGroupText(group, pending))],
      handover: items.filter((i) => !i.stale).map(({ ask }) => ({ ask, then: mcpThen(ask) })),
      warning,
    }
  },
})
