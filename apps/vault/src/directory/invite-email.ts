// A new email-bound invitation's link, emailed to the invitation's own
// address in the request that makes it, when the inviter asks
// (routes/people.ts); migrations/0019.
// - Only then: the vault keeps only the code's hash, so it can never send
//   the link again, and it stores neither the link nor the code.
// - Only to the invitation's own address, from EMAIL_FROM through the EMAIL
//   binding, as the code email (email-proof.ts). The only text the inviter
//   chose in it is their name and the workspace's, each left out when it
//   looks like a link.
// - An inviting account is sent at most 10 an hour and 30 a day, and one
//   address at most 3 a day across every inviter and workspace. Each limit
//   is a condition of the INSERT that counts the send, so requests in
//   parallel cannot pass it. Past one the invitation is still made and its
//   link is not emailed.
// - A send the binding refuses is not counted, and never fails the
//   invitation: the inviter copies the link instead.
import type { InviteEmailed, WorkspaceRole } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { html } from "../ui/html.ts"
import { randomId } from "../vault/core.ts"
import { emailSender, looksLikeLink, sendErrorCode } from "./email-proof.ts"
import { oidcConfigured } from "./oidc.ts"

// Whether this vault can complete an email-bound invitation: the invitee
// proves the address with Google or with a code the vault emails. A vault
// with neither (the local host sets no Google client and no EMAIL binding)
// invites by link only, and an owner or admin confirms whoever joins.
export function emailInvitesCompletable(env: Env): boolean {
  return oidcConfigured(env) || Boolean(env.EMAIL && env.EMAIL_FROM)
}
export const EMAIL_INVITES_UNAVAILABLE = "This vault cannot verify an email address, so nobody could complete an invitation bound to one. Invite by link instead: anyone with the link may join, and you confirm them once they have joined."

export const INVITE_EMAILS_PER_INVITER_HOUR = 10
export const INVITE_EMAILS_PER_INVITER_DAY = 30
export const INVITE_EMAILS_PER_ADDRESS_DAY = 3
const HOUR_MS = 3_600_000
const DAY_MS = 86_400_000

const ROLE_WORDS: Record<WorkspaceRole, string> = { owner: "an owner", admin: "an admin", member: "a member", guest: "a guest" }
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]

// "9 November 2026 at 18:00 UTC".
function utcWords(iso: string): string {
  const at = new Date(iso), pad = (n: number) => String(n).padStart(2, "0")
  return `${at.getUTCDate()} ${MONTHS[at.getUTCMonth()]} ${at.getUTCFullYear()} at ${pad(at.getUTCHours())}:${pad(at.getUTCMinutes())} UTC`
}

// A name that could become a link, or that carries a control, format or
// line separator character into the subject line or body, is left out.
function plainName(name: string): string | null {
  const trimmed = name.trim()
  return trimmed === "" || looksLikeLink(trimmed) || /[\p{C}\p{Zl}\p{Zp}]/u.test(trimmed) ? null : trimmed
}

export function inviteLinkEmail(input: { from: string; to: string; url: string; workspace: string; inviter: string; role: WorkspaceRole; expiresAt: string }): EmailMessageBuilder {
  const inviter = plainName(input.inviter) ?? "Someone"
  const named = plainName(input.workspace)
  const invited = `${inviter} invited you to ${named === null ? "a workspace" : `the ${named} workspace`} on Mehen, as ${ROLE_WORDS[input.role]}.`
  const works = `The link works once, and only for this email address. It expires on ${utcWords(input.expiresAt)}.`
  const ignore = "If you were not expecting this, ignore it: nothing happens until you open the link and prove this address."
  const text = [invited, "", "Open this link to join:", input.url, "", works, "", ignore].join("\n")
  const body = html`<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1a1a1a;line-height:1.5">
<p>${invited}</p>
<p><a href="${input.url}" style="display:inline-block;padding:10px 16px;background:#1a1a1a;color:#ffffff;border-radius:6px;text-decoration:none;font-weight:600">Open the invitation</a></p>
<p style="font-family:ui-monospace,Menlo,monospace;font-size:13px;word-break:break-all">${input.url}</p>
<p>${works}</p>
<p style="color:#666">${ignore}</p>
</body></html>`
  return { from: emailSender(input.from), to: input.to, subject: `${inviter} invited you to ${named ?? "a workspace"} on Mehen`, text, html: body.value }
}

// Counts the send within the limits, then sends; "limited" counts nothing,
// and a refused send is uncounted again.
export async function emailInviteLink(env: Env, input: { to: string; inviterAccount: string; workspace: { id: string; name: string }; inviter: string; role: WorkspaceRole; url: string; expiresAt: string }, now = Date.now()): Promise<Exclude<InviteEmailed, "not_requested">> {
  if (!env.EMAIL || !env.EMAIL_FROM) {
    console.error(JSON.stringify({ at: "invite.email.send", error: "unconfigured" }))
    return "failed"
  }
  const id = randomId("ivm")
  const counted = await env.DB.prepare(`INSERT INTO invite_emails(id,email,inviter,workspace,created_at)
    SELECT ?,?,?,?,? WHERE (SELECT COUNT(*) FROM invite_emails WHERE inviter=? AND created_at>?)<? AND (SELECT COUNT(*) FROM invite_emails WHERE inviter=? AND created_at>?)<? AND (SELECT COUNT(*) FROM invite_emails WHERE email=? AND created_at>?)<?`)
    .bind(id, input.to, input.inviterAccount, input.workspace.id, now, input.inviterAccount, now - HOUR_MS, INVITE_EMAILS_PER_INVITER_HOUR, input.inviterAccount, now - DAY_MS, INVITE_EMAILS_PER_INVITER_DAY, input.to, now - DAY_MS, INVITE_EMAILS_PER_ADDRESS_DAY).run()
  if (counted.meta.changes !== 1) return "limited"
  try {
    await env.EMAIL.send(inviteLinkEmail({ from: env.EMAIL_FROM, to: input.to, url: input.url, workspace: input.workspace.name, inviter: input.inviter, role: input.role, expiresAt: input.expiresAt }))
  } catch (error) {
    await env.DB.prepare("DELETE FROM invite_emails WHERE id=?").bind(id).run()
    console.error(JSON.stringify({ at: "invite.email.send", error: sendErrorCode(error) }))
    return "failed"
  }
  return "sent"
}

// Rows past the day the limits count.
export function inviteEmailSweep(env: Env, now: number): D1PreparedStatement { return env.DB.prepare("DELETE FROM invite_emails WHERE created_at<=?").bind(now - DAY_MS) }
