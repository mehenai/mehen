// An email-bound invitation's address proved by a six-digit code the vault
// emails to it, beside Google's proof (oidc-flow.ts); migrations/0016.
// - The code goes to the invitation's own address, never one the person
//   types, through Cloudflare Email Sending (the EMAIL send_email binding,
//   from EMAIL_FROM).
// - It comes from the CSPRNG and is stored only as an HMAC of the row id and
//   the code, under a key derived from ROOT_KEYS, so a copy of D1 alone
//   cannot recover it.
// - It lasts ten minutes and dies after five wrong tries; an invitation gets
//   at most three a rolling hour and five a rolling day, and a new one
//   replaces the one before. An invitation takes at most ten wrong tries a
//   rolling day across all its codes, so guessing is bounded over its life.
//   One address is sent at most five codes an hour and ten a day across all
//   its invitations, however many are made for it, so nobody can bomb an
//   inbox or burn Mehen's sending reputation with invitations. Each limit is
//   a condition of the INSERT or UPDATE it guards, so requests in parallel
//   cannot pass it.
// - Typed back, the row is a proof for ten minutes, bound to the browser
//   that asked by its __Host-mehen_email cookie. The signup and the join
//   take it where they take a Google result (workspace-accounts.ts,
//   workspace-invites.ts).
// It proves control of the inbox at that moment, as Google does, and carries
// no Google Workspace domain, so it never satisfies a workspace identity rule.
import { base64UrlEncode, timingSafeEqualText, utf8 } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { html } from "../ui/html.ts"
import { EMAIL_CODE_FAILED_WORDS, EMAIL_CODE_GOOGLE_ONLY_WORDS } from "../ui/pages/email-code.ts"
import { randomId } from "../vault/core.ts"
import { parseRootKeys } from "../vault/keys.ts"
import type { AccountWebSession } from "./account-session.ts"
import { accountGuard } from "./account-store.ts"
import { inviteIdentityContext } from "./oidc-flow.ts"
import { randomToken, readCookie, sha256Text } from "./session.ts"
import { directoryWorkspaceClient } from "./workspace-client.ts"

export const EMAIL_COOKIE = "__Host-mehen_email"
export const EMAIL_CODE_TTL_MS = 600_000
export const EMAIL_PROOF_TTL_MS = 600_000
export const EMAIL_CODE_TRIES = 5
export const EMAIL_CODE_SENDS_PER_HOUR = 3
export const EMAIL_CODE_SENDS_PER_DAY = 5
export const EMAIL_CODE_WRONG_TRIES_PER_DAY = 10
export const EMAIL_ADDRESS_SENDS_PER_HOUR = 5
export const EMAIL_ADDRESS_SENDS_PER_DAY = 10
const HOUR_MS = 3_600_000
const DAY_MS = 86_400_000

export type EmailProof = { id: string; invite_hash: string; email: string; cookie_hash: string; account: string | null; session: string | null; security_epoch: number | null; created_at: number; expires_at: number; state: "verified" | "joining"; joining_membership: string | null }
export const EMAIL_PROOF_COLUMNS = "id,invite_hash,email,cookie_hash,account,session,security_epoch,created_at,expires_at,state,joining_membership"

// The page says the same words (ui/pages/email-code.ts).
export const EMAIL_SEND_FAILED = EMAIL_CODE_FAILED_WORDS
export const EMAIL_IDENTITY_RULE = EMAIL_CODE_GOOGLE_ONLY_WORDS
export function emailSendFailed(): VaultError { return new VaultError("upstream_failed",EMAIL_SEND_FAILED) }
export function emailIdentityRuleRefusal(): VaultError { return new VaultError("identity_required",EMAIL_IDENTITY_RULE) }
// A proof the signup or the join cannot use: unknown, another browser's,
// lapsed or spent. The page asks for a new code or Google.
export function emailProofRefusal(): VaultError { return new VaultError("identity_required","The emailed code could not be checked. Send a new code from the page that asked for it.") }
function emailCodeDead(): VaultError { return new VaultError("bad_request","That code has expired, been replaced or had too many wrong tries. Send a new code.") }
// The invitation's day of codes or wrong tries is spent: a new code would not
// help, so the page says what will.
const EMAIL_INVITATION_SPENT = "This invitation has had too many codes or wrong tries today. Verify with Google, or ask whoever invited you for a new invitation."
// The address's codes across every invitation to it, whoever sent them.
const EMAIL_ADDRESS_LIMITED = "Too many codes have been sent to the invited address. Verify with Google, or try again later."

// The invitation's wrong tries over the last day, across all its codes; binds
// the invitation's code hash and the start of the day.
const WRONG_TRIES_TODAY = "(SELECT COALESCE(SUM(attempts),0) FROM email_proofs WHERE invite_hash=? AND created_at>?)"
async function wrongTriesToday(env: Env,codeHash: string,now: number): Promise<number> {
  return (await env.DB.prepare(`SELECT ${WRONG_TRIES_TODAY} AS tries`).bind(codeHash,now-DAY_MS).first<{ tries: number }>())?.tries ?? 0
}
// What the invitation, and its address across all invitations, have spent of
// what a new send needs, with its binds.
type SendBudget = { sent_hour: number; sent_day: number; wrong_day: number; address_hour: number; address_day: number }
const SEND_BUDGET = `SELECT (SELECT COUNT(*) FROM email_proofs WHERE invite_hash=? AND created_at>?) AS sent_hour,(SELECT COUNT(*) FROM email_proofs WHERE invite_hash=? AND created_at>?) AS sent_day,${WRONG_TRIES_TODAY} AS wrong_day,(SELECT COUNT(*) FROM email_proofs WHERE email=? AND created_at>?) AS address_hour,(SELECT COUNT(*) FROM email_proofs WHERE email=? AND created_at>?) AS address_day`
function sendBudgetBinds(codeHash: string,email: string,now: number): unknown[] { return [codeHash,now-HOUR_MS,codeHash,now-DAY_MS,codeHash,now-DAY_MS,email,now-HOUR_MS,email,now-DAY_MS] }
// Seconds until the oldest send in the window leaves it.
async function sendsFreeIn(env: Env,key: "invite_hash" | "email",value: string,windowMs: number,now: number): Promise<number> {
  const oldest = await env.DB.prepare(`SELECT MIN(created_at) AS at FROM email_proofs WHERE ${key}=? AND created_at>?`).bind(value,now-windowMs).first<{ at: number | null }>()
  return Math.max(1,Math.ceil(((oldest?.at ?? now)+windowMs-now)/1000))
}

// Ten minutes for the code, then ten for the proof it becomes.
export function emailCookie(token: string): string { return `${EMAIL_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1200` }
export function emailCookieToken(request: Request): string { const token = readCookie(request,EMAIL_COOKIE); if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw emailProofRefusal(); return token }

// Six digits, uniform: 4,294,000,000 is the largest multiple of a million
// below 2^32, so rejecting draws at or above it leaves no bias.
export function emailCode(): string {
  let draw: number
  do { draw = crypto.getRandomValues(new Uint32Array(1))[0] as number } while (draw >= 4_294_000_000)
  return String(draw % 1_000_000).padStart(6,"0")
}

async function emailCodeKey(env: Env,version: number): Promise<CryptoKey> {
  const root = parseRootKeys(env.ROOT_KEYS).versions.get(version)
  if (!root) throw new Error(`root key version ${version} is not configured`)
  return crypto.subtle.deriveKey({ name: "HKDF",hash: "SHA-256",salt: utf8(`mehen/root/v${version}`),info: utf8("mehen/email-code/v1") },(await root).key,{ name: "HMAC",hash: "SHA-256",length: 256 },false,["sign"])
}
export async function emailCodeHash(env: Env,version: number,id: string,code: string): Promise<string> {
  return base64UrlEncode(await crypto.subtle.sign("HMAC",await emailCodeKey(env,version),utf8(`${id}\n${code}`)))
}

// Whether the workspace's identity rule covers the invited role: then only
// Google's hosted-domain claim can satisfy it, and no code is offered.
export async function inviteNeedsGoogle(env: Env,codeHash: string): Promise<boolean> {
  const context = await inviteIdentityContext(env,codeHash)
  return context.identityRule?.roles.includes(context.role) === true
}

// "Mehen <no-reply@mehen.dev>" or a bare address.
export function emailSender(value: string): string | EmailAddress {
  const named = /^\s*([^<>]*?)\s*<([^<>\s]+@[^<>\s]+)>\s*$/.exec(value)
  return named ? { name: named[1]!,email: named[2]! } : value.trim()
}

// The inviter chooses both names, and the mail goes out as mehen.dev; one
// that a mail client might turn into a link is left out of it.
export function looksLikeLink(name: string): boolean { return /:\/\/|www\.|@|\w\.\p{L}{2,}/iu.test(name) }

// The email: the code, how long it lasts, who invited them to which
// workspace, and what to do if it was not expected. No link: a code to type.
export function inviteCodeEmail(input: { from: string; to: string; code: string; workspace: string; inviter: string }): EmailMessageBuilder {
  const inviter = input.inviter.trim() === "" || looksLikeLink(input.inviter) ? "Someone" : input.inviter
  const workspace = looksLikeLink(input.workspace) ? "a workspace" : `the ${input.workspace} workspace`
  const invited = `${inviter} invited you to ${workspace} on Mehen.`
  const text = [`Your Mehen code is ${input.code}.`,"",`Type it on the sign-up page to prove this email address is yours. It expires in 10 minutes.`,"",invited,"","If you did not ask for this, ignore this email."].join("\n")
  const body = html`<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1a1a1a;line-height:1.5">
<p>Your Mehen code is</p>
<p style="font-size:28px;font-weight:600;letter-spacing:4px;font-family:ui-monospace,Menlo,monospace">${input.code}</p>
<p>Type it on the sign-up page to prove this email address is yours. It expires in 10 minutes.</p>
<p>${invited}</p>
<p style="color:#666">If you did not ask for this, ignore this email.</p>
</body></html>`
  return { from: emailSender(input.from),to: input.to,subject: `Your Mehen code: ${input.code}`,text,html: body.value }
}

// A send failure's code (E_SENDER_NOT_VERIFIED and the like), never its
// message, which may name the address.
export function sendErrorCode(error: unknown): string {
  const code = typeof error === "object" && error !== null && "code" in error ? (error as { code: unknown }).code : null
  return typeof code === "string" && /^E_[A-Z_]{1,64}$/.test(code) ? code : "unknown"
}

// POST /api/auth/email/start. Answers when the code expires and the cookie
// that binds it to this browser; nothing about the address.
export async function startEmailProof(env: Env,code: string,account: AccountWebSession | null,now = Date.now()): Promise<{ cookie: string; expiresAt: string }> {
  const codeHash = await sha256Text(code)
  const route = await env.DB.prepare("SELECT i.workspace,i.email,i.used_by_account FROM invite_codes i JOIN workspaces w ON w.id=i.workspace WHERE i.code_hash=? AND i.kind='join' AND i.state='active' AND i.expires_at>? AND w.status='active'").bind(codeHash,now).first<{ workspace: string; email: string | null; used_by_account: string | null }>()
  if (!route || route.used_by_account !== null && route.used_by_account !== account?.account) throw new VaultError("not_found","No such invite.")
  if (route.email === null) throw new VaultError("bad_request","This invitation is not for one email address, so it needs no code.")
  if (await inviteNeedsGoogle(env,codeHash)) throw emailIdentityRuleRefusal()
  if (!env.EMAIL || !env.EMAIL_FROM) {
    console.error(JSON.stringify({ at: "email.code.send",error: "unconfigured" }))
    throw emailSendFailed()
  }
  const terms = await directoryWorkspaceClient(env).lookupInvite(route.workspace,codeHash)
  const id = randomId("eml"),token = randomToken(),secret = emailCode(),version = parseRootKeys(env.ROOT_KEYS).current
  const inserted = await env.DB.prepare(`INSERT INTO email_proofs(id,invite_hash,email,code_hash,key_version,cookie_hash,account,session,security_epoch,created_at,expires_at,sends_window)
    SELECT ?,?,?,?,?,?,?,?,?,?,?,sent_hour+1 FROM (${SEND_BUDGET}) WHERE sent_hour<? AND sent_day<? AND wrong_day<? AND address_hour<? AND address_day<?`)
    .bind(id,codeHash,route.email,await emailCodeHash(env,version,id,secret),version,await sha256Text(token),account?.account ?? null,account?.session ?? null,account?.securityEpoch ?? null,now,now+EMAIL_CODE_TTL_MS,...sendBudgetBinds(codeHash,route.email,now),EMAIL_CODE_SENDS_PER_HOUR,EMAIL_CODE_SENDS_PER_DAY,EMAIL_CODE_WRONG_TRIES_PER_DAY,EMAIL_ADDRESS_SENDS_PER_HOUR,EMAIL_ADDRESS_SENDS_PER_DAY).run()
  if (inserted.meta.changes !== 1) {
    const spent = await env.DB.prepare(SEND_BUDGET).bind(...sendBudgetBinds(codeHash,route.email,now)).first<SendBudget>()
    if (spent && (spent.sent_day >= EMAIL_CODE_SENDS_PER_DAY || spent.wrong_day >= EMAIL_CODE_WRONG_TRIES_PER_DAY)) throw new VaultError("rate_limited",EMAIL_INVITATION_SPENT)
    if (spent && spent.address_day >= EMAIL_ADDRESS_SENDS_PER_DAY) throw new VaultError("rate_limited",EMAIL_ADDRESS_LIMITED,{ retryAfter: await sendsFreeIn(env,"email",route.email,DAY_MS,now) })
    if (spent && spent.address_hour >= EMAIL_ADDRESS_SENDS_PER_HOUR) throw new VaultError("rate_limited",EMAIL_ADDRESS_LIMITED,{ retryAfter: await sendsFreeIn(env,"email",route.email,HOUR_MS,now) })
    throw new VaultError("rate_limited","This invitation has been sent three codes in the last hour. Verify with Google, or try again later.",{ retryAfter: await sendsFreeIn(env,"invite_hash",codeHash,HOUR_MS,now) })
  }
  try {
    await env.EMAIL.send(inviteCodeEmail({ from: env.EMAIL_FROM,to: route.email,code: secret,workspace: terms.workspace.name,inviter: terms.inviter.name }))
  } catch (error) {
    // No code went out, so none is kept and the send is not counted.
    await env.DB.prepare("DELETE FROM email_proofs WHERE id=?").bind(id).run()
    console.error(JSON.stringify({ at: "email.code.send",error: sendErrorCode(error) }))
    throw emailSendFailed()
  }
  await env.DB.prepare("UPDATE email_proofs SET state='consumed',consumed_at=? WHERE invite_hash=? AND state='sent' AND id!=?").bind(now,codeHash,id).run()
  return { cookie: emailCookie(token),expiresAt: new Date(now+EMAIL_CODE_TTL_MS).toISOString() }
}

// POST /api/auth/email/verify. The latest live code this browser was sent
// for the invitation, compared in constant time; a wrong one is counted.
export async function verifyEmailProof(env: Env,request: Request,code: string,typed: string,now = Date.now()): Promise<{ emailProof: string; email: string; expiresAt: string }> {
  const codeHash = await sha256Text(code),cookieHash = await sha256Text(emailCookieToken(request))
  const row = await env.DB.prepare("SELECT id,code_hash,key_version FROM email_proofs WHERE invite_hash=? AND cookie_hash=? AND state='sent' AND expires_at>? AND attempts<? ORDER BY created_at DESC LIMIT 1").bind(codeHash,cookieHash,now,EMAIL_CODE_TRIES).first<{ id: string; code_hash: string; key_version: number }>()
  if (!row) throw emailCodeDead()
  const digits = typed.replace(/\s+/g,""),hash = /^\d{6}$/.test(digits) ? await emailCodeHash(env,row.key_version,row.id,digits) : ""
  if (!timingSafeEqualText(hash,row.code_hash)) {
    const counted = await env.DB.prepare(`UPDATE email_proofs SET attempts=attempts+1 WHERE id=? AND state='sent' AND attempts<? AND ${WRONG_TRIES_TODAY}<? RETURNING attempts`).bind(row.id,EMAIL_CODE_TRIES,codeHash,now-DAY_MS,EMAIL_CODE_WRONG_TRIES_PER_DAY).first<{ attempts: number }>()
    if (await wrongTriesToday(env,codeHash,now) >= EMAIL_CODE_WRONG_TRIES_PER_DAY) throw new VaultError("bad_request",EMAIL_INVITATION_SPENT)
    if (!counted || counted.attempts >= EMAIL_CODE_TRIES) throw new VaultError("bad_request","That code is not right, and after five tries it no longer works. Send a new code.")
    throw new VaultError("bad_request","That code is not right. Check the email and try again.")
  }
  const proof = await env.DB.prepare(`UPDATE email_proofs SET state='verified',verified_at=?,expires_at=? WHERE id=? AND state='sent' AND attempts<? AND expires_at>? AND ${WRONG_TRIES_TODAY}<? RETURNING id,email,expires_at`).bind(now,now+EMAIL_PROOF_TTL_MS,row.id,EMAIL_CODE_TRIES,now,codeHash,now-DAY_MS,EMAIL_CODE_WRONG_TRIES_PER_DAY).first<{ id: string; email: string; expires_at: number }>()
  if (!proof) throw (await wrongTriesToday(env,codeHash,now)) >= EMAIL_CODE_WRONG_TRIES_PER_DAY ? new VaultError("bad_request",EMAIL_INVITATION_SPENT) : emailCodeDead()
  return { emailProof: proof.id,email: proof.email,expiresAt: new Date(proof.expires_at).toISOString() }
}

// A verified proof as the signup and the join read it: this browser's, live,
// not spent. `joining` once an account holds it, as a Google result is.
export async function readEmailProof(env: Env,id: string,cookie: string,now = Date.now()): Promise<EmailProof> {
  if (id.length > 128) throw emailProofRefusal()
  const row = await env.DB.prepare(`SELECT ${EMAIL_PROOF_COLUMNS} FROM email_proofs WHERE id=? AND cookie_hash=? AND expires_at>? AND consumed_at IS NULL AND state IN ('verified','joining')`).bind(id,await sha256Text(cookie),now).first<EmailProof>()
  if (!row) throw emailProofRefusal()
  return row
}
export function emailProofGuard(env: Env,proof: EmailProof,now: number): D1PreparedStatement { return accountGuard(env,"EXISTS (SELECT 1 FROM email_proofs WHERE id=? AND cookie_hash=? AND expires_at>? AND consumed_at IS NULL AND state=? AND account IS ? AND joining_membership IS ?)",[proof.id,proof.cookie_hash,now,proof.state,proof.account,proof.joining_membership]) }
export function holdEmailProof(env: Env,proof: EmailProof,account: { account: string; session: string; securityEpoch: number },membership: string | null): D1PreparedStatement { return env.DB.prepare("UPDATE email_proofs SET state='joining',account=?,session=?,security_epoch=?,joining_membership=? WHERE id=?").bind(account.account,account.session,account.securityEpoch,membership,proof.id) }
export function consumeEmailProof(env: Env,proof: EmailProof,now: number): D1PreparedStatement { return env.DB.prepare("UPDATE email_proofs SET state='consumed',consumed_at=? WHERE id=?").bind(now,proof.id) }
// Rows past their day of the send and wrong-try counts, unless an account is
// mid-join on one.
export function emailProofSweep(env: Env,now: number): D1PreparedStatement { return env.DB.prepare("DELETE FROM email_proofs WHERE expires_at<=? AND created_at<=? AND NOT (state='joining' AND joining_membership IS NOT NULL)").bind(now,now-DAY_MS) }
