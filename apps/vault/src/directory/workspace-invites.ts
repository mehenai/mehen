import { canonicalJson, type NextStep, type WorkspaceRole } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { randomId } from "../vault/core.ts"
import type { AccountWebSession } from "./account-session.ts"
import { accountBatch, accountGuard } from "./account-store.ts"
import { directoryWorkspaceClient, type InviteRedeemResult, type WorkspaceJoinClient } from "./workspace-client.ts"
import { accountRecoveryReadySql } from "./account-recovery-setup.ts"
import { accountRecoverySetupRequired } from "./workspace-recovery.ts"
import { invokeVault } from "../vault/client.ts"
import { assertInviteResultCurrent, assertOidcSession, oidcIdentityContext } from "./oidc-flow.ts"
import { consumeOidcResult, identityForResult, linkIdentityStatements, oidcResultGuard, readOidcResult, type OidcResult } from "./oidc-flow.ts"
import { oidcRefusal } from "./oidc.ts"
import { EMAIL_PROOF_COLUMNS, consumeEmailProof, emailIdentityRuleRefusal, emailProofGuard, emailProofRefusal, holdEmailProof, inviteNeedsGoogle, readEmailProof, type EmailProof } from "./email-proof.ts"
import { sha256Text } from "./session.ts"
export type JoinReservation = { codeHash: string; workspace: string; member: string; account: string }

// Where an invitee goes when an invitation needs a proof of its email it does
// not have, or whose proof has lapsed: /signup runs Google's step or the
// emailed code, and comes back.
export const INVITE_PROOF_NEXT: NextStep = { url: "/signup", say: "Verify the invited email with Google, then continue." }
export function inviteProofRequired(): VaultError { return new VaultError("identity_required","Prove the invited email before joining.",{ next: INVITE_PROOF_NEXT }) }

// What /signup shows before anything is created: the workspace, the role and
// whether the invitation is bound to one email. Never the email itself. An
// unknown, expired, revoked or another account's used code answers as join
// does. `account`: the signed-in account, which may read its own used code.
// `emailCode`: whether the page offers the emailed code beside Google
// (offered), only Google because the role falls under the workspace's
// identity rule (identity_rule), or no code at all (off: an open link, or no
// Email Sending binding).
export type InvitePeek = { workspace: { name: string; slug: string }; role: WorkspaceRole; bound: boolean; emailCode: "offered" | "identity_rule" | "off"; expiresAt: string }
export async function peekWorkspaceInvite(env: Env,code: string,account: AccountWebSession | null,client: WorkspaceJoinClient = directoryWorkspaceClient(env),now = Date.now()): Promise<InvitePeek> {
  const codeHash = await sha256Text(code)
  const route = await env.DB.prepare("SELECT i.workspace,i.email,i.used_by_account FROM invite_codes i JOIN workspaces w ON w.id=i.workspace WHERE i.code_hash=? AND i.kind='join' AND i.state='active' AND i.expires_at>? AND w.status='active'").bind(codeHash,now).first<{ workspace: string; email: string | null; used_by_account: string | null }>()
  if (!route || route.used_by_account !== null && route.used_by_account !== account?.account) throw new VaultError("not_found","No such invite.")
  const terms = await client.lookupInvite(route.workspace,codeHash)
  if (terms.workspace.id !== route.workspace) throw new VaultError("not_found","No such invite.")
  const emailCode = route.email === null || !env.EMAIL || !env.EMAIL_FROM ? "off" : await inviteNeedsGoogle(env,codeHash) ? "identity_rule" : "offered"
  return { workspace: { name: terms.workspace.name,slug: terms.workspace.slug },role: terms.role,bound: route.email !== null,emailCode,expiresAt: terms.expiresAt }
}
export async function reserveWorkspaceJoin(env: Env,account: AccountWebSession,code: string,client: WorkspaceJoinClient = directoryWorkspaceClient(env),now = Date.now(),identityProof?: { result: string; cookie: string },emailIdentityProof?: { proof: string; cookie: string }): Promise<JoinReservation> {
  const codeHash = await sha256Text(code)
  const route = await env.DB.prepare("SELECT workspace,email,used_at,used_by_account FROM invite_codes WHERE code_hash=? AND kind='join' AND state='active' AND expires_at>?").bind(codeHash,now).first<{ workspace: string; email: string | null; used_at: number | null; used_by_account: string | null }>()
  if (!route || route.used_by_account !== null && route.used_by_account !== account.account) throw new VaultError("not_found","No such invite.")
  let proof: OidcResult | undefined
  if (identityProof) {
    proof = await readOidcResult(env,identityProof.result,identityProof.cookie,"invite",now)
    if (proof.invite_hash !== codeHash) throw oidcRefusal("result_unavailable","invite")
    if (proof.account !== null && proof.account !== account.account || proof.session !== null && proof.session !== account.session || proof.security_epoch !== null && proof.security_epoch !== account.securityEpoch || proof.state === "joining" && proof.account !== account.account) throw oidcRefusal("account_mismatch","invite")
    await assertInviteResultCurrent(env,proof)
    const identity = await identityForResult(env,proof)
    if (identity && identity.account !== account.account) throw oidcRefusal("already_linked_elsewhere","invite")
  }
  // The emailed code proves the inbox and nothing else: never a workspace identity rule.
  let emailProof: EmailProof | undefined
  if (emailIdentityProof) {
    if (proof) throw new VaultError("bad_request","Prove the invited email once, with Google or with the emailed code.")
    emailProof = await readEmailProof(env,emailIdentityProof.proof,emailIdentityProof.cookie,now)
    if (emailProof.invite_hash !== codeHash || emailProof.account !== null && emailProof.account !== account.account || emailProof.session !== null && emailProof.session !== account.session || emailProof.security_epoch !== null && emailProof.security_epoch !== account.securityEpoch) throw emailProofRefusal()
    if (await inviteNeedsGoogle(env,codeHash)) throw emailIdentityRuleRefusal()
  }
  const provedEmail = proof?.email ?? emailProof?.email ?? null
  if (route.email !== null && provedEmail !== route.email) throw inviteProofRequired()
  const terms = await client.lookupInvite(route.workspace,codeHash)
  if (terms.workspace.id !== route.workspace) throw new VaultError("not_found","No such invite.")
  if ((terms.role !== "guest" || terms.boundEmail !== null) && !proof && !emailProof) throw inviteProofRequired()
  if (!(await env.DB.prepare(`SELECT id FROM accounts WHERE id=? AND ${accountRecoveryReadySql("accounts.id")}`).bind(account.account).first())) throw accountRecoverySetupRequired(env)
  if (route.used_at !== null) {
    const old = await env.DB.prepare("SELECT id FROM memberships WHERE account=? AND workspace=? AND state!='left'").bind(account.account,route.workspace).first<{ id: string }>()
    if (!old) throw new VaultError("not_found","No such invite.")
    if (proof && proof.joining_membership === null) {
      const existingIdentity = await identityForResult(env,proof),newIdentity = existingIdentity ? null : randomId("oid")
      const prior = await env.DB.prepare("SELECT joining_identity FROM oidc_results WHERE joining_membership=? AND account=? AND state='joining' AND joining_identity IS NOT NULL").bind(old.id,account.account).first<{ joining_identity: string }>()
      const reservedIdentity = newIdentity ?? (prior?.joining_identity === existingIdentity?.id ? existingIdentity!.id : null)
      await accountBatch(env,[oidcResultGuard(env,proof,now),
        accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND s.id=? AND s.kind='web' AND a.security_epoch=? AND a.security_transition IS NULL AND (a.restricted_until IS NULL OR a.restricted_until<=?) AND s.expires_at>? AND s.last_seen_at>?)",[account.account,account.session,account.securityEpoch,now,now,now-7*86400000]),
        ...linkIdentityStatements(env,proof,account.account,now,newIdentity ?? undefined),
        env.DB.prepare("DELETE FROM oidc_identities WHERE id IN (SELECT joining_identity FROM oidc_results WHERE joining_membership=? AND account=? AND state='joining' AND id!=?) AND id!=? AND NOT EXISTS (SELECT 1 FROM session_identity_checks WHERE identity=oidc_identities.id) AND NOT EXISTS (SELECT 1 FROM operation_identity_checks WHERE identity=oidc_identities.id)").bind(old.id,account.account,proof.id,existingIdentity?.id ?? newIdentity),
        env.DB.prepare("UPDATE oidc_results SET state='consumed',consumed_at=? WHERE joining_membership=? AND account=? AND state='joining' AND id!=?").bind(now,old.id,account.account,proof.id),
        env.DB.prepare("UPDATE oidc_results SET state='joining',account=?,session=?,security_epoch=?,joining_membership=?,joining_identity=? WHERE id=?").bind(account.account,account.session,account.securityEpoch,old.id,reservedIdentity,proof.id),
        env.DB.prepare("UPDATE memberships SET state='joining',updated_at=? WHERE id=? AND account=? AND workspace=? AND state IN ('joining','member')").bind(now,old.id,account.account,route.workspace),
      ])
    }
    if (emailProof && emailProof.joining_membership === null) {
      await accountBatch(env,[emailProofGuard(env,emailProof,now),
        accountGuard(env,"EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND s.id=? AND s.kind='web' AND a.security_epoch=? AND a.security_transition IS NULL AND (a.restricted_until IS NULL OR a.restricted_until<=?) AND s.expires_at>? AND s.last_seen_at>?)",[account.account,account.session,account.securityEpoch,now,now,now-7*86400000]),
        env.DB.prepare("UPDATE email_proofs SET state='consumed',consumed_at=? WHERE joining_membership=? AND account=? AND state='joining' AND id!=?").bind(now,old.id,account.account,emailProof.id),
        holdEmailProof(env,emailProof,account,old.id),
        env.DB.prepare("UPDATE memberships SET state='joining',updated_at=? WHERE id=? AND account=? AND workspace=? AND state IN ('joining','member')").bind(now,old.id,account.account,route.workspace),
      ])
    }
    return { codeHash,workspace: route.workspace,member: old.id,account: account.account }
  }
  const member = randomId("mem"),newIdentity = proof && !await identityForResult(env,proof) ? randomId("oid") : null
  await accountBatch(env,[
    accountGuard(env,`EXISTS (SELECT 1 FROM accounts a JOIN web_sessions s ON s.account=a.id WHERE a.id=? AND a.status='active' AND a.security_epoch=? AND a.security_transition IS NULL AND ${accountRecoveryReadySql("a.id")}
      AND (a.restricted_until IS NULL OR a.restricted_until<=?) AND s.id=? AND s.kind='web' AND s.expires_at>? AND s.last_seen_at>?)`,[account.account,account.securityEpoch,now,account.session,now,now-7*86400000]),
    accountGuard(env,"EXISTS (SELECT 1 FROM invite_codes i JOIN workspaces w ON w.id=i.workspace WHERE i.code_hash=? AND i.kind='join' AND i.state='active' AND (i.email IS NULL OR i.email=?) AND i.expires_at>? AND i.used_at IS NULL AND (i.used_by_account IS NULL OR i.used_by_account=?) AND w.status='active')",[codeHash,provedEmail,now,account.account]),
    accountGuard(env,"NOT EXISTS (SELECT 1 FROM memberships WHERE account=? AND workspace=? AND state!='left')",[account.account,route.workspace]),
    env.DB.prepare("INSERT INTO memberships(id,account,workspace,state,role_hint,updated_at) VALUES (?,?,?,'joining',?,?)").bind(member,account.account,route.workspace,terms.role,now),
    env.DB.prepare("UPDATE invite_codes SET used_at=?,used_by_account=? WHERE code_hash=?").bind(now,account.account,codeHash),
    ...(proof ? [oidcResultGuard(env,proof,now),...linkIdentityStatements(env,proof,account.account,now,newIdentity ?? undefined),env.DB.prepare("UPDATE oidc_results SET state='joining',account=?,session=?,security_epoch=?,joining_membership=?,joining_identity=? WHERE id=?").bind(account.account,account.session,account.securityEpoch,member,newIdentity,proof.id)] : []),
    ...(emailProof ? [emailProofGuard(env,emailProof,now),holdEmailProof(env,emailProof,account,member)] : []),
  ])
  return { codeHash,workspace: route.workspace,member,account: account.account }
}
export async function completeWorkspaceJoin(env: Env,reservation: JoinReservation,client: WorkspaceJoinClient = directoryWorkspaceClient(env),now = Date.now()): Promise<InviteRedeemResult> {
  const row = await env.DB.prepare(`SELECT a.name,a.security_epoch,a.security_transition,${accountRecoveryReadySql("a.id")} AS recovery_ready FROM accounts a JOIN memberships m ON m.account=a.id WHERE a.id=? AND a.status='active' AND m.id=? AND m.workspace=? AND m.state IN ('joining','member')`).bind(reservation.account,reservation.member,reservation.workspace).first<{ name: string; security_epoch: number; security_transition: string | null; recovery_ready: number }>()
  if (!row || row.recovery_ready !== 1) throw accountRecoverySetupRequired(env)
  if (row.security_transition) throw new VaultError("account_pending","Account security changes are still pending.")
  await client.install(reservation.workspace,{ account: reservation.account,committedEpoch: row.security_epoch,pending: null })
  const proof = await env.DB.prepare("SELECT * FROM oidc_results WHERE joining_membership=? AND account=? AND invite_hash=? AND state='joining' AND consumed_at IS NULL AND expires_at>?").bind(reservation.member,reservation.account,reservation.codeHash,now).first<OidcResult>()
  const emailProof = proof ? null : await env.DB.prepare(`SELECT ${EMAIL_PROOF_COLUMNS} FROM email_proofs WHERE joining_membership=? AND account=? AND invite_hash=? AND state='joining' AND consumed_at IS NULL AND expires_at>?`).bind(reservation.member,reservation.account,reservation.codeHash,now).first<EmailProof>()
  const bound = await env.DB.prepare("SELECT email FROM invite_codes WHERE code_hash=?").bind(reservation.codeHash).first<{ email: string | null }>()
  if (bound?.email !== null && !proof && !emailProof) throw new VaultError("identity_required","Prove the invited email before joining.")
  // Either proof names the proved address in identity.email.
  const identity = proof ? { provider: "google" as const,subject: proof.subject,email: proof.email,hd: proof.domain } : emailProof ? { provider: "email" as const,email: emailProof.email } : null
  let result: InviteRedeemResult
  try { result = await client.redeemInvite(reservation.workspace,{ member: reservation.member,codeHash: reservation.codeHash,account: reservation.account,name: row.name,evidence: { recoverySetup: true,identity } }) } catch (error) {
    if (error instanceof VaultError && ["not_found","forbidden","conflict","identity_required"].includes(error.code)) {
      if (proof) await abortOidcJoin(env,proof,reservation,now)
      else if (emailProof) await abortEmailJoin(env,emailProof,reservation,now)
    }
    throw error
  }
  if (result.member !== reservation.member) throw new Error("Join changed the reserved member")
  const identityCheck = proof ? await installInviteIdentity(env,proof,reservation,row.security_epoch,result.state) : null
  await accountBatch(env,[
    accountGuard(env,`EXISTS (SELECT 1 FROM accounts WHERE id=? AND status='active' AND security_transition IS NULL AND ${accountRecoveryReadySql("accounts.id")})`,[reservation.account]),
    env.DB.prepare("UPDATE memberships SET state='member',updated_at=? WHERE id=? AND account=? AND state='joining'").bind(now,reservation.member,reservation.account),
    ...(proof ? [oidcResultGuard(env,proof,now),consumeOidcResult(env,proof,now),...(identityCheck ? [identityCheck] : [])] : []),
    ...(emailProof ? [emailProofGuard(env,emailProof,now),consumeEmailProof(env,emailProof,now)] : []),
  ])
  return result
}
export async function reconcileWorkspaceJoins(env: Env,client: WorkspaceJoinClient = directoryWorkspaceClient(env)): Promise<void> {
  const rows = await env.DB.prepare("SELECT i.code_hash,m.workspace,m.id,m.account FROM memberships m JOIN invite_codes i ON i.workspace=m.workspace AND i.used_by_account=m.account WHERE m.state='joining' AND i.kind='join' AND i.state='active' AND i.used_at IS NOT NULL ORDER BY m.updated_at LIMIT 100").all<{ code_hash: string; workspace: string; id: string; account: string }>()
  for (const row of rows.results) { try { await completeWorkspaceJoin(env,{ codeHash: row.code_hash,workspace: row.workspace,member: row.id,account: row.account },client) } catch { console.error(JSON.stringify({ at: "workspace.join.pending",workspace: row.workspace,member: row.id })) } }
}

async function cleanupOidcJoin(env: Env,proof: OidcResult,reservation: JoinReservation,now: number): Promise<void> {
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM oidc_results r JOIN memberships m ON m.id=r.joining_membership WHERE r.id=? AND r.state='joining' AND r.account=? AND r.invite_hash=? AND r.joining_membership=? AND m.state='joining' AND m.workspace=?)",[proof.id,reservation.account,reservation.codeHash,reservation.member,reservation.workspace]),
    env.DB.prepare("DELETE FROM memberships WHERE id=? AND account=? AND workspace=? AND state='joining'").bind(reservation.member,reservation.account,reservation.workspace),
    env.DB.prepare("UPDATE invite_codes SET used_at=NULL,used_by_account=NULL WHERE code_hash=? AND used_by_account=?").bind(reservation.codeHash,reservation.account),
    env.DB.prepare("UPDATE oidc_results SET state='consumed',consumed_at=? WHERE id=?").bind(now,proof.id),
    env.DB.prepare("DELETE FROM oidc_identities WHERE id=? AND account=? AND NOT EXISTS (SELECT 1 FROM session_identity_checks WHERE identity=oidc_identities.id) AND NOT EXISTS (SELECT 1 FROM operation_identity_checks WHERE identity=oidc_identities.id)").bind(proof.joining_identity,reservation.account),
  ])
}
async function abortOidcJoin(env: Env,proof: OidcResult,reservation: JoinReservation,now: number): Promise<void> {
  await abortJoin(env,reservation,now,"expired or refused OIDC join",consumeOidcResult(env,proof,now),() => cleanupOidcJoin(env,proof,reservation,now))
}
async function cleanupEmailJoin(env: Env,proof: EmailProof,reservation: JoinReservation,now: number): Promise<void> {
  await accountBatch(env,[
    accountGuard(env,"EXISTS (SELECT 1 FROM email_proofs r JOIN memberships m ON m.id=r.joining_membership WHERE r.id=? AND r.state='joining' AND r.account=? AND r.invite_hash=? AND r.joining_membership=? AND m.state='joining' AND m.workspace=?)",[proof.id,reservation.account,reservation.codeHash,reservation.member,reservation.workspace]),
    env.DB.prepare("DELETE FROM memberships WHERE id=? AND account=? AND workspace=? AND state='joining'").bind(reservation.member,reservation.account,reservation.workspace),
    env.DB.prepare("UPDATE invite_codes SET used_at=NULL,used_by_account=NULL WHERE code_hash=? AND used_by_account=?").bind(reservation.codeHash,reservation.account),
    consumeEmailProof(env,proof,now),
  ])
}
async function abortEmailJoin(env: Env,proof: EmailProof,reservation: JoinReservation,now: number): Promise<void> {
  await abortJoin(env,reservation,now,"expired or refused emailed-code join",consumeEmailProof(env,proof,now),() => cleanupEmailJoin(env,proof,reservation,now))
}
// A join whose proof lapsed or whose workspace refused it: undone in the
// workspace and here, unless the workspace already redeemed it, when the
// membership stands and the proof is spent.
async function abortJoin(env: Env,reservation: JoinReservation,now: number,reason: string,consumeProof: D1PreparedStatement,cleanup: () => Promise<void>): Promise<void> {
  try {
    const aborted = await invokeVault(env,reservation.workspace,{ op: "access.invites.abort",input: { codeHash: reservation.codeHash,member: reservation.member,account: reservation.account },auth: { kind: "system",reason } }) as { aborted: boolean }
    if (!aborted.aborted) {
      let source: Awaited<ReturnType<typeof oidcIdentityContext>> | null = null
      try { source = await oidcIdentityContext(env,reservation.workspace,reservation.account) } catch (error) { if (!(error instanceof VaultError) || error.code !== "not_found") throw error }
      if (source) throw new VaultError("conflict","The source join reservation is unresolved.")
    }
  }
  catch (error) {
    if (!(error instanceof VaultError) || error.code !== "conflict") throw error
    const member = await oidcIdentityContext(env,reservation.workspace,reservation.account)
    if (member.status !== "active" || member.member !== reservation.member) throw error
    await accountBatch(env,[env.DB.prepare("UPDATE memberships SET state='member',updated_at=? WHERE id=? AND account=? AND workspace=? AND state='joining'").bind(now,reservation.member,reservation.account,reservation.workspace),consumeProof])
    return
  }
  await cleanup()
}
export async function expireOidcJoins(env: Env,now = Date.now()): Promise<void> {
  const rows = await env.DB.prepare("SELECT * FROM oidc_results WHERE state='joining' AND joining_membership IS NOT NULL AND expires_at<=? ORDER BY expires_at LIMIT 100").bind(now).all<OidcResult>()
  for (const proof of rows.results) {
    try {
      const membership = await env.DB.prepare("SELECT workspace FROM memberships WHERE id=? AND account=? AND state='joining'").bind(proof.joining_membership,proof.account).first<{ workspace: string }>()
      if (membership) await abortOidcJoin(env,proof,{ codeHash: proof.invite_hash!,workspace: membership.workspace,member: proof.joining_membership!,account: proof.account! },now)
    } catch { console.error(JSON.stringify({ at: "oidc.join.expiry.pending",result: proof.id })) }
  }
}
export async function expireEmailJoins(env: Env,now = Date.now()): Promise<void> {
  const rows = await env.DB.prepare(`SELECT ${EMAIL_PROOF_COLUMNS} FROM email_proofs WHERE state='joining' AND joining_membership IS NOT NULL AND expires_at<=? ORDER BY expires_at LIMIT 100`).bind(now).all<EmailProof>()
  for (const proof of rows.results) {
    try {
      const membership = await env.DB.prepare("SELECT workspace FROM memberships WHERE id=? AND account=? AND state='joining'").bind(proof.joining_membership,proof.account).first<{ workspace: string }>()
      if (membership) await abortEmailJoin(env,proof,{ codeHash: proof.invite_hash,workspace: membership.workspace,member: proof.joining_membership!,account: proof.account! },now)
      else await consumeEmailProof(env,proof,now).run()
    } catch { console.error(JSON.stringify({ at: "email.join.expiry.pending",proof: proof.id })) }
  }
}

// The proof becomes the session's identity check: for a membership waiting
// on confirmation it is also the invite check the confirmation needs; a
// membership that joined straight away, or was confirmed before a retried
// join, is active, so it is installed as an ordinary session check.
async function installInviteIdentity(env: Env,proof: OidcResult,reservation: JoinReservation,epoch: number,state: InviteRedeemResult["state"]): Promise<D1PreparedStatement> {
  const saved = await assertInviteResultCurrent(env,proof),context = await oidcIdentityContext(env,reservation.workspace,reservation.account)
  if (!proof.session) throw oidcRefusal("session_ended","invite")
  if (proof.security_epoch !== epoch) throw oidcRefusal("epoch_changed","invite")
  if (saved.member !== null && saved.member !== reservation.member || saved.ruleRevision !== context.identityRuleRev || saved.gateGeneration !== context.gateGeneration) throw oidcRefusal("gate_changed","invite")
  await assertOidcSession(env,reservation.account,proof.session,epoch,"web","invite")
  const session = await env.DB.prepare("SELECT expires_at FROM web_sessions WHERE id=? AND account=? AND kind='web'").bind(proof.session,reservation.account).first<{ expires_at: number }>(),identity = await identityForResult(env,proof)
  if (!session) throw oidcRefusal("session_ended","invite")
  if (!identity || identity.account !== reservation.account) throw oidcRefusal("no_linked_identity","invite")
  const id = `chk_${proof.id}`,action = { type: "member.confirm",member: reservation.member,termsDigest: saved.inviteTermsDigest!,identityRuleRevision: saved.ruleRevision }
  const sessionCheck = { id,identityRuleRev: saved.ruleRevision,gateGeneration: saved.gateGeneration,checkSequence: saved.sequence,succeededAt: new Date(proof.created_at).toISOString(),expiresAt: new Date(session.expires_at).toISOString() }
  const install = state === "active" ? { purpose: "session" as const } : { purpose: "invite" as const,operationCheck: { id,subjectDigest: await sha256Text(canonicalJson(action)),identityRuleRev: saved.ruleRevision,gateGeneration: saved.gateGeneration,succeededAt: new Date(proof.created_at).toISOString(),expiresAt: new Date(proof.expires_at).toISOString() } }
  await invokeVault(env,reservation.workspace,{ op: "access.identity.install",input: { ...install,account: reservation.account,member: reservation.member,session: proof.session,securityEpoch: epoch,sessionCheck },auth: { kind: "system",reason: "verified exact invite identity" } })
  return env.DB.prepare(`INSERT INTO session_identity_checks(id,session,workspace,member,identity,account,session_kind,security_epoch,claims,rule_revision,gate_generation,sequence,started_at,succeeded_at,purpose,expires_at) VALUES (?,?,?,?,?,?,'web',?,?,?,?,?,?,?,'session',?) ON CONFLICT(session,workspace) DO UPDATE SET id=excluded.id,member=excluded.member,identity=excluded.identity,security_epoch=excluded.security_epoch,claims=excluded.claims,rule_revision=excluded.rule_revision,gate_generation=excluded.gate_generation,sequence=excluded.sequence,started_at=excluded.started_at,succeeded_at=excluded.succeeded_at,expires_at=excluded.expires_at WHERE excluded.member!=session_identity_checks.member OR excluded.sequence>session_identity_checks.sequence`).bind(id,proof.session,reservation.workspace,reservation.member,identity.id,reservation.account,epoch,JSON.stringify({ issuer: proof.issuer,subject: proof.subject,email: proof.email,domain: proof.domain,name: proof.name }),saved.ruleRevision,saved.gateGeneration,saved.sequence,saved.startedAt,proof.created_at,session.expires_at)
}
