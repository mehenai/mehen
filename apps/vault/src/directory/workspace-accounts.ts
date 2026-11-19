import { base64UrlDecode, fromUtf8, timingSafeEqualText, utf8 } from "@mehen/protocol"
import { z } from "zod"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { randomId } from "../vault/core.ts"
import { refreshAccountRecoverySetup } from "./account-recovery-setup.ts"
import { accountBatch, accountEvent, accountGuard, accountSessionStatements, findAccountPasskey, insertAccountPasskey } from "./account-store.ts"
import { refuseSuspendedAccount } from "./account-suspension.ts"
import { newSession, randomToken, sha256Text, type NewSession } from "./session.ts"
import { assertInviteResultCurrent, consumeOidcResult, identityForResult, oidcResultGuard, readOidcResult, type OidcResult } from "./oidc-flow.ts"
import { oidcRefusal } from "./oidc.ts"
import { emailIdentityRuleRefusal, emailProofGuard, emailProofRefusal, holdEmailProof, inviteNeedsGoogle, readEmailProof, type EmailProof } from "./email-proof.ts"
import { credentialId, passkeyCeremonies } from "./webauthn.ts"
import { inviteProofRequired } from "./workspace-invites.ts"
import { directoryWorkspaceClient } from "./workspace-client.ts"

export const AccountSignupOptions = z.strictObject({ invite: z.string().min(8).max(200),name: z.string().trim().min(1).max(64),oidcResult: z.string().max(128).optional(),emailProof: z.string().max(128).optional() })
export const AccountSignupVerify = AccountSignupOptions.extend({ response: z.record(z.string(),z.unknown()) })
export const AccountSigninVerify = z.strictObject({ flow: z.string().min(1).max(128),response: z.record(z.string(),z.unknown()) })
type Client = { client: string; place: string | null }
const DEFAULT_CLIENT: Client = { client: "A browser",place: null }
// What a signup with a code that is not a live invitation (or the bootstrap
// code) says to do: the same words whichever it was, so nothing is told apart.
export const SIGNUP_DEAD_INVITE_SAY = "This invitation has expired, been used or been revoked. Ask the person who invited you for a new link; if you already have an account, sign in instead."
// The invited email is proved by Google (oidcResult and its cookie) or by an
// emailed code (emailProof and its cookie), never both.
type SignupProofs = { resultId?: string; cookie?: string; emailProof?: string; emailCookie?: string }
async function signupInvite(env: Env,code: string,now: number,{ resultId,cookie,emailProof: emailProofId,emailCookie }: SignupProofs = {}): Promise<{ kind: "bootstrap" | "join"; hash: string; proof?: OidcResult; emailProof?: EmailProof }> {
  const hash = await sha256Text(code)
  if (typeof env.BOOTSTRAP_CODE === "string" && env.BOOTSTRAP_CODE.length >= 8 && timingSafeEqualText(code,env.BOOTSTRAP_CODE)) {
    if (await env.DB.prepare("SELECT id FROM accounts LIMIT 1").first()) throw new VaultError("conflict","This deployment already has an account. Ask for a workspace invite.")
    return { kind: "bootstrap",hash }
  }
  const dead = () => new VaultError("not_found","No such invite.",{ next: { say: SIGNUP_DEAD_INVITE_SAY } })
  const row = await env.DB.prepare("SELECT workspace,email FROM invite_codes WHERE code_hash=? AND kind='join' AND state='active' AND used_at IS NULL AND used_by_account IS NULL AND expires_at>?").bind(hash,now).first<{ workspace: string; email: string | null }>()
  if (!row) throw dead()
  let proof: OidcResult | undefined
  if (resultId && cookie) {
    proof = await readOidcResult(env,resultId,cookie,"invite",now)
    if (proof.invite_hash !== hash || proof.state !== "unused") throw oidcRefusal("result_unavailable","invite")
    if (proof.account !== null) throw oidcRefusal("account_mismatch","invite")
    if (row.email !== null && proof.email !== row.email) throw oidcRefusal("invite_email_mismatch","invite")
    await assertInviteResultCurrent(env,proof)
    if (await identityForResult(env,proof)) throw oidcRefusal("already_linked_elsewhere","invite")
  }
  let emailProof: EmailProof | undefined
  if (emailProofId) {
    if (proof) throw new VaultError("bad_request","Prove the invited email once, with Google or with the emailed code.")
    if (!emailCookie) throw emailProofRefusal()
    emailProof = await readEmailProof(env,emailProofId,emailCookie,now)
    if (emailProof.invite_hash !== hash || emailProof.account !== null || emailProof.state !== "verified" || emailProof.email !== row.email) throw emailProofRefusal()
    if (await inviteNeedsGoogle(env,hash)) throw emailIdentityRuleRefusal()
  }
  if (row.email !== null && !proof && !emailProof) throw inviteProofRequired()
  // A proof above has asked the workspace; without one, the routing row alone
  // outlives a revocation (its inviter's removal) or an inviter who may no
  // longer invite, so the workspace is asked here, as join does.
  if (!proof && !emailProof) {
    const terms = await directoryWorkspaceClient(env).lookupInvite(row.workspace,hash).catch((error: unknown) => { throw error instanceof VaultError && error.code === "not_found" ? dead() : error })
    if (terms.workspace.id !== row.workspace) throw dead()
  }
  return { kind: "join",hash,...(proof ? { proof } : {}),...(emailProof ? { emailProof } : {}) }
}
// The deployment's first account may create workspaces: the operator's
// bootstrap code stands for the operator's grant. Only inside the guarded
// bootstrap batch (no account exists yet), and with the operator event and
// account notice the allow-list trigger writes on UPDATE, since an INSERT
// does not fire it. Invited accounts are never granted here.
export const BOOTSTRAP_OPERATOR = "operator:bootstrap"
function bootstrapAccountStatements(env: Env,account: string,name: string,now: number): D1PreparedStatement[] {
  return [
    env.DB.prepare("INSERT INTO accounts(id,name,created_at,can_create_workspaces,can_create_workspaces_by,can_create_workspaces_op) VALUES (?,?,?,1,?,?)").bind(account,name,now,BOOTSTRAP_OPERATOR,crypto.randomUUID()),
    accountEvent(env,account,"operator.allow_workspaces",{ by: BOOTSTRAP_OPERATOR,allowed: 1 },now),
    env.DB.prepare("INSERT INTO account_notices(id,account,kind,payload,at) VALUES (?,?,'workspace',?,?)").bind(`ntc_${crypto.randomUUID().replaceAll("-","")}`,account,JSON.stringify({ change: "workspace_creation",allowed: 1,by: BOOTSTRAP_OPERATOR }),now),
  ]
}
export function accountRegistrationChallenge(response: Record<string,unknown>): string {
  try {
    const inner = z.object({ response: z.object({ clientDataJSON: z.string().max(4096) }) }).parse(response)
    return z.object({ challenge: z.string().min(1).max(200) }).parse(JSON.parse(fromUtf8(base64UrlDecode(inner.response.clientDataJSON)))).challenge
  } catch { throw new VaultError("bad_request","That passkey could not be verified. Try again.") }
}
export async function accountSignupOptions(env: Env,input: z.infer<typeof AccountSignupOptions>,now = Date.now(),oidcCookie?: string,emailCookie?: string): Promise<{ options: unknown }> {
  const invite = await signupInvite(env,input.invite,now,{ resultId: input.oidcResult,cookie: oidcCookie,emailProof: input.emailProof,emailCookie }),account = randomId("acc")
  const options = await passkeyCeremonies().registrationOptions({ rpId: env.RP_ID,userId: utf8(account),name: input.name })
  // The future account does not exist yet, so challenges.account stays null.
  await env.DB.prepare("INSERT INTO challenges(id,kind,challenge,context,expires_at) VALUES (?,'account-signup',?,?,?)")
    .bind(await sha256Text(options.challenge),options.challenge,JSON.stringify({ account,invite: invite.hash,name: input.name,proof: invite.proof?.id ?? invite.emailProof?.id ?? null }),now+300000).run()
  return { options }
}
export async function accountSignupVerify(env: Env,input: z.infer<typeof AccountSignupVerify>,from: Client = DEFAULT_CLIENT,now = Date.now(),oidcCookie?: string,emailCookie?: string): Promise<{ account: string; session: NewSession; via: "bootstrap" | "join" }> {
  const invite = await signupInvite(env,input.invite,now,{ resultId: input.oidcResult,cookie: oidcCookie,emailProof: input.emailProof,emailCookie })
  const challenge = accountRegistrationChallenge(input.response)
  const stored = await env.DB.prepare("DELETE FROM challenges WHERE id=? AND kind='account-signup' RETURNING challenge,context,expires_at").bind(await sha256Text(challenge)).first<{ challenge: string; context: string; expires_at: number }>()
  if (!stored || stored.expires_at <= now) throw new VaultError("bad_request","That took too long. Start again from the vault page.")
  const context = z.strictObject({ account: z.string(),invite: z.string(),name: z.string(),proof: z.string().nullable() }).parse(JSON.parse(stored.context))
  if (context.invite !== invite.hash || context.name !== input.name || context.proof !== (invite.proof?.id ?? invite.emailProof?.id ?? null)) throw new VaultError("bad_request","That passkey could not be verified. Try again.")
  const passkey = await passkeyCeremonies().verifyRegistration(input.response,{ challenge: stored.challenge,origin: env.VAULT_ORIGIN,rpId: env.RP_ID })
  if (!passkey) throw new VaultError("bad_request","That passkey could not be verified. Try again.")
  const session = await newSession()
  const finalNow = Math.max(now,Date.now())
  const statements = [accountGuard(env,invite.kind === "bootstrap" ? "NOT EXISTS (SELECT 1 FROM accounts)" : "EXISTS (SELECT 1 FROM invite_codes WHERE code_hash=? AND kind='join' AND state='active' AND (email IS NULL OR email=?) AND used_at IS NULL AND used_by_account IS NULL AND expires_at>?)",invite.kind === "bootstrap" ? [] : [invite.hash,invite.proof?.email ?? invite.emailProof?.email ?? null,finalNow]),
    ...(invite.kind === "bootstrap" ? bootstrapAccountStatements(env,context.account,input.name,finalNow) : [env.DB.prepare("INSERT INTO accounts(id,name,created_at) VALUES (?,?,?)").bind(context.account,input.name,finalNow)]),
    insertAccountPasskey(env,context.account,passkey,finalNow,"signup"),
    refreshAccountRecoverySetup(env,context.account,finalNow),
    ...accountSessionStatements(env,session,context.account,finalNow,{ kind: "web",method: "signup",passkey: passkey.credentialId,...from }),
    accountEvent(env,context.account,"account.signup",{ via: invite.kind,...from },finalNow),
  ]
  if (invite.kind === "join") statements.push(env.DB.prepare("UPDATE invite_codes SET used_by_account=? WHERE code_hash=?").bind(context.account,invite.hash))
  if (invite.proof) statements.push(oidcResultGuard(env,invite.proof,finalNow),env.DB.prepare("UPDATE oidc_results SET state='joining',account=?,session=?,security_epoch=0 WHERE id=?").bind(context.account,session.id,invite.proof.id))
  if (invite.emailProof) statements.push(emailProofGuard(env,invite.emailProof,finalNow),holdEmailProof(env,invite.emailProof,{ account: context.account,session: session.id,securityEpoch: 0 },null))
  await accountBatch(env,statements)
  return { account: context.account,session,via: invite.kind }
}
export async function accountSigninOptions(env: Env,now = Date.now(),identification?: { result: string; cookie: string }): Promise<{ flow: string; options: unknown }> {
  const options = await passkeyCeremonies().authenticationOptions({ rpId: env.RP_ID }),flow = randomToken()
  let context: { account: string; result: string; cookieHash: string } | null = null
  if (identification) {
    const result = await readOidcResult(env,identification.result,identification.cookie,"signin",now),identity = await identityForResult(env,result)
    if (!identity) throw oidcRefusal("no_linked_identity","signin")
    context = { account: identity.account,result: result.id,cookieHash: result.cookie_hash }
  }
  await env.DB.prepare("INSERT INTO challenges(id,kind,challenge,context,expires_at) VALUES (?,'account-signin',?,?,?)").bind(flow,options.challenge,context ? JSON.stringify(context) : null,now+300000).run()
  return { flow,options }
}
export async function accountSigninVerify(env: Env,input: z.infer<typeof AccountSigninVerify>,from: Client = DEFAULT_CLIENT,now = Date.now(),kind: "web" | "app" = "web",oidcCookie?: string): Promise<{ account: string; session: NewSession }> {
  const refusal = () => new VaultError("unauthenticated","We could not sign you in with that passkey.")
  const stored = await env.DB.prepare("DELETE FROM challenges WHERE id=? AND kind='account-signin' RETURNING challenge,context,expires_at").bind(input.flow).first<{ challenge: string; context: string | null; expires_at: number }>()
  if (!stored || stored.expires_at <= now) throw refusal()
  const key = await findAccountPasskey(env,credentialId(input.response))
  if (!key) throw refusal()
  let identification: OidcResult | null = null
  if (stored.context) {
    const context = z.strictObject({ account: z.string(),result: z.string(),cookieHash: z.string() }).parse(JSON.parse(stored.context))
    if (!oidcCookie || context.account !== key.account || kind !== "web") throw refusal()
    identification = await readOidcResult(env,context.result,oidcCookie,"signin",now)
    if (identification.cookie_hash !== context.cookieHash) throw refusal()
  }
  const verified = await passkeyCeremonies().verifyAuthentication(input.response,{ challenge: stored.challenge,origin: env.VAULT_ORIGIN,rpId: env.RP_ID },key.record)
  if (verified === null) throw refusal()
  await refuseSuspendedAccount(env,key.account)
  const session = await newSession()
  const finalNow = Math.max(now,Date.now())
  if (stored.expires_at<=finalNow) throw refusal()
  try {
    await accountBatch(env,[
      accountGuard(env,`EXISTS (SELECT 1 FROM accounts a JOIN passkeys p ON p.account=a.id WHERE a.id=? AND a.status='active' AND a.suspended_at IS NULL AND p.handle=? AND NOT EXISTS
        (SELECT 1 FROM account_security_transitions t,json_each(t.removed_factors) f WHERE t.account=a.id AND t.state='pending' AND f.value=p.handle))`,[key.account,key.handle]),
      env.DB.prepare("UPDATE passkeys SET counter=MAX(counter,?),backed_up=?,last_used_at=?,last_used_client=?,last_used_place=? WHERE handle=?").bind(verified.counter,Number(verified.backedUp),finalNow,from.client,from.place,key.handle),
      refreshAccountRecoverySetup(env,key.account,finalNow),
      ...accountSessionStatements(env,session,key.account,finalNow,{ kind,method: "passkey",passkey: key.record.credentialId,...from }),
      accountEvent(env,key.account,"account.signin",{ passkey: key.handle,...from },finalNow),
      ...(identification ? [oidcResultGuard(env,identification,finalNow),consumeOidcResult(env,identification,finalNow)] : []),
    ])
  } catch (error) { if (error instanceof VaultError && error.code === "conflict") throw refusal(); throw error }
  return { account: key.account,session }
}
