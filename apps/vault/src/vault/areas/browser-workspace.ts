// Fill: the vault seals one field of a credential to the asking machine,
// which types it into one web page after checking the page's address
// (packages/protocol/src/fill.ts). This area owns fill's own state and
// POST /v1/fill (browser.fill).

import { type ApprovalSubject, type FillFieldSpec, type FillResponse, FillRequestSchema, KINDS, deviceModeAllowed, fillSealContext, importSealPublicKey, parseProof, parseTotp, seal, signinOrigins, totpCode, typeIntoOrigins } from "@mehen/protocol"
import { VaultError } from "../../http.ts"
import { type AccessPrincipal, principalDevice } from "../access.ts"
import { auditPrivateEvent } from "../audit.ts"
import type { Area, DevicePrincipal, VaultContext } from "../core.ts"
import type { ApprovalPresentation } from "../services.ts"
import { mapCardText } from "../../relay/presentation.ts"
import { spellCardText, textWarnings } from "../../relay/spelling.ts"
import { browserFillOn, FILL_MANAGED_REFUSAL } from "../fill-unavailable.ts"
import { digestOf } from "./approvals.ts"
import { workspaceApproval } from "./approvals-workspace.ts"
import { deviceCovers, devicePolicyState } from "./devices.ts"
import { type CheckedCredential, assertCredentialCurrent, credentialOps, openCredentialSecrets, visibleCredential } from "./items-workspace.ts"
import { type ProtectedSnapshot, assertApprovedUse, consumeApprovedUse, prepareApprovedUse } from "./projects-workspace.ts"
import { accessState, authorise, managedSetting, recordExposure, type WorkspaceInvocationContext } from "./workspace-runtime.ts"
import { principalWorkload, workloadEnded, workloadRow } from "./workloads.ts"

const HOUR_MS = 3_600_000
// Per machine and item: 20 secret fills and 20 codes an hour; per machine:
// 60 fills of any field an hour. Fixed windows, started by the first fill.
type Bucket = { item: string; kind: "secret" | "code" | "any"; limit: number }
const ANY_ITEM = "*"
function bucketsFor(item: string, spec: FillFieldSpec): Bucket[] {
  const own: Bucket[] = spec.input === "username" ? [] : [{ item, kind: spec.input === "one-time-code" ? "code" : "secret", limit: 20 }]
  return [...own, { item: ANY_ITEM, kind: "any", limit: 60 }]
}
// Seconds until the fullest bucket's window ends, or null when none is full.
function bucketRetryAfter(ctx: VaultContext, device: string, buckets: Bucket[], now: number): number | null {
  let wait: number | null = null
  for (const bucket of buckets) {
    const row = ctx.sql.exec<{ window_start: number; count: number }>("SELECT window_start,count FROM fill_buckets WHERE device=? AND item=? AND kind=?", device, bucket.item, bucket.kind).toArray()[0]
    if (!row || now >= row.window_start + HOUR_MS || row.count < bucket.limit) continue
    wait = Math.max(wait ?? 0, Math.ceil((row.window_start + HOUR_MS - now) / 1000))
  }
  return wait
}
function bumpBuckets(ctx: VaultContext, device: string, buckets: Bucket[], now: number): void {
  for (const bucket of buckets)
    ctx.sql.exec("INSERT INTO fill_buckets(device,item,kind,window_start,count) VALUES (?,?,?,?,1) ON CONFLICT(device,item,kind) DO UPDATE SET count=CASE WHEN ?>=window_start+? THEN 1 ELSE count+1 END, window_start=CASE WHEN ?>=window_start+? THEN ? ELSE window_start END", device, bucket.item, bucket.kind, now, now, HOUR_MS, now, HOUR_MS, now)
}

// At most three codes per item, machine and time step, and one step's code
// to one origin only, whichever machine asked.
const CODES_PER_STEP = 3
type Code = { code: string; step: number; validUntilMs: number }
function codeRefusal(ctx: VaultContext, item: string, device: string, origin: string, code: Code, now: number): VaultError | null {
  const elsewhere = ctx.sql.exec<{ origin: string }>("SELECT origin FROM fill_codes WHERE item=? AND step=? AND origin<>? LIMIT 1", item, code.step, origin).toArray()[0]
  if (elsewhere) return new VaultError("origin_mismatch", `This one-time code already went to ${elsewhere.origin}; wait for the next one.`, { retryAfter: Math.max(1, Math.ceil((code.validUntilMs - now) / 1000)) })
  const sent = ctx.sql.exec<{ count: number }>("SELECT count FROM fill_codes WHERE item=? AND step=? AND device=?", item, code.step, device).toArray()[0]?.count ?? 0
  if (sent >= CODES_PER_STEP) return new VaultError("rate_limited", "This machine already had three codes for this time step; wait for the next one.", { retryAfter: Math.max(1, Math.ceil((code.validUntilMs - now) / 1000)) })
  return null
}

const PURPOSE = { signIn: "signin", typeInto: "type_into" } as const

// What one approval allows: every sign-in field but the username (which
// needs none) on one sign-in's page, or one typing into another service's
// page. The ask's constraints and the card's words are both these.
export const FILL_GRANTS = { signIn: { uses: 6, ttlSeconds: 600 }, typeInto: { uses: 1, ttlSeconds: 600 } } as const
type FillGrant = { readonly uses: number; readonly ttlSeconds: number }

type CardItem = Pick<CheckedCredential, "slug" | "kind" | "publicFields">

// "password", "one-time code", or a secret field's own label ("key").
function fieldNoun(item: CardItem, spec: FillFieldSpec): string {
  return spec.input === "one-time-code" ? "one-time code" : spec.input === "secret" ? (KINDS[item.kind].fields.find((f) => f.name === spec.source)?.label ?? spec.name).toLowerCase() : spec.input
}
function whose(item: CardItem): string {
  return item.publicFields.username || item.slug
}
const minutes = (seconds: number): string => {
  const n = Math.max(1, Math.round(seconds / 60))
  return `${n} minute${n === 1 ? "" : "s"}`
}

// The card a human approves, under the page's "An agent on <machine> wants
// to". It names the page's origin, never its path: one sign-in spans
// several pages. A sign-in's card is the same whichever field asked, so
// every field of one sign-in joins one ask. The card is part of what the
// approval is bound to, so a use under changed words asks again; its
// numbers are the grant's own. Hidden characters are spelled and warned
// about, as on a relay card.
export function fillCard(item: CardItem, spec: FillFieldSpec, origin: string, grant: FillGrant): ApprovalPresentation {
  const host = origin.replace(/^https:\/\//, "")
  const card: ApprovalPresentation = spec.signIn ? signInCard(item, origin, host, grant) : {
    title: `Type the ${fieldNoun(item, spec)} of ${whose(item)} into ${host}`,
    details: [{ label: "Page", value: origin }, { label: "Allows", value: `Typed ${grant.uses === 1 ? "once" : `up to ${grant.uses} times`}, within the next ${minutes(grant.ttlSeconds)}.` }],
    body: null,
    warnings: ["This puts the credential into another service. Every time asks you first."],
  }
  const texts: string[] = []
  mapCardText(card, (text) => {
    texts.push(text)
    return text
  })
  const added = textWarnings(texts)
  if (added.length === 0) return card
  const spelled = mapCardText(card, spellCardText)
  return { ...spelled, warnings: [...added, ...(spelled.warnings ?? [])] }
}
function signInCard(item: CardItem, origin: string, host: string, grant: FillGrant): ApprovalPresentation {
  const fields = KINDS[item.kind].fill.filter((field) => field.signIn)
  const [first, ...rest] = fields.filter((field) => field.input !== "username").map((field) => fieldNoun(item, field))
  const also = rest.length > 0
    ? `This also lets it type the ${rest.join(" and ")} on ${origin}, up to ${grant.uses} fields in all, for the next ${minutes(grant.ttlSeconds)}.`
    : `This lets it type it on ${origin} up to ${grant.uses} times, for the next ${minutes(grant.ttlSeconds)}.`
  const free = fields.some((field) => field.input === "username") ? " The username needs no approval." : ""
  return { title: `Type the ${first ?? "value"} for ${whose(item)} into ${host}`, details: [{ label: "Page", value: origin }, { label: "Allows", value: `${also}${free}` }], body: null, warnings: [] }
}

// What the machine says it typed: "the password for alex@example.com".
function label(item: CheckedCredential, spec: FillFieldSpec): string {
  return `the ${fieldNoun(item, spec)} for ${whose(item)}`.slice(0, 200)
}

// item.fill: the machine and its workload, the origin, the field and the
// outcome, the page for a shared credential, and never a value. A private
// credential's is its owner's event, with the origin and the field alone.
function fillAudit(ctx: VaultContext, principal: Extract<AccessPrincipal, { kind: "device" }>, item: CheckedCredential, fill: { origin: string; field: string; page: string }, outcome: string, approval: string | null): void {
  const workload = principal.workload === undefined ? null : workloadRow(ctx, principal.workload)
  if (item.home.kind === "member") {
    const device = accessState(ctx).devices.find((d) => d.id === principal.deviceId)
    const owner = device?.owner.kind === "team" ? { kind: "team" as const, team: device.owner.id } : { kind: "member" as const, member: device?.owner.id ?? "" }
    auditPrivateEvent(ctx, { action: "item.fill", at: ctx.now(), actor: { kind: "device", device: principal.deviceId, owner, ...(workload ? { workload: { id: workload.id, label: workload.label } } : {}) }, session: null, item: item.id, slug: item.slug, outcome, run: null, browser: { origin: fill.origin, field: fill.field } }, item.home.member)
    return
  }
  ctx.audit({ actor: `device:${principal.deviceId}`, action: "item.fill", target: item.slug, detail: { item: item.id, ...(workload ? { workload: workload.id } : {}), origin: fill.origin, field: fill.field, page: fill.page, outcome, approval } })
}

// POST /v1/fill. The checks run in the design's order; a sign-in username
// needs no approval, every other field a current grant, and another
// service's page asks every time.
export async function fillWorkspaceItem(ctx: VaultContext, principal: AccessPrincipal, raw: unknown, invocation: WorkspaceInvocationContext): Promise<FillResponse> {
  if (principal.kind !== "device" || invocation.auth.kind !== "device") throw new VaultError("forbidden", "Only an enrolled machine can type into web pages.")
  if (!browserFillOn(ctx.env, ctx.tenant)) throw new VaultError("forbidden", "Typing into web pages is not available in this workspace.")
  if (managedSetting(ctx) !== null) throw new VaultError("forbidden", FILL_MANAGED_REFUSAL)
  const req = FillRequestSchema.parse(raw)
  const now = ctx.now()
  const state = accessState(ctx), device = principalDevice(state, principal, now), policyDevice = devicePolicyState(ctx, principal.deviceId)
  const workload = principal.workload === undefined ? null : workloadRow(ctx, principal.workload)
  if (principal.workload !== undefined && (!device || !workload)) throw workloadEnded()
  if (!device || !policyDevice?.active) throw new VaultError("not_found", "No such machine.")
  const context = req.context ?? null
  const item = visibleCredential(ctx, principal, req.item, { context, mode: "fill" })
  const spec = KINDS[item.kind].fill.find((field) => field.name === req.field)
  if (!spec) throw new VaultError("bad_request", `"${item.slug}" has no field "${req.field}" that can be typed into a web page.`)
  if (item.status === "disabled") throw new VaultError("forbidden", `"${item.slug}" is disabled.`)
  if (!deviceModeAllowed(item.ceiling, "fill")) throw new VaultError("mode_refused", `"${item.slug}" may not be typed into web pages: its exposure ceiling is ${item.ceiling}.`, { next: { say: "Only a human can change its ceiling, in the vault." } })
  const legacy: DevicePrincipal = { kind: "device", device: principal.deviceId, name: policyDevice.name, scope: device.scope, session: null, grant: null, workload: workload ? principalWorkload(workload) : null }
  if (!deviceCovers(legacy, item, "fill")) throw new VaultError("forbidden", `This machine's scope does not cover typing "${item.slug}" into web pages.`, { next: { say: "A human can widen this machine's scope in the vault." } })
  authorise(ctx, invocation, { type: "item.use", context }, { credential: item.id, mode: "fill" }, now)
  const fill = { origin: req.origin, field: spec.name, page: req.page }
  const allowed = spec.signIn ? signinOrigins(item) : typeIntoOrigins(item)
  if (!allowed.includes(req.origin)) {
    ctx.storage.transactionSync(() => fillAudit(ctx, principal, item, fill, "refused:origin_mismatch", null))
    throw new VaultError("origin_mismatch", spec.signIn ? `${req.origin} is not one of the sign-in pages for "${item.slug}".` : `${req.origin} is not a page "${item.slug}" may be typed into.`, { next: { say: "Only a human can add a page, on the credential's page in the vault." } })
  }
  const buckets = bucketsFor(item.id, spec)
  const limited = (retryAfter: number): VaultError => {
    ctx.storage.transactionSync(() => fillAudit(ctx, principal, item, fill, "refused:rate_limited", null))
    return new VaultError("rate_limited", "This machine has typed this credential too often in the last hour.", { retryAfter })
  }
  const wait = bucketRetryAfter(ctx, principal.deviceId, buckets, now)
  if (wait !== null) throw limited(wait)

  let grant: { snapshot: ProtectedSnapshot; approval: string } | null = null
  if (spec.input !== "username") {
    const purpose = spec.signIn ? PURPOSE.signIn : PURPOSE.typeInto
    const fields = spec.signIn ? KINDS[item.kind].fill.filter((field) => field.signIn).map((field) => field.name) : [spec.name]
    const grantTerms = spec.signIn ? FILL_GRANTS.signIn : FILL_GRANTS.typeInto
    const subject: ApprovalSubject = { item: item.slug, method: "FILL", url: `${req.origin}/`, contentType: null, contentEncoding: null, headersSha256: digestOf([]), bodySha256: digestOf({ purpose, fields }), constraints: { ...grantTerms } }
    const batch = { floor: spec.signIn ? [] : ["sharing" as const], shape: digestOf({ fill: req.origin, purpose }), replaces: null }
    const projection = { id: item.id, slug: item.slug, home: item.home, configRevision: item.configRev }
    const approved = prepareApprovedUse(ctx, state, { principal, workspace: invocation.workspace, presentation: fillCard(item, spec, req.origin, grantTerms), mode: "fill", batch }, projection, context ? { project: context.project, env: context.environment } : null, subject, req.approval ?? null, now)
    if (approved.kind === "required") {
      const asked = workspaceApproval(ctx, approved.approvalId)
      if (!asked) throw new VaultError("not_found", "No such approval.")
      throw new VaultError("approval_required", "Typing this into a web page needs a human's approval.", { approval: approved.approvalId, bindingCode: asked.binding_code, expiresAt: new Date(asked.expires_at).toISOString(), deciders: approved.deciders, next: { url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/a/${approved.approvalId}`, ...(principal.workload === undefined ? { command: `mehen wait ${approved.approvalId}` } : {}), say: approved.deciders.length ? `Send this link to ${approved.deciders.join(" or ")}.` : "Send this link to a manager of the project, or open Needs you in the workspace." } })
    }
    grant = { snapshot: approved.snapshot, approval: approved.approvalId }
  }

  // The value, from what is stored now; a code from the vault's clock.
  let value: string
  let code: Code | null = null
  if (spec.input === "username") value = item.publicFields[spec.source] ?? ""
  else {
    const stored = (await openCredentialSecrets(ctx, item))[spec.source] ?? ""
    if (spec.input === "one-time-code" && stored !== "") {
      const parsed = parseTotp(stored)
      if (!parsed.ok) {
        ctx.storage.transactionSync(() => fillAudit(ctx, principal, item, fill, "refused:totp_unreadable", null))
        throw new VaultError("totp_unreadable", `The one-time code secret cannot be read. ${parsed.reason}`)
      }
      code = await totpCode(parsed.totp, now)
      value = code.code
    } else value = stored
  }
  if (value === "") throw new VaultError("not_found", `"${item.slug}" has no ${spec.name} stored.`)
  if (code) {
    const refusal = codeRefusal(ctx, item.id, principal.deviceId, req.origin, code, now)
    if (refusal) {
      ctx.storage.transactionSync(() => fillAudit(ctx, principal, item, fill, `refused:${refusal.code}`, null))
      throw refusal
    }
  }
  const jti = parseProof(invocation.auth.proof).claims.jti
  const box = await seal(await importSealPublicKey(req.recipient), value, fillSealContext({ workspace: invocation.workspace.id, item: item.id, field: spec.name, origin: req.origin, jti }))

  // No await after this point: what was checked is still so when the box is handed back.
  ctx.storage.transactionSync(() => {
    const at = ctx.now()
    assertCredentialCurrent(ctx, item)
    visibleCredential(ctx, principal, item.slug, { context, mode: "fill" })
    authorise(ctx, invocation, { type: "item.use", context }, { credential: item.id, mode: "fill" }, at)
    if (principal.workload !== undefined && !principalDevice(accessState(ctx), principal, at)) throw workloadEnded()
    const retry = bucketRetryAfter(ctx, principal.deviceId, buckets, at)
    if (retry !== null) throw new VaultError("rate_limited", "This machine has typed this credential too often in the last hour.", { retryAfter: retry })
    if (code) {
      const refusal = codeRefusal(ctx, item.id, principal.deviceId, req.origin, code, at)
      if (refusal) throw refusal
      // Only this item's current and previous steps are kept: steps are as
      // long as each item's own period, so other items' rows wait for theirs.
      ctx.sql.exec("DELETE FROM fill_codes WHERE item=? AND step<?", item.id, code.step - 1)
      ctx.sql.exec("INSERT INTO fill_codes(item,step,origin,device,count) VALUES (?,?,?,?,1) ON CONFLICT(item,step,device) DO UPDATE SET count=count+1", item.id, code.step, req.origin, principal.deviceId)
    }
    if (grant) {
      assertApprovedUse(ctx, accessState(ctx), grant.snapshot, grant.approval, at)
      consumeApprovedUse(ctx, grant.snapshot, grant.approval)
    }
    bumpBuckets(ctx, principal.deviceId, buckets, at)
    ctx.sql.exec("UPDATE items SET last_used_at=? WHERE id=?", at, item.id)
    fillAudit(ctx, principal, item, fill, "typed", grant?.approval ?? null)
    if (spec.input !== "username") recordExposure(ctx, { event: `fill:${jti}`, item: item.id, version: item.version, member: device.owner.kind === "member" ? device.owner.id : null, device: principal.deviceId, source: "filled", at })
  })
  return { box, item: item.id, field: spec.name, input: spec.input, label: label(item, spec), origin: req.origin, ...(code ? { validUntil: new Date(code.validUntilMs).toISOString() } : {}), by: grant ? { approval: grant.approval } : { free: true } }
}

export const browserArea: Area = {
  name: "browser",
  migrations: [
    // fill_buckets: the hourly rate limits, one row per device, item and
    // kind of fill, its window's start (ms) and the fills in it.
    // fill_codes: the one-time codes sent for an item in one time step, per
    // device, and the one origin every code of that step went to.
    `CREATE TABLE fill_buckets (
       device TEXT NOT NULL,
       item TEXT NOT NULL,
       kind TEXT NOT NULL,
       window_start INTEGER NOT NULL,
       count INTEGER NOT NULL,
       PRIMARY KEY (device, item, kind)
     );
     CREATE TABLE fill_codes (
       item TEXT NOT NULL,
       step INTEGER NOT NULL,
       origin TEXT NOT NULL,
       device TEXT NOT NULL,
       count INTEGER NOT NULL,
       PRIMARY KEY (item, step, device)
     );`,
  ],
  workspaceOps: credentialOps({ "browser.fill": { auth: ["device"], handler: fillWorkspaceItem } }),
}
