import { z } from "zod"
import { CredentialHomeSchema, KINDS, canonicalJson, type CustomOAuthProvider, customItemPolicy, getTemplate, isLeaseOnly, isSealedBox, leaseOnlyAllowed, leaseOnlyBinding, leaseOnlyRefusal, mintOnly, mintOnlyRefusal, NATURAL_INJECTION, openText, type CredentialHome, type PrivateEvent, type WorkspaceIntakeView } from "@mehen/protocol"
import { BindingSchema, InjectionSchema, KindSchema, WorkspaceIntakeCreate, Slug, Tag, type IntakeStatus } from "@mehen/protocol/api"
import type { AccessPrincipal } from "../access.ts"
import { one, randomId, type VaultContext } from "../core.ts"
import { auditPrivateEvent } from "../audit.ts"
import { VaultError } from "../../http.ts"
import { sealPrivateKey, sealPublicJwk } from "../../seal-key.ts"
import { devicePolicyState } from "./devices.ts"
import { IntakeSubmission, MEMBER_REASON, assertProposedInjection } from "./intake.ts"
import { assertBindingHosts, parseOpInput, stepUpDigest } from "./items.ts"
import { assertCredentialCurrent, assertCredentialNameFree, assertCredentialReservation, assertNameBudget, unavailableName, assertItemRight, checkedCredential, credentialAccessState, credentialAudit, credentialCreationContext, creationHome, describeCredential, missingCredential, prepareCredential, storeCredential, visibleCredential, type CheckedCredential, type WorkspaceItemInput } from "./items-workspace.ts"
import { askingWorkload, assertWorkloadAskRoom, assertWorkloadMayAsk, assertWorkloadMayFollow } from "./workloads.ts"
import { MACHINE_MAX_OPEN_ASKS, machineAsksFull } from "./approvals-workspace.ts"
import { heldManagedPlatform } from "../managed-platform.ts"
import { waitForStorageWrite } from "../storage-waits.ts"
import { FILL_MANAGED_REFUSAL, refuseFillUnlessOn } from "../fill-unavailable.ts"
import { managedSetting, nameMiss, requireStepUp, openAskCount, registerOpenAskCounter, registerWorkloadAskCounter, type WorkspaceInvocationContext } from "./workspace-runtime.ts"

export const workspaceRequestMigration = `CREATE TABLE workspace_credential_requests (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, slug TEXT NOT NULL, home TEXT NOT NULL,
 requester_member TEXT, requester_device TEXT, status TEXT NOT NULL, payload TEXT NOT NULL,
 target_id TEXT, client_id TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
 ); CREATE INDEX workspace_requests_slug ON workspace_credential_requests(slug,status);
 CREATE INDEX workspace_requests_member ON workspace_credential_requests(requester_member);
 CREATE INDEX workspace_requests_device ON workspace_credential_requests(requester_device);`
// The workload that asked, when one did: only it may poll or wait on the
// request; it or its device's own key may cancel it.
export const workspaceRequestWorkloadMigration = `ALTER TABLE workspace_credential_requests ADD COLUMN requester_workload TEXT;
CREATE INDEX workspace_requests_workload ON workspace_credential_requests(requester_workload);`
registerOpenAskCounter("credentials", (ctx, device, now) => one(ctx.sql.exec<{
  count: number
}>("SELECT count(*) AS count FROM workspace_credential_requests WHERE requester_device=? AND status='open' AND expires_at>?", device, now))?.count ?? 0)
registerWorkloadAskCounter("credentials", (ctx, workload, now) => one(ctx.sql.exec<{ count: number }>("SELECT count(*) AS count FROM workspace_credential_requests WHERE requester_workload=? AND status='open' AND expires_at>?", workload, now))?.count ?? 0)

export type CredentialRequest = {
  id: string
  kind: string
  slug: string
  home: string
  requester_member: string | null
  requester_device: string | null
  requester_workload: string | null
  status: string
  payload: string
  target_id: string | null
  client_id: string | null
  created_at: number
  expires_at: number
}

export function requestRow(ctx: VaultContext, id: string): CredentialRequest {
  const row = one(ctx.sql.exec<CredentialRequest>("SELECT * FROM workspace_credential_requests WHERE id=?", id))
  if (!row)
    throw new VaultError("not_found", "No such credential request.")
  return row
}

export function requestHome(row: CredentialRequest): CredentialHome { return CredentialHomeSchema.parse(JSON.parse(row.home)); }

export function requestAuthority(ctx: VaultContext, p: AccessPrincipal, row: CredentialRequest, invocation: WorkspaceInvocationContext): void {
  try {
    if (p.kind === "member" && credentialAccessState(ctx).members.find(member => member.id === p.memberId)?.standing.effectiveRole === "guest" && row.requester_member !== p.memberId)
      throw new VaultError("not_found", "No such credential request.")
    if (p.kind === "device" && (row.requester_device !== p.deviceId || row.requester_workload !== (p.workload ?? null)))
      throw new VaultError("not_found", "No such credential request.")
    const payload=JSON.parse(row.payload) as {tags?:string[];originalHome?:CredentialHome}
    if(payload.originalHome?.kind === "member")assertItemRight(ctx,invocation,{type:"item.read"},{destinationHome:payload.originalHome,prospectiveSlug:row.slug,prospectiveTags:(row.target_id?checkedCredential(ctx,row.slug)?.tags:null)??payload.tags??[]})
    if (row.target_id) {
      visibleCredential(ctx, p, row.slug, undefined, invocation)
      assertItemRight(ctx, invocation, { type: "item.read" }, { credential: row.target_id })
    }
    else {
      const payload = JSON.parse(row.payload) as {
        tags?: string[]
      }
      assertItemRight(ctx, invocation, { type: "item.read" }, { destinationHome: requestHome(row), prospectiveSlug: row.slug, prospectiveTags: payload.tags ?? [] })
    }
  }
  catch (error) {
    if (error instanceof VaultError && ["not_found", "forbidden", "owner_inactive", "environment_refused"].includes(error.code))
      throw new VaultError("not_found", "No such credential request.")
    throw error
  }
}

export function cancelCredentialRequest(ctx: VaultContext, p: AccessPrincipal, id: string, kind: "intake" | "connect", invocation: WorkspaceInvocationContext): Record<string, never> {
  return ctx.storage.transactionSync(() => {
    const row = requestRow(ctx, id)
    // Only the key that asked cancels: a workload its own asks, the device's
    // own key its own. The device ends a workload's asks by revoking it.
    if (row.kind !== kind || p.kind === "device" && row.requester_workload !== (p.workload ?? null))
      throw new VaultError("not_found", "No such credential request.")
    try {
      assertItemRight(ctx, invocation, { type: kind === "intake" ? "intake.cancel" : "connect.cancel" }, { device: row.requester_device ?? undefined, creator: row.requester_device ? undefined : row.requester_member ?? undefined, destinationHome: requestHome(row), credential: row.target_id ?? undefined, ask: row.requester_device ? { device: row.requester_device, credential: row.target_id, credentials: row.target_id ? [row.target_id] : [], context: null } : undefined })
    }
    catch (error) {
      if (error instanceof VaultError && ["not_found", "forbidden", "owner_inactive"].includes(error.code))
        throw new VaultError("not_found", "No such credential request.")
      throw error
    }
    requestOpen(ctx, row)
    ctx.sql.exec("UPDATE workspace_credential_requests SET status='cancelled' WHERE id=?", row.id)
    requestAudit(ctx, p, { ...row, status: "cancelled" }, kind === "intake" ? "intake.cancel" : "oauth.connect_cancel", invocation)
    return {}
  })
}

export const RequestWait = { wait: z.boolean().optional(), waitMs: z.number().int().min(0).max(30000).optional() }

export async function waitForCredentialRequest(ctx: VaultContext, p: AccessPrincipal, id: string, invocation: WorkspaceInvocationContext, ms: number): Promise<CredentialRequest> {
  const deadline = ctx.now() + ms
  for (;;) {
    const row = requestRow(ctx, id)
    requestAuthority(ctx, p, row, invocation)
    const now = ctx.now()
    if (row.status !== "open" || row.expires_at <= now || now >= deadline) return row
    await waitForStorageWrite(ctx.storage, Math.min(deadline, row.expires_at) - now)
  }
}

export function requestOpen(ctx: VaultContext, row: CredentialRequest): void { if (row.status !== "open" || ctx.now() >= row.expires_at)
  throw new VaultError("conflict", "This credential request is no longer open."); }

export function requestTarget(ctx: VaultContext, row: CredentialRequest): CheckedCredential | null {
  if (!row.target_id)
    return null
  const target = checkedCredential(ctx, row.slug)
  if (!target || target.id !== row.target_id)
    throw missingCredential(row.slug)
  return target
}

export function checkFiller(ctx: VaultContext, p: AccessPrincipal, row: CredentialRequest, invocation: WorkspaceInvocationContext, home = requestHome(row)) {
  const target = requestTarget(ctx, row)
  return assertItemRight(ctx, invocation, target ? { type: "credential.rotate" } : { type: "credential.create" }, target ? { credential: target.id } : { destinationHome: home })
}

export function createCredentialRequest(ctx: VaultContext, p: AccessPrincipal, input: {
  kind: string
  slug: string
  home: CredentialHome
  // The credential's tags: the request's, or for a rotation the target's.
  tags: string[]
  payload: Record<string, unknown>
  target: CheckedCredential | null
  client?: CheckedCredential
  ttl?: number
}, invocation: WorkspaceInvocationContext): CredentialRequest {
  // A liveness gate before any namespace probe.
  assertItemRight(ctx, invocation, p.kind === "device" ? { type: "device.read_self" } : { type: "asks.read" }, p.kind === "device" ? { device: p.deviceId } : {})
  assertWorkloadMayFollow(ctx, p, { slug: input.slug, tags: input.tags, home: input.home })
  assertNameBudget(ctx, p)
  const workload = p.kind === "device" ? p.workload ?? null : null
  const open = one(ctx.sql.exec<CredentialRequest>("SELECT * FROM workspace_credential_requests WHERE slug=? AND kind=? AND status='open' AND expires_at>? AND ((requester_device=? AND ? IS NOT NULL AND requester_workload IS ?) OR (requester_device IS NULL AND requester_member=? AND ? IS NULL)) ORDER BY created_at DESC LIMIT 1", input.slug, input.kind, ctx.now(), p.kind === "device" ? p.deviceId : null, p.kind === "device" ? p.deviceId : null, workload, p.kind === "member" ? p.memberId : null, p.kind === "device" ? p.deviceId : null))
  if (open) {
    const normal = (value: Record<string, unknown>) => { const { requestItemId: _id, fresh: _fresh,originalHome:_home, ...rest } = value; return rest; }
    if (input.payload.fresh === true) {
      ctx.sql.exec("UPDATE workspace_credential_requests SET status='cancelled' WHERE id=?", open.id)
      requestAudit(ctx, p, { ...open, status: "cancelled" }, "credential.request_superseded", invocation)
    }
    else if (open.home === JSON.stringify(input.home) && canonicalJson(normal(JSON.parse(open.payload) as Record<string, unknown>)) === canonicalJson(normal(input.payload)))
      return open
    else
      unavailableName(ctx, p)
  }
  if (input.target) {
    visibleCredential(ctx, p, input.slug, undefined, invocation)
    if (p.kind === "device")
      assertItemRight(ctx, invocation, { type: "credential.rotate" }, { credential: input.target.id })
  }
  else {
    assertItemRight(ctx, invocation, { type: "credential.create" }, { destinationHome: input.home })
    assertCredentialNameFree(ctx, p, input.slug)
  }
  if (p.kind === "device" && openAskCount(ctx, p.deviceId, ctx.now()) >= MACHINE_MAX_OPEN_ASKS)
    throw machineAsksFull(ctx, { device: p.deviceId, ...(p.workload !== undefined ? { workload: p.workload } : {}) }, invocation.workspace.slug, "This machine already has 20 open asks.")
  if (p.kind === "device")
    assertWorkloadAskRoom(ctx, p.workload)
  const state = credentialAccessState(ctx)
  const device = p.kind === "device" ? state.devices.find(d => d.id === p.deviceId) : null
  const id = randomId(input.kind === "connect" ? "con" : "int")
  const member = p.kind === "member" ? p.memberId : device?.owner.kind === "member" ? device.owner.id : null
  const payload = { ...input.payload,originalHome:input.home, requestItemId: input.target?.id ?? randomId("itm") }
  return ctx.storage.transactionSync(() => {
    ctx.sql.exec("INSERT INTO workspace_credential_requests(id,kind,slug,home,requester_member,requester_device,status,payload,target_id,client_id,created_at,expires_at,requester_workload) VALUES (?,?,?,?,?,?,'open',?,?,?,?,?,?)", id, input.kind, input.slug, JSON.stringify(input.home), member, p.kind === "device" ? p.deviceId : null, JSON.stringify(payload), input.target?.id ?? null, input.client?.id ?? null, ctx.now(), ctx.now() + (input.ttl ?? 86400000), workload)
    const row = requestRow(ctx, id)
    requestAudit(ctx, p, row, input.kind === "connect" ? "oauth.connect_request" : "intake.request", invocation)
    return row
  })
}

export function requestAudit(ctx: VaultContext, p: AccessPrincipal, row: CredentialRequest, action: string, invocation: WorkspaceInvocationContext): void {
  const home = requestHome(row), payload = JSON.parse(row.payload) as {
    requestItemId: string
    originalHome?:CredentialHome
  }
  if (home.kind === "member"||payload.originalHome?.kind === "member") {
    const device = p.kind === "device" ? credentialAccessState(ctx).devices.find(d => d.id === p.deviceId) : null
    const actor: PrivateEvent["actor"] = p.kind === "member" ? { kind: "member", member: p.memberId } : { kind: "device", device: p.deviceId, owner: device?.owner.kind === "team" ? { kind: "team", team: device.owner.id } : { kind: "member", member: device?.owner.id ?? "" } }
    auditPrivateEvent(ctx, { action, at: ctx.now(), actor, session: invocation.auth.kind === "account" ? invocation.auth.session : null, item: payload.requestItemId, slug: row.slug, outcome: row.status, run: null }, payload.originalHome?.kind === "member" ? payload.originalHome.member : home.kind === "member" ? home.member : "")
  }
  else
    ctx.audit({ actor: p.kind === "member" ? `member:${p.memberId}` : `device:${p.deviceId}`, action, target: row.id, detail: { item: payload.requestItemId, outcome: row.status } })
}
const CreateMember = z
  .strictObject({
    provider: z.string().max(64).optional(),
    kind: KindSchema.optional(),
    binding: BindingSchema.optional(),
    injection: InjectionSchema.optional(),
    slug: Slug,
    tags: z.array(Tag).max(16).default([]),
    home: z.enum(["private", "project", "workspace"]),
    project: z.string().optional(),
    fresh: z.boolean().optional(),
  })
  .refine(input => (input.home === "project" ? input.project !== undefined : input.project === undefined), "Project home requires its project id")

function createIntakeRequest(ctx:VaultContext,p:AccessPrincipal,input:unknown,invocation:WorkspaceInvocationContext){
 const raw=p.kind === "device"?parseOpInput(WorkspaceIntakeCreate,input):parseOpInput(CreateMember,input)
 if("kind" in raw&&raw.kind!==undefined&&mintOnly(raw.kind))throw new VaultError("bad_request",mintOnlyRefusal(raw.kind))
 const template=raw.provider?getTemplate(raw.provider):null
 if(raw.provider&&!template)throw new VaultError("bad_request","Unknown credential template.")
 // In a managed workspace the platform's defaults apply when an intake is
 // made, by a device as by the platform (areas/managed.ts): its template
 // list, and its default tags on a new item.
 const defaults=managedSetting(ctx)?heldManagedPlatform(ctx).platform.defaults:null
 if(template&&defaults?.templates!==undefined&&!defaults.templates.includes(template.id))throw new VaultError("bad_request","This platform does not offer that service.")
 const proposedHome=creationHome(ctx,p,raw.home,raw.project)
 assertWorkloadMayAsk(ctx,p,raw.slug,proposedHome)
 if(p.kind === "device"&&proposedHome.kind === "member")assertItemRight(ctx,invocation,{type:"credential.create"},{destinationHome:proposedHome})
 assertNameBudget(ctx,p)
 const rotationOnly=p.kind === "member"&&!raw.provider&&!("kind" in raw&&raw.kind!==undefined)
 let target:CheckedCredential|null=null
 if(checkedCredential(ctx,raw.slug)){
  try{target=visibleCredential(ctx,p,raw.slug,undefined,invocation)}catch(error){if(error instanceof VaultError&&error.code === "not_found"){if(rotationOnly)throw missingCredential(raw.slug);assertItemRight(ctx,invocation,{type:"credential.create"},{destinationHome:proposedHome});unavailableName(ctx,p)}throw error}
 }
 if(rotationOnly&&!target)throw missingCredential(raw.slug)
 assertItemRight(ctx,invocation,target?{type:"credential.rotate"}:{type:"credential.create"},target?{credential:target.id}:{destinationHome:proposedHome})
 if(target&&raw.provider!==undefined&&raw.provider!==target.provider)throw new VaultError("conflict","Rotation keeps the credential provider.")
 if(p.kind === "member"&&target&&(("binding" in raw&&raw.binding!==undefined)||("injection" in raw&&raw.injection!==undefined)))throw new VaultError("conflict","Rotation keeps the credential destination and injection.")
 const kind=target?.kind??template?.kind??("kind" in raw&&raw.kind!==undefined?raw.kind:null)
 if(!kind)throw new VaultError("bad_request","Choose a built-in template or a credential kind.")
 if(mintOnly(kind))throw new VaultError("bad_request",mintOnlyRefusal(kind))
 if("kind" in raw&&raw.kind!==undefined&&raw.kind!==kind)throw new VaultError("bad_request","The credential kind does not match its template.")
 const home=p.kind === "member"&&target?target.home:proposedHome
 if(home.kind === "member")assertItemRight(ctx,invocation,{type:"credential.create"},{destinationHome:home})
 if(target&&canonicalJson(target.home)!==canonicalJson(home))throw new VaultError("conflict","Rotation keeps the credential home.")
 // A custom credential proposed with no binding and no injection is
 // lease-only, unless its kind is one the relay puts into requests.
 const proposedBinding="binding" in raw?raw.binding:undefined
 const leaseOnly=!target&&!template&&proposedBinding===undefined
 if(!target&&!template){
  const injection="injection" in raw?raw.injection:undefined
  if(injection&&NATURAL_INJECTION[kind]===null)throw new VaultError("bad_request",`The relay never puts a ${KINDS[kind].label} into a request, so it takes no injection. Leave it out.`)
  if(injection&&(!proposedBinding||isLeaseOnly(proposedBinding)))throw new VaultError("bad_request","A custom credential sent with an injection needs a binding: name the hosts it goes to with --host.")
  if((!proposedBinding||isLeaseOnly(proposedBinding))&&!leaseOnlyAllowed(kind))throw new VaultError("bad_request",leaseOnlyRefusal(kind))
  if(proposedBinding)assertBindingHosts(proposedBinding)
  if(injection)assertProposedInjection(kind,injection)
 }
 const tags=target?.tags??(defaults?[...new Set([...defaults.tags,...(raw.tags??[])])]:raw.tags??[])
 if(tags.length>16)throw new VaultError("bad_request","An item carries at most 16 tags.")
 const row=createCredentialRequest(ctx,p,{kind:"intake",slug:raw.slug,home,tags,payload:{...raw,kind,provider:target?target.provider:raw.provider,tags,target,...(leaseOnly?{binding:leaseOnlyBinding()}:{})},target},invocation)
 // A managed workspace has no page to fill it in: its platform submits it.
 return {intake:row.id,...(managedSetting(ctx)?{}:{url:`${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/i/${row.id}`}),expiresAt:new Date(row.expires_at).toISOString()}
}

export function createWorkspaceIntake(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext) {
  // A liveness gate before any namespace probe.
  assertItemRight(ctx, invocation, p.kind === "device" ? { type: "device.read_self" } : { type: "asks.read" }, p.kind === "device" ? { device: p.deviceId } : {})
  try {
    return ctx.storage.transactionSync(() => createIntakeRequest(ctx, p, input, invocation))
  }
  catch (e) {
    if (e instanceof VaultError && e.code === "conflict" && e.message === "name not available")
      nameMiss.record(ctx, p, ctx.now())
    throw e
  }
}
function assertRotationTarget(ctx: VaultContext, target: CheckedCredential): void {
  try { assertCredentialCurrent(ctx, target) }
  catch (error) {
    if (error instanceof VaultError && error.code === "conflict") throw new VaultError("conflict", "The credential changed; ask again.")
    throw error
  }
}
const submitSchema = () => IntakeSubmission.extend({ intake: z.string(), home: CredentialHomeSchema })

// A check its caller makes in the transaction that stores the item, beside
// the name's reservation: the target for a rotation, null for a new item
// (a managed workspace's item limit, areas/managed.ts).
export type IntakeStoreCheck = (target: CheckedCredential | null) => void

export async function submitWorkspaceIntake(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext, storeCheck?: IntakeStoreCheck) {
  const req = parseOpInput(submitSchema(), input)
  const row = requestRow(ctx, req.intake)
  requestAuthority(ctx, p, row, invocation)
  requestOpen(ctx, row)
  const decision = checkFiller(ctx, p, row, invocation, req.home)
  const { intake: _intake, ...submission } = req
  const payload = JSON.parse(row.payload) as {
    tags?: string[]
    target?: CheckedCredential
  }
  const tags = payload.target?.tags ?? payload.tags ?? []
  if (canonicalJson([...req.tags].sort()) !== canonicalJson([...tags].sort()))
    throw new VaultError("forbidden", "The credential tags must match the request.")
  const digest = await stepUpDigest({ ...submission, tags: [...tags].sort() })
  requireStepUp(ctx, decision, { type: "intake.submit", intake: row.id, digest }, invocation)
  const plan = JSON.parse(row.payload) as {
    kind: WorkspaceItemInput["kind"]
    provider?: string
    binding?: WorkspaceItemInput["binding"]
    injection?: WorkspaceItemInput["injection"]
    target: CheckedCredential | null
    requestItemId: string
    connect?: string
    // An OAuth client with its own provider definition (a platform's intake,
    // areas/managed.ts): written once to items.custom_provider with the new
    // item, and never updated; a rotation keeps it.
    customProvider?: CustomOAuthProvider
  }
  const target = plan.target
  if (target)
    assertRotationTarget(ctx, target)
  const template = target ? (target.provider?getTemplate(target.provider):null) : plan.provider ? getTemplate(plan.provider) : null
  const binding = target?.binding ?? template?.binding ?? plan.binding
  if (req.slug !== row.slug || canonicalJson(binding) !== canonicalJson(req.binding))
    throw new VaultError("bad_request", "The credential name and binding must match the request.")
  if (target && canonicalJson(req.home) !== canonicalJson(target.home))
    throw new VaultError("bad_request", "Rotation keeps the credential home.")
  if (req.allowReads === true && (target || template))
    throw new VaultError("bad_request", "A rotation or template keeps its policy.")
  if (req.allowReads === true && binding !== undefined && isLeaseOnly(binding))
    throw new VaultError("bad_request", "A credential with no host is never sent to a service, so it takes no reads policy.")
  // Fill only ever comes from the person's signed choice; the asker cannot name it.
  if (req.ceiling === "fill") {
    if (target) throw new VaultError("bad_request", "A rotation keeps the credential's ceiling.")
    if (plan.kind !== "password-login") throw new VaultError("bad_request", "Only a website or app login can be typed into web pages.")
    refuseFillUnlessOn(ctx, ["fill"])
    if (managedSetting(ctx) !== null) throw new VaultError("forbidden", FILL_MANAGED_REFUSAL)
  }
  if (target && Object.keys(req.publicFields).length)
    throw new VaultError("bad_request", "A rotation replaces secret fields only.")
  const key = await sealPrivateKey(ctx.env)
  const secrets: Record<string, string> = {}
  for (const [name, box] of Object.entries(req.sealed)) {
    if (!isSealedBox(box))
      throw new VaultError("bad_request", "Invalid sealed field.")
    try {
      secrets[name] = await openText(key, box, `intake/${row.id}/${name}`)
    }
    catch {
      throw new VaultError("bad_request", "The sealed field does not belong to this request.")
    }
  }
  const spec = KINDS[plan.kind]
  const prepared = await prepareCredential(ctx, { slug: row.slug, kind: plan.kind, provider: target?target.provider:plan.provider ?? null, account: target?.account ?? null, accountVerified: target?.accountVerified ?? false, tags: req.tags, home: req.home, ceiling: target?.ceiling ?? req.ceiling ?? template?.ceiling ?? spec.defaultCeiling, binding: req.binding, policy: target?.policy ?? template?.policy ?? customItemPolicy(req.allowReads === true), injection: target ? target.injection : template ? template.injection : plan.injection ?? NATURAL_INJECTION[plan.kind], publicFields: target?.publicFields ?? req.publicFields, secretFields: secrets, description: target?.description ?? null }, target, plan.requestItemId)
  return ctx.storage.transactionSync(() => {
    const live = requestRow(ctx, row.id)
    requestAuthority(ctx, p, live, invocation)
    requestOpen(ctx, live)
    requireStepUp(ctx, checkFiller(ctx, p, live, invocation, req.home), { type: "intake.submit", intake: row.id, digest }, invocation)
    if (target) assertRotationTarget(ctx, target)
    else assertCredentialReservation(ctx, row.slug, row.id)
    storeCheck?.(target)
    const item = storeCredential(ctx, prepared, p, target ? "item.rotate" : "item.create", invocation.auth.kind === "account" ? invocation.auth.session : null)
    if (plan.customProvider !== undefined && !target) ctx.sql.exec("UPDATE items SET custom_provider=? WHERE id=? AND custom_provider IS NULL", canonicalJson(plan.customProvider), item.id)
    ctx.sql.exec("UPDATE workspace_credential_requests SET status='completed',home=? WHERE id=?", JSON.stringify(req.home), row.id)
    if (plan.connect)
      ctx.sql.exec("UPDATE workspace_credential_requests SET expires_at=MIN(expires_at,?) WHERE id=? AND kind='connect'", ctx.now() + 900000, plan.connect)
    credentialAudit(ctx, p, item, "intake.complete", "allowed", req.ceiling === "fill" ? { ceiling: "fill" } : {}, null, invocation.auth.kind === "account" ? invocation.auth.session : null)
    return { item: describeCredential(ctx, item) }
  })
}

export const workspaceIntakeOps = {
  "intake.create": { auth: ["device"] as const, handler: createWorkspaceIntake },
  "intake.createByMember": { auth: ["account"] as const, handler: createWorkspaceIntake },
  "intake.submit": { auth: ["account"] as const, handler: submitWorkspaceIntake },
  "intake.view": { auth: ["account"] as const, async handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): Promise<WorkspaceIntakeView> {
      const { intake } = parseOpInput(z.object({ intake: z.string() }), input)
      requestAuthority(ctx, p, requestRow(ctx, intake), invocation)
      const key = await sealPublicJwk(ctx.env), row = requestRow(ctx, intake)
      requestAuthority(ctx, p, row, invocation)
      const plan = JSON.parse(row.payload) as {
        kind: WorkspaceItemInput["kind"]
        provider?: string
        reason?: string
        tags?: string[]
        binding?: WorkspaceItemInput["binding"]
        injection?: WorkspaceItemInput["injection"]
        target: CheckedCredential | null
        connect?: string
        session?: string
      }
      const target = plan.target, template = target ? (target.provider?getTemplate(target.provider):null) : plan.provider ? getTemplate(plan.provider) : null
      const binding = target?.binding ?? template?.binding ?? plan.binding
      if (!binding)
        throw new VaultError("bad_request", "This credential request has no binding.")
      return { intake: row.id, status: row.status === "open" && row.expires_at <= ctx.now() ? "expired" : row.status as IntakeStatus["status"], kind: plan.kind, slug: row.slug, provider: target?target.provider:plan.provider ?? null, providerName: template?.displayName ?? null, reason: plan.reason ?? MEMBER_REASON, requestedBy: row.requester_device ? { device: row.requester_device, deviceName: devicePolicyState(ctx, row.requester_device)?.name ?? row.requester_device, session: plan.session ?? null, ...askingWorkload(ctx, row.requester_workload) } : { member: row.requester_member ?? "", self: p.kind === "member" && p.memberId === row.requester_member }, rotates: target !== null, fields: KINDS[plan.kind].fields.filter(field => !target || field.secret).map(field => ({ name: field.name, label: template?.fields?.[field.name]?.label ?? field.label, secret: field.secret, required: field.required, multiline: template?.fields?.[field.name]?.multiline ?? field.multiline ?? false, hint: template?.fields?.[field.name]?.hint ?? null })), binding: { value: binding, verified: target !== null || template !== null }, injection: { value: target ? target.injection : template ? template.injection : plan.injection ?? NATURAL_INJECTION[plan.kind], verified: target !== null || template !== null || !plan.injection }, customPolicy: !target && !template && !isLeaseOnly(binding), tags: [...(target?.tags ?? plan.tags ?? [])].sort(), sealKey: key, expiresAt: new Date(row.expires_at).toISOString(), ...credentialCreationContext(ctx, p, requestHome(row), target, null, invocation), ...(plan.connect ? { then: { connect: plan.connect, url: `${ctx.env.VAULT_ORIGIN}/w/${invocation.workspace.slug}/c/${plan.connect}` } } : {}) }
    } },
  "intake.status": { auth: ["device"] as const, async handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext): Promise<IntakeStatus> {
      const { intake, wait, waitMs } = parseOpInput(z.object({ intake: z.string(), ...RequestWait }), input)
      const row = await waitForCredentialRequest(ctx, p, intake, invocation, waitMs ?? (wait ? 30000 : 0))
      return { intake: row.id, status: row.status === "open" && row.expires_at <= ctx.now() ? "expired" : row.status as IntakeStatus["status"], expiresAt: new Date(row.expires_at).toISOString(), ...(row.status === "completed" ? { item: describeCredential(ctx, visibleCredential(ctx, p, row.slug, undefined, invocation), { principal: p, invocation }) } : {}) }
    } },
  "intake.cancel": { auth: ["account", "device"] as const, handler(ctx: VaultContext, p: AccessPrincipal, input: unknown, invocation: WorkspaceInvocationContext) {
      const { intake } = parseOpInput(z.object({ intake: z.string() }), input)
      return cancelCredentialRequest(ctx, p, intake, "intake", invocation)
    } },
}
