// A signed client for an enrolled machine, or for one of its workloads: the
// same routes, the same tenant, a different signer.

import { z } from "zod"
import { type ConnectCreated, type ConnectStatus, ERROR_HEADER, ITEM_HEADER, type IntakeCreated, type IntakeStatus, KindSchema, RelayRequest, type RelayRequestInput, RunCreate, Slug, UPSTREAM_HEADER, WorkspaceConnectCreate, WorkspaceIntakeCreate } from "@mehen/protocol/api"
import { type Bytes, base64UrlEncode, utf8 } from "@mehen/protocol/bytes"
import { type DeviceJwk, type ProofSigner, jwkThumbprint } from "@mehen/protocol/proof"
import { type WorkloadScope, type WorkloadView, WorkloadCreateSchema, WorkloadIdSchema, WorkloadRenewSchema, WorkloadViewSchema } from "@mehen/protocol/workload"
import { type ItemUseContext, type WorkspaceItemDescription, type WorkspaceItemSummary, type WorkspaceNotice, WorkspaceNoticeSchema, type WorkspacePendingAsk, type WorkspaceRunCreated } from "@mehen/protocol/workspace"
import { MehenTransport } from "./errors.ts"
import { vaultLink, vaultOrigin } from "./origin.ts"
import {
  APPROVAL_ID,
  type ApprovalState,
  ApprovalStateSchema,
  CONNECT_ID,
  ConnectStatusSchema,
  EmptySchema,
  INTAKE_ID,
  IntakeStatusSchema,
  ItemListSchema,
  type MachineIdentity,
  MachineIdentitySchema,
  type MachineProject,
  MachineProjectSchema,
  PROJECT_ID,
  RUN_ID,
  type RunEnded,
  RunEndedSchema,
  type RunRenewed,
  RunRenewedSchema,
  WorkloadListAnswerSchema,
  WorkspaceItemDescriptionSchema,
  WorkspaceRunCreatedSchema,
  linkedSchemas,
} from "./responses.ts"
import { type Credentials, LONG_POLL_TIMEOUT_MS, type Method, type SendOptions, type Sent, type TransportOptions, deadlineBody, readAnswer, readBytes, refusalOf, send, transportFor } from "./transport.ts"

export type ClientOptions = TransportOptions & {
  vaultUrl: string
  // The workspace id (tn_...) the device was enrolled in: proof `ten`.
  tenant: string
  signer: ProofSigner
  // Proof `sid` and the session field of relays and asks: an agent session
  // label the vault shows people and records in the audit.
  session?: string
}

export type ItemFilter = { tag?: string; kind?: z.infer<typeof KindSchema>; provider?: string }

// What a relay uses: one item's credential, injected as the item says (with
// the project environment it is used for), or a run, whose placeholders the
// vault swaps wherever the item behind each one allows. A run fixes its own
// project environment.
export type RelayTarget = { item: string; context?: ItemUseContext } | { run: string }

export type RelayInput = RelayTarget & {
  method: string
  url: string
  headers?: [string, string][]
  // Raw bytes, or text sent as UTF-8.
  body?: Bytes | string
  // The approval id, when retrying after a person approved this request.
  approval?: string
}

export type RelayResponse = {
  kind: "response"
  // The upstream's own status: a 4xx or 5xx here is the upstream's answer,
  // never a vault refusal.
  status: number
  headers: Headers
  body: Uint8Array<ArrayBuffer>
  // Mehen-Item: which item, and which account, acted.
  item: string | null
}

// The upstream's answer as it arrives: the body is unread, and the caller
// reads or cancels it. The relay's timeout still runs while it is read: a
// body that stalls past it errors with a MehenTransport timeout.
export type RelayStream = {
  kind: "stream"
  status: number
  headers: Headers
  body: ReadableStream<Uint8Array> | null
  item: string | null
}

export type RelayStreamOptions = { timeoutMs?: number; signal?: AbortSignal }

export type WaitOption = { wait?: boolean }

export type IntakeInput = z.input<typeof WorkspaceIntakeCreate>
export type ConnectInput = z.input<typeof WorkspaceConnectCreate>

export type PendingAsks = { pending: WorkspacePendingAsk[]; notices: WorkspaceNotice[] }

export type WorkloadCreateInput = { jwk: DeviceJwk; label: string; ttlSeconds?: number; scope: WorkloadScope }

// A run as `mehen run` starts one; the session comes from the client's options.
export type RunInput = Omit<z.input<typeof RunCreate>, "session">

// A run lives 15 minutes from creation or its last renewal, and at most 12
// hours (two for an approved protected run). Only the workload that created
// it, or the device's own key for its own runs, uses, renews or ends it.
export type Runs = {
  // POST /v1/runs: each variable's delivery, and the hosts its placeholders are bound to.
  create(input: RunInput): Promise<WorkspaceRunCreated>
  // POST /v1/runs/:id/renew: another 15 minutes, within the run's maximum life.
  renew(id: string): Promise<RunRenewed>
  // DELETE /v1/runs/:id: its placeholders stop working at once.
  end(id: string): Promise<RunEnded>
}

export type Workloads = {
  // Signed by the parent device's own key, never a workload's.
  create(input: WorkloadCreateInput): Promise<WorkloadView>
  // Active workloads only.
  list(): Promise<WorkloadView[]>
  get(id: string): Promise<WorkloadView>
  renew(id: string, options?: { ttlSeconds?: number }): Promise<WorkloadView>
  // Idempotent: revoking an ended workload answers its view again.
  revoke(id: string): Promise<WorkloadView>
}

export type MehenClient = {
  me(): Promise<MachineIdentity>
  items(filter?: ItemFilter): Promise<WorkspaceItemSummary[]>
  item(slug: string): Promise<WorkspaceItemDescription>
  // One HTTP request through the vault with the item's credential injected,
  // or with the run's placeholders swapped for their values. Resolves with
  // the upstream's response, whatever its status; throws MehenRefusal when
  // the vault itself refused (approval_required carries the approval id,
  // binding code, expiry and link). After a MehenTransport
  // the upstream outcome is unknown: the vault may have sent the request, so
  // never retry a non-idempotent request blindly.
  relay(input: RelayInput): Promise<RelayResponse>
  // As relay, but the upstream's body is handed over unread as a stream.
  // The timeout (the client's, unless timeoutMs is given) covers the whole
  // exchange, the body included; aborting `signal` rejects, or errors the
  // body, with the signal's own reason.
  relayStream(input: RelayInput, options?: RelayStreamOptions): Promise<RelayStream>
  // GET /v1/projects/:id: the remotes, environments and variables a run names.
  project(id: string): Promise<MachineProject>
  // wait: long-polls up to 25 s while the approval is pending.
  approval(id: string, options?: WaitOption): Promise<ApprovalState>
  intake(input: IntakeInput): Promise<IntakeCreated>
  intakeStatus(id: string, options?: WaitOption): Promise<IntakeStatus>
  cancelIntake(id: string): Promise<void>
  connect(input: ConnectInput): Promise<ConnectCreated>
  connectStatus(id: string, options?: WaitOption): Promise<ConnectStatus>
  cancelConnect(id: string): Promise<void>
  pending(): Promise<PendingAsks>
  workloads: Workloads
  runs: Runs
  revokeSelf(): Promise<void>
  freeze(): Promise<void>
}

// Encodings fetch implementations decode on their own while keeping the
// Content-Encoding and Content-Length of the encoded body.
const DECODED_BY_FETCH = new Set(["gzip", "x-gzip", "deflate", "br", "zstd"])

function upstreamHeaders(response: Response): Headers {
  const headers = new Headers(response.headers)
  const encoding = headers.get("content-encoding")?.trim().toLowerCase()
  if (encoding !== undefined && DECODED_BY_FETCH.has(encoding)) {
    headers.delete("content-encoding")
    headers.delete("content-length")
  }
  return headers
}

function idPath(prefix: string, pattern: RegExp, what: string, id: string, suffix = ""): string {
  if (!pattern.test(id)) throw new TypeError(`${JSON.stringify(id)} is not ${what}.`)
  return `${prefix}${encodeURIComponent(id)}${suffix}`
}

function itemPath(slug: string): string {
  if (!Slug.safeParse(slug).success) throw new TypeError(`${JSON.stringify(slug)} is not an item slug.`)
  return `/v1/items/${encodeURIComponent(slug)}`
}

function runPath(id: string, suffix = ""): string {
  return idPath("/v1/runs/", RUN_ID, "a run id (run_...)", id, suffix)
}

function workloadPath(id: string, suffix = ""): string {
  if (!WorkloadIdSchema.safeParse(id).success) throw new TypeError(`${JSON.stringify(id)} is not a workload id (wl_...).`)
  return `/v1/workloads/${encodeURIComponent(id)}${suffix}`
}

export function parsedInput<T>(schema: z.ZodType<T>, value: unknown, what: string): T {
  const parsed = schema.safeParse(value)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    throw new TypeError(`Invalid ${what}${issue ? `: ${issue.path.length > 0 ? `${issue.path.join(".")}: ` : ""}${issue.message}` : ""}.`)
  }
  return parsed.data
}

export function createClient(options: ClientOptions): MehenClient {
  const transport = transportFor(vaultOrigin(options.vaultUrl), options)
  if (options.tenant.length === 0) throw new TypeError("tenant is the workspace id the device was enrolled in.")
  const credentials: Credentials = { tenant: options.tenant, signer: options.signer, ...(options.session ? { session: options.session } : {}) }
  const session = options.session ? { session: options.session } : {}
  const linked = linkedSchemas(transport.origin)

  async function call<T>(method: Method, path: string, body: unknown, schema: z.ZodType<T>, wait = false): Promise<T> {
    const text = body === undefined ? null : JSON.stringify(body)
    const sent = await send(transport, credentials, method, path, text, wait ? { timeoutMs: Math.max(transport.timeoutMs, LONG_POLL_TIMEOUT_MS) } : {})
    return readAnswer(transport, sent, schema)
  }

  const waitQuery = (wait?: WaitOption) => (wait?.wait ? "?wait=1" : "")

  // Checked before anything is sent: exactly one of item and run, and the
  // whole request as the vault parses it.
  function relayRequest(input: RelayInput): RelayRequestInput {
    const item = "item" in input ? input.item : undefined
    const run = "run" in input ? input.run : undefined
    if ((item === undefined) === (run === undefined)) throw new TypeError("A relay names exactly one of item, whose credential it uses, or run, whose placeholders it swaps.")
    if (run !== undefined && !RUN_ID.test(run)) throw new TypeError(`${JSON.stringify(run)} is not a run id (run_...).`)
    const context = "context" in input ? input.context : undefined
    const body = input.body === undefined ? undefined : typeof input.body === "string" ? utf8(input.body) : input.body
    return parsedInput(
      RelayRequest,
      {
        ...(context ? { context } : {}),
        ...(item !== undefined ? { item } : { run }),
        method: input.method.toUpperCase(),
        url: input.url,
        headers: input.headers ?? [],
        ...(body !== undefined && body.length > 0 ? { body: base64UrlEncode(body) } : {}),
        ...session,
        ...(input.approval ? { approval: input.approval } : {}),
      },
      "relay request",
    )
  }

  // The vault's refusal throws MehenRefusal; an answer that is neither a
  // refusal nor the upstream's is a MehenTransport, its body cancelled.
  async function upstreamAnswer(sent: Sent): Promise<Response> {
    const { response } = sent
    if (response.headers.has(ERROR_HEADER)) throw await refusalOf(transport, sent)
    if (!response.headers.has(UPSTREAM_HEADER)) {
      await response.body?.cancel().catch(() => undefined)
      throw new MehenTransport("unexpected", `The vault answered the relay with HTTP ${response.status} but neither ${UPSTREAM_HEADER} nor ${ERROR_HEADER}, so it is not the upstream's answer. Whether the upstream received the request is unknown.`, response.status)
    }
    return response
  }

  // Sends one relay; resolves once the upstream's answer arrives, its body
  // unread. Nothing it resolves with reaches `input` or the request's JSON,
  // so a large body is free to be collected once the headers have arrived.
  async function sendRelay(input: RelayInput, options: SendOptions): Promise<Sent> {
    const sent = await send(transport, credentials, "POST", "/v1/relay", JSON.stringify(relayRequest(input)), options)
    await upstreamAnswer(sent)
    return sent
  }

  async function relayResponse(sent: Sent): Promise<RelayResponse> {
    const { response } = sent
    const bytes = await readBytes(transport, sent)
    return { kind: "response", status: response.status, headers: upstreamHeaders(response), body: bytes, item: response.headers.get(ITEM_HEADER) }
  }

  // Not async: an async relay would hold `input` while the answer is read.
  function relay(input: RelayInput): Promise<RelayResponse> {
    return sendRelay(input, {}).then(relayResponse)
  }

  async function relayStream(input: RelayInput, options: RelayStreamOptions = {}): Promise<RelayStream> {
    const sent = await sendRelay(input, { ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}), ...(options.signal ? { signal: options.signal } : {}) })
    const { response } = sent
    return { kind: "stream", status: response.status, headers: upstreamHeaders(response), body: deadlineBody(transport, sent), item: response.headers.get(ITEM_HEADER) }
  }

  async function pending(): Promise<PendingAsks> {
    const answer = await call("GET", "/v1/pending", undefined, linked.PendingAsks)
    // Notices are advisory and their kinds grow with the vault: ones this
    // client does not know, or that link off the vault, are left out.
    const notices = (answer.notices ?? []).flatMap((value) => {
      const notice = WorkspaceNoticeSchema.safeParse(value)
      const link = notice.success ? vaultLink(transport.origin, notice.data.url) : null
      return notice.success && link !== null ? [{ ...notice.data, url: link }] : []
    })
    return { pending: answer.pending, notices }
  }

  async function createWorkload(input: WorkloadCreateInput): Promise<WorkloadView> {
    const body = parsedInput(WorkloadCreateSchema, { jwk: { kty: input.jwk.kty, crv: input.jwk.crv, x: input.jwk.x, y: input.jwk.y }, label: input.label, ...(input.ttlSeconds !== undefined ? { ttlSeconds: input.ttlSeconds } : {}), scope: input.scope }, "workload")
    const view = await call("POST", "/v1/workloads", body, WorkloadViewSchema)
    if (view.thumbprint !== (await jwkThumbprint(body.jwk))) throw new MehenTransport("unexpected", "The vault's new workload holds a different key from the one this client sent.")
    return view
  }

  return {
    me: async () => call("GET", "/v1/me", undefined, MachineIdentitySchema),
    async items(filter = {}) {
      const url = new URL("/v1/items", transport.origin)
      for (const key of ["tag", "kind", "provider"] as const) {
        const value = filter[key]
        if (value) url.searchParams.set(key, value)
      }
      return (await call("GET", `${url.pathname}${url.search}`, undefined, ItemListSchema)).items
    },
    item: async (slug) => call("GET", itemPath(slug), undefined, WorkspaceItemDescriptionSchema),
    relay,
    relayStream,
    project: async (id) => call("GET", idPath("/v1/projects/", PROJECT_ID, "a project id (prj_...)", id), undefined, MachineProjectSchema),
    approval: async (id, options) => call("GET", idPath("/v1/approvals/", APPROVAL_ID, "an approval id (apr_...)", id, waitQuery(options)), undefined, ApprovalStateSchema, options?.wait === true),
    intake: async (input) => call("POST", "/v1/intakes", parsedInput(WorkspaceIntakeCreate, { ...session, ...input }, "intake"), linked.IntakeCreated),
    intakeStatus: async (id, options) => call("GET", idPath("/v1/intakes/", INTAKE_ID, "an intake id (int_...)", id, waitQuery(options)), undefined, IntakeStatusSchema, options?.wait === true),
    async cancelIntake(id) {
      await call("POST", idPath("/v1/intakes/", INTAKE_ID, "an intake id (int_...)", id, "/cancel"), {}, EmptySchema)
    },
    connect: async (input) => call("POST", "/v1/connect", parsedInput(WorkspaceConnectCreate, { ...session, ...input }, "connect"), linked.ConnectCreated),
    connectStatus: async (id, options) => call("GET", idPath("/v1/connect/", CONNECT_ID, "a connect id (con_...)", id, waitQuery(options)), undefined, ConnectStatusSchema, options?.wait === true),
    async cancelConnect(id) {
      await call("POST", idPath("/v1/connect/", CONNECT_ID, "a connect id (con_...)", id, "/cancel"), {}, EmptySchema)
    },
    pending,
    workloads: {
      create: createWorkload,
      list: async () => (await call("GET", "/v1/workloads", undefined, WorkloadListAnswerSchema)).workloads,
      get: async (id) => call("GET", workloadPath(id), undefined, WorkloadViewSchema),
      renew: async (id, renewal = {}) => call("POST", workloadPath(id, "/renew"), parsedInput(WorkloadRenewSchema, renewal, "workload renewal"), WorkloadViewSchema),
      revoke: async (id) => call("DELETE", workloadPath(id), undefined, WorkloadViewSchema),
    },
    runs: {
      async create(input) {
        const body = parsedInput(RunCreate, { ...session, ...input }, "run")
        if (!PROJECT_ID.test(body.project)) throw new TypeError(`${JSON.stringify(body.project)} is not a project id (prj_...).`)
        return call("POST", "/v1/runs", body, WorkspaceRunCreatedSchema)
      },
      renew: async (id) => call("POST", runPath(id, "/renew"), {}, RunRenewedSchema),
      end: async (id) => call("DELETE", runPath(id), undefined, RunEndedSchema),
    },
    async revokeSelf() {
      await call("POST", "/v1/devices/self/revoke", {}, EmptySchema)
    },
    async freeze() {
      await call("POST", "/v1/freeze", {}, EmptySchema)
    },
  }
}
