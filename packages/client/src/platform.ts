// A signed client for a platform: a business the operator registered, which
// signs every call with its own P-256 key (a Mehen-Platform-Proof) and acts
// in its subjects' managed workspaces only through /v1/platform. Every call
// is made from the protocol's route table, PLATFORM_ROUTES: the path's
// parameters, the query and the body are checked with the row's schemas
// before anything is signed, and the answer is parsed with the row's.

import type { z } from "zod"
import type { ConnectStatus, ItemSummary } from "@mehen/protocol/api"
import {
  PLATFORM_ID,
  PLATFORM_KEY_ID,
  PLATFORM_PROOF_HEADER,
  type ItemRemoval,
  type PlatformApprovalDecide,
  type PlatformApprovalStatusSchema,
  type PlatformApprovalView,
  type PlatformConnectFinish,
  type PlatformConnectFinished,
  type PlatformConnectStart,
  type PlatformConnectStarted,
  type PlatformDefaults,
  type PlatformDefaultsView,
  type PlatformDeviceCreate,
  type PlatformDeviceListEntry,
  type PlatformDeviceView,
  type PlatformIntake,
  type PlatformIntakeCreate,
  type PlatformIntakeSubmit,
  type PlatformItemFilter,
  type PlatformProjectCreate,
  type PlatformProjectView,
  type PlatformRoute,
  type PlatformRouteName,
  type PlatformSigner,
  type PlatformVarSet,
  type PlatformView,
  type SubjectList,
  type SubjectRemoval,
  type SubjectView,
  type SubjectsRemoval,
  PlatformSubjectSchema,
  createPlatformProof,
  platformRoute,
  webCryptoPlatformSigner,
} from "@mehen/protocol/platform"
import type { WorkspaceAuditPage } from "@mehen/protocol/workspace"
import { parsedInput } from "./client.ts"
import { vaultOrigin } from "./origin.ts"
import { type RequestProver, type TransportOptions, readAnswer, sendProved, transportFor } from "./transport.ts"

export type PlatformClientOptions = TransportOptions & {
  vaultUrl: string
  signer: PlatformSigner
}

export type PlatformApprovalStatus = z.infer<typeof PlatformApprovalStatusSchema>

export type PlatformAuditOptions = { cursor?: string; limit?: number }

// Everything the platform does in one subject's managed workspace. The
// subject is checked when the client is made; every call's proof names it.
export type SubjectClient = {
  readonly subject: string
  devices: {
    // A device for one agent, which relays and serves placeholders only,
    // through workloads. The same key again answers the existing device.
    create(input: PlatformDeviceCreate): Promise<PlatformDeviceView>
    list(): Promise<PlatformDeviceListEntry[]>
    // Idempotent: its workloads, asks and runs end with it.
    revoke(device: string): Promise<PlatformDeviceView>
  }
  items: {
    // Mehen's metadata only, never a value.
    list(filter?: PlatformItemFilter): Promise<ItemSummary[]>
    remove(slug: string): Promise<ItemRemoval>
  }
  intakes: {
    // The seal key and the fields for the platform's page: seal each
    // secret in the browser with @mehen/client/seal's sealFields.
    create(input: PlatformIntakeCreate): Promise<PlatformIntake>
    submit(intake: string, input: PlatformIntakeSubmit): Promise<ItemSummary>
    cancel(intake: string): Promise<void>
  }
  // OAuth with the subject's own app: an oauth-client item in their
  // workspace, added through an intake like any key.
  connects: {
    // The provider's authorisation URL to send the person to, with the
    // platform's own callback as its redirect URI.
    start(input: PlatformConnectStart): Promise<PlatformConnectStarted>
    // What the platform's callback received: the state, and the code or
    // the provider's error.
    finish(input: PlatformConnectFinish): Promise<PlatformConnectFinished>
    status(connect: string): Promise<ConnectStatus>
    cancel(connect: string): Promise<void>
  }
  approvals: {
    list(filter?: { status?: PlatformApprovalStatus }): Promise<PlatformApprovalView[]>
    get(approval: string): Promise<PlatformApprovalView>
    // One use of that exact request; `digest` must be the approval's own.
    decide(approval: string, input: PlatformApprovalDecide): Promise<PlatformApprovalView>
  }
  projects: {
    // The same slug again, with the same environments and default, answers
    // the existing project; any other shape under that slug is a conflict.
    create(input: PlatformProjectCreate): Promise<PlatformProjectView>
    get(project: string): Promise<PlatformProjectView>
    // `before` is the value last read; a stale one is refused `conflict`.
    setVar(project: string, name: string, input: PlatformVarSet): Promise<PlatformProjectView>
    remove(project: string): Promise<void>
  }
  audit(options?: PlatformAuditOptions): Promise<WorkspaceAuditPage>
  freeze(): Promise<void>
  unfreeze(): Promise<void>
}

export type PlatformClient = {
  view(): Promise<PlatformView>
  defaults: {
    // Read from the platform's view (GET /v1/platform).
    get(): Promise<PlatformDefaultsView>
    put(defaults: PlatformDefaults): Promise<PlatformDefaultsView>
  }
  subjects: {
    // 201 or 200 alike: the subject's managed workspace exists afterwards.
    ensure(subject: string): Promise<SubjectView>
    get(subject: string): Promise<SubjectView>
    list(cursor?: string): Promise<SubjectList>
    remove(subject: string): Promise<SubjectRemoval>
    // `confirmSlug` is the platform's own slug.
    removeAll(confirmSlug: string): Promise<SubjectsRemoval>
  }
  subject(subject: string): SubjectClient
}

// A software signer over a WebCrypto P-256 key, with its ids checked: a
// platform's own server. Any other PlatformSigner (a KMS, an HSM) works
// the same way.
export function platformSigner(platformId: string, keyId: string, privateKey: CryptoKey): PlatformSigner {
  checkSignerIds(platformId, keyId)
  return webCryptoPlatformSigner(platformId, keyId, privateKey)
}

function checkSignerIds(platformId: string, keyId: string): void {
  if (!PLATFORM_ID.test(platformId)) throw new TypeError(`${JSON.stringify(platformId)} is not a platform id (plt_...).`)
  if (!PLATFORM_KEY_ID.test(keyId)) throw new TypeError(`${JSON.stringify(keyId)} is not a platform key id (pky_...).`)
}

type RouteNamed<N extends PlatformRouteName> = ReturnType<typeof platformRoute<N>>
type AnswerOf<N extends PlatformRouteName> = z.output<RouteNamed<N>["answer"]>

type CallInput = {
  params?: Record<string, string>
  query?: Record<string, string | number | undefined>
  body?: unknown
}

// The row's path with each :param checked by the row's schema and encoded.
function routePath(route: PlatformRoute, params: Record<string, string>): string {
  return route.path.replaceAll(/:([A-Za-z]+)/g, (_, name: string) => {
    const schema = route.params[name]
    const value = params[name]
    if (schema === undefined || value === undefined) throw new TypeError(`${route.name} needs ${name}.`)
    if (!schema.safeParse(value).success) throw new TypeError(`${JSON.stringify(value)} is not a valid ${name} for ${route.name}.`)
    return encodeURIComponent(value)
  })
}

function routeQuery(route: PlatformRoute, query: Record<string, string | number | undefined>): string {
  if (route.query === null) return ""
  parsedInput(route.query, query, `${route.name} query`)
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) search.set(key, String(value))
  }
  const text = search.toString()
  return text === "" ? "" : `?${text}`
}

export function createPlatformClient(options: PlatformClientOptions): PlatformClient {
  const transport = transportFor(vaultOrigin(options.vaultUrl), options)
  const { signer } = options
  checkSignerIds(signer.platformId, signer.keyId)
  const prove: RequestProver = async (request) => ({ header: PLATFORM_PROOF_HEADER, proof: await createPlatformProof(signer, request) })

  async function call<N extends PlatformRouteName>(name: N, input: CallInput = {}): Promise<AnswerOf<N>> {
    const route: PlatformRoute = platformRoute(name)
    const path = `${routePath(route, input.params ?? {})}${routeQuery(route, input.query ?? {})}`
    const body = route.body === null ? null : JSON.stringify(parsedInput(route.body, input.body ?? {}, route.name))
    const sent = await sendProved(transport, prove, route.method, path, body)
    return readAnswer(transport, sent, route.answer as z.ZodType<AnswerOf<N>>)
  }

  function subjectClient(subject: string): SubjectClient {
    if (!PlatformSubjectSchema.safeParse(subject).success) throw new TypeError(`${JSON.stringify(subject)} is not a subject: 8 to 128 letters, digits, - or _.`)
    const params = (extra: Record<string, string> = {}) => ({ subject, ...extra })
    return {
      subject,
      devices: {
        create: async (input) => call("devices.create", { params: params(), body: input }),
        list: async () => (await call("devices.list", { params: params() })).devices,
        revoke: async (device) => call("devices.revoke", { params: params({ device }) }),
      },
      items: {
        list: async (filter = {}) => (await call("items.list", { params: params(), query: { kind: filter.kind, tag: filter.tag } })).items,
        remove: async (slug) => call("items.remove", { params: params({ slug }) }),
      },
      intakes: {
        create: async (input) => call("intakes.create", { params: params(), body: input }),
        submit: async (intake, input) => (await call("intakes.submit", { params: params({ intake }), body: input })).item,
        async cancel(intake) {
          await call("intakes.cancel", { params: params({ intake }) })
        },
      },
      connects: {
        start: async (input) => call("connects.start", { params: params(), body: input }),
        finish: async (input) => call("connects.finish", { params: params(), body: input }),
        status: async (connect) => call("connects.get", { params: params({ connect }) }),
        async cancel(connect) {
          await call("connects.cancel", { params: params({ connect }) })
        },
      },
      approvals: {
        list: async (filter = {}) => (await call("approvals.list", { params: params(), query: { status: filter.status } })).approvals,
        get: async (approval) => call("approvals.get", { params: params({ approval }) }),
        decide: async (approval, input) => call("approvals.decide", { params: params({ approval }), body: input }),
      },
      projects: {
        create: async (input) => call("projects.create", { params: params(), body: input }),
        get: async (project) => call("projects.get", { params: params({ project }) }),
        setVar: async (project, name, input) => call("projects.setVar", { params: params({ project, name }), body: input }),
        async remove(project) {
          await call("projects.remove", { params: params({ project }) })
        },
      },
      audit: async (audit = {}) => call("audit.read", { params: params(), query: { cursor: audit.cursor, limit: audit.limit } }),
      async freeze() {
        await call("workspace.freeze", { params: params() })
      },
      async unfreeze() {
        await call("workspace.unfreeze", { params: params() })
      },
    }
  }

  return {
    view: async () => call("platform.view"),
    defaults: {
      async get() {
        const view = await call("platform.view")
        return { defaults: view.defaults, defaultsRevision: view.defaultsRevision }
      },
      put: async (defaults) => call("defaults.put", { body: defaults }),
    },
    subjects: {
      ensure: async (subject) => call("subjects.ensure", { params: { subject } }),
      get: async (subject) => call("subjects.get", { params: { subject } }),
      list: async (cursor) => call("subjects.list", { query: { cursor } }),
      remove: async (subject) => call("subjects.remove", { params: { subject } }),
      removeAll: async (confirmSlug) => call("subjects.removeAll", { body: { confirm: confirmSlug } }),
    },
    subject: subjectClient,
  }
}
