// Reviewed route catalogues (catalogue v2): for one service's hosts, the
// writes someone has reviewed, each in an area with the words a page shows,
// and the routes that always reach a person (floor). policy-safety.ts reads
// a request against them (policyCatalogueVerdict): a catalogue floor, a
// floor key in the body or a reader's floor verdict wins over every entry,
// and a destructive entry over a routine one. A catalogue route skips the
// generic and path-word floor checks, so an entry whose path holds a floor
// word must say why it is reviewed (floorWordsReviewed). A catalogue's
// version only grows, and an entry or floor names the version it arrived in
// (since): a task grant or posture covers a routine entry only when it was
// signed at that version or later.

import type { PolicyFloorView, PolicyHttpMethod } from "./policy-mode.ts"
import type { PolicySafetyInput } from "./policy-safety.ts"
import { parseJsonStrictly } from "./body-match.ts"

export type PolicyFloorReason = PolicyFloorView["reason"]
export const POLICY_FLOOR_REASONS = ["credential", "persistence", "send", "money", "sharing", "destructive", "opaque"] as const satisfies readonly PolicyFloorReason[]

// The body readers policy-safety.ts implements (CATALOGUE_READERS), one per
// body shape a catalogue entry names.
export type CatalogueReaderId = "github.issue" | "github.comment" | "cloudflare.dns-record" | "cloudflare.dns-address-record" | "cloudflare.dns-cname-record" | "cloudflare.queue-pull-consumer" | "cloudflare.queue-worker-consumer" | "cloudflare.worker-upload" | "cloudflare.kv-bulk" | "cloudflare.cron-triggers" | "cloudflare.analytics-engine-sql"
// The readers whose body, which is not JSON, a task grant or posture still
// covers (policy-rules.ts routineEntry and postureCovers), as it covers an
// entry's stored bytes (data): each reads the whole body as text it proves
// harmless. Every other reader's entry is covered only when sent as JSON.
export const CATALOGUE_COVERED_TEXT_READERS: ReadonlySet<CatalogueReaderId> = new Set(["cloudflare.analytics-engine-sql"])
// What an entry accepts as its body: none at all; a body the safety checks
// read as one strict JSON object, or none; bytes the API stores, where only
// the method-override and charset scans apply; or a reader's verdict. No
// entry takes a body whose type declares a charset the checks do not read.
export type CatalogueBody = "none" | "json" | "data" | { reader: CatalogueReaderId }
// A reader's answer: the body is this entry's, it is not, or it makes the
// request floor for this reason.
export type CatalogueReaderVerdict = "match" | "no-match" | { floor: PolicyFloorReason }
export type CatalogueReader = (request: PolicySafetyInput) => CatalogueReaderVerdict

export type CatalogueEntry = {
  id: string
  area: string
  effect: "routine" | "destructive"
  methods: PolicyHttpMethod[]
  path: string
  body: CatalogueBody
  // A key found anywhere in a JSON body (any depth, folded) makes the
  // request floor for its reason.
  floorKeys?: Record<string, PolicyFloorReason>
  floorWordsReviewed?: string
  words: string
  since: number
  additionalPermission: boolean
}
// A floor matches on method and path, whatever the body or query: a body
// never narrows a floor (a reader floors through its verdict instead).
export type CatalogueFloor = { id: string; reason: PolicyFloorReason; methods: PolicyHttpMethod[]; path: string; words: string; since: number }
export type CatalogueArea = { id: string; name: string; words: string }
export type PolicyCatalogue = { template: string; version: number; hosts: string[]; areas: CatalogueArea[]; entries: CatalogueEntry[]; floor: CatalogueFloor[] }

// The typed segments a catalogue path may hold. "*" is any one segment;
// "**", only as a floor's last segment, is any number of them, none
// included.
export const CATALOGUE_SEGMENTS: Record<string, RegExp> = {
  "{account}": /^[0-9a-f]{32}$/,
  "{zone}": /^[0-9a-f]{32}$/,
  "{id}": /^(?:[0-9a-f]{32}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})$/,
  "{name}": /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/,
  "{owner}": /^[A-Za-z0-9][A-Za-z0-9-]*$/,
  "{repo}": /^[A-Za-z0-9_.-]+$/,
  "{number}": /^[1-9][0-9]*$/,
  "{v}": /^v[0-9]{1,2}$/,
}

const segmentsOf = (path: string): string[] => (path === "/" ? [] : path.slice(1).split("/"))

// Whether a path is a catalogue path: literal segments, "*" and typed
// segments, and "**" as the last segment when floor.
export function isCataloguePath(path: string, floor = false): boolean {
  if (!path.startsWith("/")) return false
  const segments = segmentsOf(path)
  return segments.every((s, i) => s === "*" || (floor && s === "**" && i === segments.length - 1) || s in CATALOGUE_SEGMENTS || /^[A-Za-z0-9_.~-]+$/.test(s))
}

// Whether a request path matches a catalogue path, segment for segment: a
// literal exactly, "*" any non-empty segment, a typed segment only what its
// pattern allows, and a trailing "**" the rest. A floor is the broad side:
// its literals match in any case and its typed segments as "*" does.
export function cataloguePathMatches(pattern: string, path: string, floor = false): boolean {
  const pat = segmentsOf(pattern)
  const segments = segmentsOf(path)
  for (let i = 0; i < pat.length; i++) {
    const p = pat[i] as string
    if (p === "**") return true
    const s = segments[i]
    if (s === undefined) return false
    const typed = CATALOGUE_SEGMENTS[p]
    if (p === "*" || (floor && typed !== undefined) ? s === "" : typed !== undefined ? !typed.test(s) : floor ? p.toLowerCase() !== s.toLowerCase() : p !== s) return false
  }
  return segments.length === pat.length
}

const issueWords = "Opens, edits, closes and comments on issues in a repository the key reaches"
const GITHUB_CATALOGUE: PolicyCatalogue = {
  template: "github",
  version: 1,
  hosts: ["api.github.com"],
  areas: [{ id: "issues", name: "Issues and comments", words: issueWords }],
  entries: [
    { id: "github.issue-create", area: "issues", effect: "routine", methods: ["POST"], path: "/repos/{owner}/{repo}/issues", body: { reader: "github.issue" }, words: "Opens an issue", since: 1, additionalPermission: true },
    { id: "github.issue-update", area: "issues", effect: "routine", methods: ["PATCH"], path: "/repos/{owner}/{repo}/issues/{number}", body: { reader: "github.issue" }, words: "Edits, closes or reopens an issue", since: 1, additionalPermission: true },
    { id: "github.comment-create", area: "issues", effect: "routine", methods: ["POST"], path: "/repos/{owner}/{repo}/issues/{number}/comments", body: { reader: "github.comment" }, words: "Comments on an issue", since: 1, additionalPermission: true },
    { id: "github.comment-update", area: "issues", effect: "routine", methods: ["PATCH"], path: "/repos/{owner}/{repo}/issues/comments/{number}", body: { reader: "github.comment" }, words: "Edits a comment on an issue", since: 1, additionalPermission: true },
    { id: "github.comment-delete", area: "issues", effect: "destructive", methods: ["DELETE"], path: "/repos/{owner}/{repo}/issues/comments/{number}", body: "none", words: "Deletes a comment on an issue", since: 1, additionalPermission: true },
  ],
  floor: [],
}

const STRIPE_CATALOGUE: PolicyCatalogue = {
  template: "stripe",
  version: 1,
  hosts: ["api.stripe.com"],
  areas: [{ id: "products", name: "Products and prices", words: "Creates and changes products and their prices" }],
  entries: (["products", "prices"] as const).flatMap((name): CatalogueEntry[] => {
    const thing = name === "products" ? "product" : "price"
    return [
      { id: `stripe.${name}-create`, area: "products", effect: "routine", methods: ["POST"], path: `/v1/${name}`, body: "json", words: `Creates a ${thing}`, since: 1, additionalPermission: false },
      { id: `stripe.${name}-update`, area: "products", effect: "routine", methods: ["POST"], path: `/v1/${name}/*`, body: "json", words: `Changes a ${thing}`, since: 1, additionalPermission: false },
    ]
  }),
  floor: [],
}

// Cloudflare (api.cloudflare.com, every path under /client/v4), each path
// checked against https://developers.cloudflare.com/api/. Every DELETE is
// already floor through the template, and minting tokens is denied there.
// A floor holds every write to its path; a floor on a route whose answer
// holds a secret holds its read too, which the template's reads would
// otherwise hand to an agent.
const CF = "/client/v4"
const CF_ACCOUNT = `${CF}/accounts/{account}`
const CF_ZONE = `${CF}/zones/{zone}`
const CF_SCRIPT = `${CF_ACCOUNT}/workers/scripts/{name}`
const CF_KV = `${CF_ACCOUNT}/storage/kv/namespaces`
const CF_R2 = `${CF_ACCOUNT}/r2/buckets`
const CF_D1 = `${CF_ACCOUNT}/d1/database`
const CF_QUEUES = `${CF_ACCOUNT}/queues`
const CF_PAGES = `${CF_ACCOUNT}/pages/projects`
const CF_GATEWAYS = `${CF_ACCOUNT}/ai-gateway/gateways`
const CF_WIDGETS = `${CF_ACCOUNT}/challenges/widgets`
const CF_VECTORIZE = `${CF_ACCOUNT}/vectorize/v2/indexes`
const CF_WORKFLOWS = `${CF_ACCOUNT}/workflows`
const CF_DNS = `${CF_ZONE}/dns_records`
const WRITE_METHODS: PolicyHttpMethod[] = ["POST", "PUT", "PATCH", "DELETE"]
const READ_METHODS: PolicyHttpMethod[] = ["GET", "HEAD"]
// A route whose answer holds a secret, read or written.
const ANSWER_METHODS: PolicyHttpMethod[] = [...READ_METHODS, ...WRITE_METHODS]
const PAGES_ANSWER = "whose answer holds the project's variables' values, secret ones included"
const QUEUE_WORDS = "A message to or from the account's own queue, not a message to a person"
const GATEWAY_KEYS: Record<string, PolicyFloorReason> = { logpush: "persistence", logpush_public_key: "persistence", otel: "persistence", stripe: "credential" }

const cf = (patch: Omit<CatalogueEntry, "since" | "additionalPermission" | "effect"> & Partial<Pick<CatalogueEntry, "effect" | "since">>): CatalogueEntry => ({ effect: "routine", since: 1, additionalPermission: false, ...patch })
const cfFloor = (id: string, reason: PolicyFloorReason, path: string, words: string, methods: PolicyHttpMethod[] = WRITE_METHODS): CatalogueFloor => ({ id: `cloudflare.${id}`, reason, methods, path, words, since: 1 })

const CLOUDFLARE_CATALOGUE: PolicyCatalogue = {
  template: "cloudflare-api-token",
  version: 2,
  hosts: ["api.cloudflare.com"],
  areas: [
    { id: "workers", name: "Workers scripts and deployments", words: "Uploads Workers and their versions, and queries their logs and Analytics Engine data" },
    { id: "routes", name: "Worker routes, domains and schedules", words: "Points routes, domains and schedules at Workers" },
    { id: "kv", name: "KV namespaces and values", words: "Creates KV namespaces and writes and reads their values" },
    { id: "r2", name: "R2 buckets", words: "Creates and changes R2 buckets" },
    { id: "d1", name: "D1 databases", words: "Creates and changes D1 databases, not the data in them" },
    { id: "queues", name: "Queues", words: "Creates queues and consumers, and sends messages to the account's own queues" },
    { id: "pages", name: "Pages custom domains", words: "Points custom domains at Pages projects and checks them again" },
    { id: "ai-gateway", name: "AI Gateway", words: "Creates AI gateways and changes their datasets, evaluations and logs" },
    { id: "vectorize", name: "Vectorize indexes", words: "Creates Vectorize indexes and writes and queries their vectors" },
    { id: "workflows", name: "Workflows", words: "Deploys Workflows and starts and signals their instances" },
    { id: "dns", name: "DNS records", words: "Adds A, AAAA and CNAME records" },
  ],
  entries: [
    cf({ id: "cloudflare.worker-upload", area: "workers", effect: "destructive", methods: ["PUT"], path: CF_SCRIPT, body: { reader: "cloudflare.worker-upload" }, words: "Uploads a Worker, replacing its live code" }),
    cf({ id: "cloudflare.worker-version", area: "workers", methods: ["POST"], path: `${CF_SCRIPT}/versions`, body: { reader: "cloudflare.worker-upload" }, words: "Uploads a version of a Worker" }),
    cf({ id: "cloudflare.worker-telemetry-query", area: "workers", methods: ["POST"], path: `${CF_ACCOUNT}/workers/observability/telemetry/query`, body: "json", words: "Queries Workers logs" }),
    cf({ id: "cloudflare.analytics-engine-sql", area: "workers", methods: ["POST"], path: `${CF_ACCOUNT}/analytics_engine/sql`, body: { reader: "cloudflare.analytics-engine-sql" }, words: "Reads Workers Analytics Engine data with a SQL query", since: 2 }),
    cf({ id: "cloudflare.worker-deploy", area: "workers", effect: "destructive", methods: ["POST"], path: `${CF_SCRIPT}/deployments`, body: "json", words: "Moves a Worker's live traffic to other versions" }),
    cf({ id: "cloudflare.worker-route-create", area: "routes", effect: "destructive", methods: ["POST"], path: `${CF_ZONE}/workers/routes`, body: "json", words: "Points a route at a Worker" }),
    cf({ id: "cloudflare.worker-route-update", area: "routes", effect: "destructive", methods: ["PUT"], path: `${CF_ZONE}/workers/routes/{id}`, body: "json", words: "Repoints a Worker route" }),
    cf({ id: "cloudflare.worker-domain", area: "routes", effect: "destructive", methods: ["PUT"], path: `${CF_ACCOUNT}/workers/domains`, body: "json", words: "Points a custom domain at a Worker" }),
    cf({ id: "cloudflare.worker-subdomain", area: "routes", effect: "destructive", methods: ["POST"], path: `${CF_SCRIPT}/subdomain`, body: "json", words: "Turns a Worker's workers.dev route on or off" }),
    cf({ id: "cloudflare.worker-schedules", area: "routes", effect: "destructive", methods: ["PUT"], path: `${CF_SCRIPT}/schedules`, body: { reader: "cloudflare.cron-triggers" }, words: "Replaces a Worker's cron schedules" }),
    cf({ id: "cloudflare.workers-subdomain", area: "routes", effect: "destructive", methods: ["PUT"], path: `${CF_ACCOUNT}/workers/subdomain`, body: "json", words: "Renames the account's workers.dev subdomain" }),
    cf({ id: "cloudflare.kv-namespace-create", area: "kv", methods: ["POST"], path: CF_KV, body: "json", words: "Creates a KV namespace" }),
    cf({ id: "cloudflare.kv-namespace-rename", area: "kv", methods: ["PUT"], path: `${CF_KV}/{id}`, body: "json", words: "Renames a KV namespace" }),
    cf({ id: "cloudflare.kv-value-write", area: "kv", methods: ["PUT"], path: `${CF_KV}/{id}/values/{name}`, body: "data", words: "Writes a KV value" }),
    cf({ id: "cloudflare.kv-bulk-write", area: "kv", methods: ["PUT"], path: `${CF_KV}/{id}/bulk`, body: { reader: "cloudflare.kv-bulk" }, words: "Writes several KV values" }),
    cf({ id: "cloudflare.kv-bulk-get", area: "kv", methods: ["POST"], path: `${CF_KV}/{id}/bulk/get`, body: "json", words: "Reads several KV values" }),
    cf({ id: "cloudflare.r2-bucket-create", area: "r2", methods: ["POST"], path: CF_R2, body: "json", words: "Creates an R2 bucket" }),
    cf({ id: "cloudflare.r2-bucket-update", area: "r2", methods: ["PATCH"], path: `${CF_R2}/{name}`, body: "json", words: "Changes an R2 bucket's storage class" }),
    cf({ id: "cloudflare.r2-cors", area: "r2", effect: "destructive", methods: ["PUT"], path: `${CF_R2}/{name}/cors`, body: "json", words: "Replaces which sites may read an R2 bucket" }),
    cf({ id: "cloudflare.r2-lock", area: "r2", effect: "destructive", methods: ["PUT"], path: `${CF_R2}/{name}/lock`, body: "json", words: "Replaces an R2 bucket's object locks" }),
    cf({ id: "cloudflare.d1-create", area: "d1", methods: ["POST"], path: CF_D1, body: "json", words: "Creates a D1 database" }),
    cf({ id: "cloudflare.d1-update", area: "d1", methods: ["PUT", "PATCH"], path: `${CF_D1}/{id}`, body: "json", words: "Changes a D1 database's settings" }),
    cf({ id: "cloudflare.queue-create", area: "queues", methods: ["POST"], path: CF_QUEUES, body: "json", words: "Creates a queue" }),
    cf({ id: "cloudflare.queue-update", area: "queues", methods: ["PUT", "PATCH"], path: `${CF_QUEUES}/{id}`, body: "json", words: "Changes a queue" }),
    cf({ id: "cloudflare.queue-consumer-create", area: "queues", methods: ["POST"], path: `${CF_QUEUES}/{id}/consumers`, body: { reader: "cloudflare.queue-pull-consumer" }, words: "Adds a pull consumer to a queue" }),
    cf({ id: "cloudflare.queue-worker-consumer-create", area: "queues", effect: "destructive", methods: ["POST"], path: `${CF_QUEUES}/{id}/consumers`, body: { reader: "cloudflare.queue-worker-consumer" }, words: "Points a queue's messages at a Worker" }),
    cf({ id: "cloudflare.queue-consumer-update", area: "queues", effect: "destructive", methods: ["PUT"], path: `${CF_QUEUES}/{id}/consumers/{id}`, body: "json", words: "Changes a queue's consumer, which can point its messages at another Worker" }),
    cf({ id: "cloudflare.queue-send", area: "queues", methods: ["POST"], path: `${CF_QUEUES}/{id}/messages`, body: "json", floorWordsReviewed: QUEUE_WORDS, words: "Sends a message to a queue" }),
    cf({ id: "cloudflare.queue-send-batch", area: "queues", methods: ["POST"], path: `${CF_QUEUES}/{id}/messages/batch`, body: "json", floorWordsReviewed: QUEUE_WORDS, words: "Sends messages to a queue" }),
    cf({ id: "cloudflare.queue-pull", area: "queues", effect: "destructive", methods: ["POST"], path: `${CF_QUEUES}/{id}/messages/pull`, body: "json", floorWordsReviewed: QUEUE_WORDS, words: "Takes messages off a queue for a while" }),
    cf({ id: "cloudflare.queue-ack", area: "queues", effect: "destructive", methods: ["POST"], path: `${CF_QUEUES}/{id}/messages/ack`, body: "json", floorWordsReviewed: QUEUE_WORDS, words: "Removes or retries messages pulled from a queue" }),
    cf({ id: "cloudflare.pages-domain-update", area: "pages", methods: ["PATCH"], path: `${CF_PAGES}/{name}/domains/{name}`, body: "json", words: "Checks a Pages custom domain again" }),
    cf({ id: "cloudflare.pages-domain-add", area: "pages", effect: "destructive", methods: ["POST"], path: `${CF_PAGES}/{name}/domains`, body: "json", words: "Points a custom domain at a Pages project" }),
    cf({ id: "cloudflare.gateway-create", area: "ai-gateway", methods: ["POST"], path: CF_GATEWAYS, body: "json", floorKeys: GATEWAY_KEYS, words: "Creates an AI gateway" }),
    cf({ id: "cloudflare.gateway-dataset-create", area: "ai-gateway", methods: ["POST"], path: `${CF_GATEWAYS}/{name}/datasets`, body: "json", words: "Creates an AI gateway dataset" }),
    cf({ id: "cloudflare.gateway-dataset-update", area: "ai-gateway", methods: ["PUT"], path: `${CF_GATEWAYS}/{name}/datasets/{name}`, body: "json", words: "Changes an AI gateway dataset" }),
    cf({ id: "cloudflare.gateway-evaluation-create", area: "ai-gateway", methods: ["POST"], path: `${CF_GATEWAYS}/{name}/evaluations`, body: "json", words: "Runs an AI gateway evaluation" }),
    cf({ id: "cloudflare.gateway-log-update", area: "ai-gateway", methods: ["PATCH"], path: `${CF_GATEWAYS}/{name}/logs/{name}`, body: "json", words: "Scores or annotates an AI gateway log" }),
    cf({ id: "cloudflare.vectorize-create", area: "vectorize", methods: ["POST"], path: CF_VECTORIZE, body: "json", words: "Creates a Vectorize index" }),
    cf({ id: "cloudflare.vectorize-insert", area: "vectorize", methods: ["POST"], path: `${CF_VECTORIZE}/{name}/insert`, body: "data", words: "Adds vectors to an index" }),
    cf({ id: "cloudflare.vectorize-upsert", area: "vectorize", methods: ["POST"], path: `${CF_VECTORIZE}/{name}/upsert`, body: "data", words: "Adds or replaces vectors in an index" }),
    cf({ id: "cloudflare.vectorize-query", area: "vectorize", methods: ["POST"], path: `${CF_VECTORIZE}/{name}/query`, body: "json", words: "Queries an index" }),
    cf({ id: "cloudflare.vectorize-get", area: "vectorize", methods: ["POST"], path: `${CF_VECTORIZE}/{name}/get_by_ids`, body: "json", words: "Reads vectors from an index" }),
    cf({ id: "cloudflare.vectorize-metadata-index", area: "vectorize", methods: ["POST"], path: `${CF_VECTORIZE}/{name}/metadata_index/create`, body: "json", words: "Indexes a metadata field" }),
    cf({ id: "cloudflare.workflow-deploy", area: "workflows", effect: "destructive", methods: ["PUT"], path: `${CF_WORKFLOWS}/{name}`, body: "json", words: "Creates or changes a Workflow, which can point it at another script" }),
    cf({ id: "cloudflare.workflow-start", area: "workflows", methods: ["POST"], path: `${CF_WORKFLOWS}/{name}/instances`, body: "json", words: "Starts a Workflow instance" }),
    cf({ id: "cloudflare.workflow-event", area: "workflows", methods: ["POST"], path: `${CF_WORKFLOWS}/{name}/instances/{name}/events/{name}`, body: "json", words: "Sends an event to a Workflow instance" }),
    cf({ id: "cloudflare.workflow-status", area: "workflows", effect: "destructive", methods: ["PATCH"], path: `${CF_WORKFLOWS}/{name}/instances/{name}/status`, body: "json", words: "Pauses, resumes, restarts or ends a Workflow instance" }),
    cf({ id: "cloudflare.dns-record-create", area: "dns", methods: ["POST"], path: CF_DNS, body: { reader: "cloudflare.dns-address-record" }, words: "Adds an A or AAAA record" }),
    cf({ id: "cloudflare.dns-cname-create", area: "dns", effect: "destructive", methods: ["POST"], path: CF_DNS, body: { reader: "cloudflare.dns-cname-record" }, words: "Adds a CNAME record, which can prove a domain or authorise mail" }),
    cf({ id: "cloudflare.dns-record-update", area: "dns", effect: "destructive", methods: ["PUT", "PATCH"], path: `${CF_DNS}/{id}`, body: { reader: "cloudflare.dns-record" }, words: "Repoints an A, AAAA or CNAME record" }),
  ],
  floor: [
    cfFloor("worker-content", "credential", `${CF_SCRIPT}/content`, "Replaces a Worker's code, keeping every binding it has, its secrets included"),
    cfFloor("worker-settings", "persistence", `${CF_SCRIPT}/settings`, "Changes a Worker's bindings, logging or tail consumers"),
    cfFloor("worker-script-settings", "persistence", `${CF_SCRIPT}/script-settings`, "Changes a Worker's logging or tail consumers"),
    cfFloor("worker-secrets", "credential", `${CF_SCRIPT}/secrets/**`, "Sets a Worker's secrets"),
    cfFloor("worker-secrets-bulk", "credential", `${CF_SCRIPT}/secrets-bulk`, "Sets a Worker's secrets"),
    cfFloor("worker-tails", "credential", `${CF_SCRIPT}/tails/**`, "Opens a log stream whose link works without the key"),
    cfFloor("workers-account-settings", "persistence", `${CF_ACCOUNT}/workers/account-settings`, "Changes the account's Workers settings"),
    cfFloor("kv-bulk-delete", "destructive", `${CF_KV}/{id}/bulk/delete`, "Deletes KV values"),
    cfFloor("r2-lifecycle", "destructive", `${CF_R2}/{name}/lifecycle`, "Sets rules that delete a bucket's objects later"),
    cfFloor("r2-domains", "sharing", `${CF_R2}/{name}/domains/**`, "Makes a bucket public on a domain"),
    cfFloor("r2-sippy", "credential", `${CF_R2}/{name}/sippy`, "Gives a bucket another cloud's credentials"),
    cfFloor("event-notifications", "persistence", `${CF_ACCOUNT}/event_notifications/**`, "Sends a bucket's events to a queue"),
    cfFloor("d1-query", "destructive", `${CF_D1}/{id}/query`, "Runs SQL, which can change or drop anything in the database"),
    cfFloor("d1-raw", "destructive", `${CF_D1}/{id}/raw`, "Runs SQL, which can change or drop anything in the database"),
    cfFloor("d1-import", "destructive", `${CF_D1}/{id}/import`, "Imports SQL into a database"),
    cfFloor("d1-restore", "destructive", `${CF_D1}/{id}/time_travel/restore`, "Restores a database to an earlier point"),
    cfFloor("d1-export", "sharing", `${CF_D1}/{id}/export`, "Exports a database to a download link"),
    cfFloor("queue-purge", "destructive", `${CF_QUEUES}/{id}/purge`, "Deletes every message in a queue"),
    cfFloor("pages-project-create", "credential", CF_PAGES, `Lists or creates Pages projects, ${PAGES_ANSWER}`, ANSWER_METHODS),
    cfFloor("pages-project-update", "credential", `${CF_PAGES}/{name}`, `Reads or changes a Pages project, ${PAGES_ANSWER}`, ANSWER_METHODS),
    cfFloor("pages-deploy", "credential", `${CF_PAGES}/{name}/deployments`, `Lists a Pages project's deployments or deploys it, ${PAGES_ANSWER}`, ANSWER_METHODS),
    cfFloor("pages-deployment", "credential", `${CF_PAGES}/{name}/deployments/{id}`, `Reads a Pages deployment, ${PAGES_ANSWER}`, READ_METHODS),
    cfFloor("pages-retry", "credential", `${CF_PAGES}/{name}/deployments/{id}/retry`, `Retries a Pages deployment, ${PAGES_ANSWER}`),
    cfFloor("pages-rollback", "credential", `${CF_PAGES}/{name}/deployments/{id}/rollback`, `Puts an earlier Pages deployment live, ${PAGES_ANSWER}`),
    cfFloor("pages-source", "credential", `${CF_PAGES}/{name}/source`, `Changes a Pages project's repository connection, ${PAGES_ANSWER}`),
    cfFloor("queue-messages-purge", "destructive", `${CF_QUEUES}/{id}/messages/purge`, "Deletes every message in a queue"),
    cfFloor("turnstile-widget-create", "credential", CF_WIDGETS, "Creates a Turnstile widget, whose answer holds its secret"),
    cfFloor("turnstile-widget", "credential", `${CF_WIDGETS}/{name}`, "Reads or changes a Turnstile widget, whose answer holds its secret", ["GET", "HEAD", "PUT"]),
    cfFloor("turnstile-rotate-secret", "credential", `${CF_WIDGETS}/{name}/rotate_secret`, "Rotates a Turnstile widget's secret"),
    cfFloor("vectorize-delete", "destructive", `${CF_VECTORIZE}/{name}/delete_by_ids`, "Deletes vectors"),
    cfFloor("vectorize-metadata-index-delete", "destructive", `${CF_VECTORIZE}/{name}/metadata_index/delete`, "Drops a metadata index"),
    cfFloor("dns-batch", "destructive", `${CF_DNS}/batch`, "Adds, changes and deletes DNS records at once"),
    cfFloor("dns-import", "destructive", `${CF_DNS}/import`, "Imports a zone file"),
    cfFloor("dns-scan-review", "destructive", `${CF_DNS}/scan/review`, "Accepts or rejects scanned DNS records"),
    cfFloor("hyperdrive", "credential", `${CF_ACCOUNT}/hyperdrive/**`, "Changes a Hyperdrive config, which holds a database password"),
    cfFloor("secrets-store", "credential", `${CF_ACCOUNT}/secrets_store/**`, "Changes the account's secrets store"),
    cfFloor("zone-email-routing", "persistence", `${CF_ZONE}/email/routing/**`, "Changes where a zone's email goes"),
    cfFloor("account-email-routing", "persistence", `${CF_ACCOUNT}/email/routing/**`, "Changes where the account's email may go"),
    cfFloor("zone-email-sending", "send", `${CF_ZONE}/email/sending/**`, "Sets up a zone to send email"),
    cfFloor("account-email-sending", "send", `${CF_ACCOUNT}/email/sending/**`, "Sends email"),
    cfFloor("zone-settings", "persistence", `${CF_ZONE}/settings/**`, "Changes a zone's settings"),
    cfFloor("zone-logpush", "persistence", `${CF_ZONE}/logpush/**`, "Sends a zone's logs elsewhere"),
    cfFloor("account-logpush", "persistence", `${CF_ACCOUNT}/logpush/**`, "Sends the account's logs elsewhere"),
    cfFloor("account-access", "sharing", `${CF_ACCOUNT}/access/**`, "Changes who may reach the account's applications"),
    cfFloor("zone-access", "sharing", `${CF_ZONE}/access/**`, "Changes who may reach a zone's applications"),
    cfFloor("tunnels", "sharing", `${CF_ACCOUNT}/cfd_tunnel/**`, "Changes a tunnel into a private network"),
    cfFloor("tunnel-token", "credential", `${CF_ACCOUNT}/cfd_tunnel/{id}/token`, "Reads the token that runs a tunnel", ["GET", "HEAD"]),
    // Routes whose documented answer holds a secret, each checked on its
    // page under https://developers.cloudflare.com/api/resources/ and in
    // Cloudflare's OpenAPI schema (x-sensitive). The PR body lists each.
    cfFloor("worker-assets-session", "credential", `${CF_SCRIPT}/assets-upload-session`, "Starts uploading a Worker's static assets, whose answer is an upload token"),
    cfFloor("dispatch-assets-session", "credential", `${CF_ACCOUNT}/workers/dispatch/namespaces/{name}/scripts/{name}/assets-upload-session`, "Starts uploading a dispatched Worker's static assets, whose answer is an upload token"),
    cfFloor("workers-assets-upload", "credential", `${CF_ACCOUNT}/workers/assets/upload`, "Uploads static assets, whose answer is a completion token"),
    cfFloor("worker-versions", "credential", `${CF_ACCOUNT}/workers/workers/{name}/versions/**`, "Reads or makes a Worker's versions, whose answer holds the assets completion token", ANSWER_METHODS),
    cfFloor("worker-previews", "credential", `${CF_ACCOUNT}/workers/workers/{name}/previews/{name}/deployments/**`, "Reads or makes a Worker preview's deployments, whose answer holds the assets completion token", ANSWER_METHODS),
    cfFloor("gateways", "credential", CF_GATEWAYS, "Lists the AI gateways, whose answer holds each gateway's stored authorisation", READ_METHODS),
    cfFloor("gateway", "credential", `${CF_GATEWAYS}/{name}`, "Reads or changes an AI gateway, whose answer holds its stored authorisation", ["GET", "HEAD", "PUT"]),
    cfFloor("gateway-custom-providers", "credential", `${CF_ACCOUNT}/ai-gateway/custom-providers/**`, "Reads or changes AI gateway custom providers, whose answer holds the headers sent to them", ANSWER_METHODS),
    cfFloor("gateway-billing", "credential", `${CF_ACCOUNT}/ai-gateway/billing/**`, "Tops up AI gateway credit, whose answer holds a payment secret"),
    cfFloor("pages-upload-token", "credential", `${CF_PAGES}/{name}/upload-token`, "Reads a Pages project's upload token", READ_METHODS),
    cfFloor("workflow-subscribe-token", "credential", `${CF_WORKFLOWS}/{name}/instances/{name}/subscribe/token`, "Reads a token to a Workflow instance's events", READ_METHODS),
    cfFloor("warp-connector-token", "credential", `${CF_ACCOUNT}/warp_connector/{id}/token`, "Reads the token that runs a WARP connector", READ_METHODS),
    cfFloor("tunnel-management-token", "credential", `${CF_ACCOUNT}/cfd_tunnel/{id}/management`, "Makes a token to manage a tunnel"),
    cfFloor("account-logpush-jobs", "credential", `${CF_ACCOUNT}/logpush/jobs/**`, "Reads or changes the account's Logpush jobs, whose destinations hold keys", ANSWER_METHODS),
    cfFloor("account-logpush-dataset-jobs", "credential", `${CF_ACCOUNT}/logpush/datasets/{name}/jobs`, "Lists a dataset's Logpush jobs, whose destinations hold keys", READ_METHODS),
    cfFloor("zone-logpush-jobs", "credential", `${CF_ZONE}/logpush/jobs/**`, "Reads or changes a zone's Logpush jobs, whose destinations hold keys", ANSWER_METHODS),
    cfFloor("zone-logpush-dataset-jobs", "credential", `${CF_ZONE}/logpush/datasets/{name}/jobs`, "Lists a dataset's Logpush jobs, whose destinations hold keys", READ_METHODS),
    cfFloor("zone-logpush-edge-jobs", "credential", `${CF_ZONE}/logpush/edge/jobs`, "Lists a zone's Instant Logs jobs, whose destinations hold keys", READ_METHODS),
    cfFloor("stream-live-inputs", "credential", `${CF_ACCOUNT}/stream/live_inputs`, "Creates a Stream live input, whose answer holds its stream keys"),
    cfFloor("stream-live-input", "credential", `${CF_ACCOUNT}/stream/live_inputs/{id}/**`, "Reads or changes a Stream live input or its outputs, whose answer holds their stream keys", ANSWER_METHODS),
    cfFloor("stream-webhook", "credential", `${CF_ACCOUNT}/stream/webhook`, "Reads or sets the Stream webhook, whose answer holds its signing secret", ANSWER_METHODS),
    cfFloor("stream-keys", "credential", `${CF_ACCOUNT}/stream/keys`, "Makes a Stream signing key"),
    cfFloor("stream-token", "credential", `${CF_ACCOUNT}/stream/{id}/token`, "Makes a signed Stream video token"),
    cfFloor("tsigs", "credential", `${CF_ACCOUNT}/secondary_dns/tsigs/**`, "Reads or changes TSIG keys, whose answer holds their secret", ANSWER_METHODS),
    cfFloor("account-access-apps", "credential", `${CF_ACCOUNT}/access/apps`, "Lists or adds Access applications, whose answer holds their client secrets", ANSWER_METHODS),
    cfFloor("account-access-app", "credential", `${CF_ACCOUNT}/access/apps/{id}`, "Reads or changes an Access application, whose answer holds its client secrets", ANSWER_METHODS),
    cfFloor("account-identity-providers", "credential", `${CF_ACCOUNT}/access/identity_providers`, "Lists or adds identity providers, whose answer holds their client and SCIM secrets", ANSWER_METHODS),
    cfFloor("account-identity-provider", "credential", `${CF_ACCOUNT}/access/identity_providers/{id}`, "Reads or changes an identity provider, whose answer holds its client and SCIM secrets", ANSWER_METHODS),
    cfFloor("account-service-tokens", "credential", `${CF_ACCOUNT}/access/service_tokens`, "Makes an Access service token, whose answer holds its client secret"),
    cfFloor("account-service-token-rotate", "credential", `${CF_ACCOUNT}/access/service_tokens/{id}/rotate`, "Rotates an Access service token, whose answer holds its new client secret"),
    cfFloor("zone-access-apps", "credential", `${CF_ZONE}/access/apps`, "Lists or adds a zone's Access applications, whose answer holds their client secrets", ANSWER_METHODS),
    cfFloor("zone-access-app", "credential", `${CF_ZONE}/access/apps/{id}`, "Reads or changes a zone's Access application, whose answer holds its client secrets", ANSWER_METHODS),
    cfFloor("zone-identity-providers", "credential", `${CF_ZONE}/access/identity_providers`, "Lists or adds a zone's identity providers, whose answer holds their client and SCIM secrets", ANSWER_METHODS),
    cfFloor("zone-identity-provider", "credential", `${CF_ZONE}/access/identity_providers/{id}`, "Reads or changes a zone's identity provider, whose answer holds its client and SCIM secrets", ANSWER_METHODS),
    cfFloor("zone-service-tokens", "credential", `${CF_ZONE}/access/service_tokens`, "Makes a zone's Access service token, whose answer holds its client secret"),
    cfFloor("oauth-clients", "credential", `${CF_ACCOUNT}/oauth_clients/**`, "Makes an OAuth client or rotates its secret, whose answer holds the secret"),
    cfFloor("moq-relays", "credential", `${CF_ACCOUNT}/moq/relays/**`, "Makes a media relay or its tokens, whose answer holds the token once"),
    cfFloor("calls", "credential", `${CF_ACCOUNT}/calls/**`, "Makes a Realtime app or TURN key, whose answer holds its bearer token"),
    cfFloor("realtime-livestreams", "credential", `${CF_ACCOUNT}/realtime/kit/{name}/livestreams/**`, "Reads RealtimeKit livestreams, whose answer holds their stream keys", READ_METHODS),
    cfFloor("realtime-meeting-livestream", "credential", `${CF_ACCOUNT}/realtime/kit/{name}/meetings/{id}/livestream`, "Reads a RealtimeKit meeting's livestream, whose answer holds its stream key", READ_METHODS),
    cfFloor("realtime-meeting-active-livestream", "credential", `${CF_ACCOUNT}/realtime/kit/{name}/meetings/{id}/active-livestream`, "Reads a RealtimeKit meeting's active livestream, whose answer holds its stream key", READ_METHODS),
    cfFloor("realtime-meeting-livestreams", "credential", `${CF_ACCOUNT}/realtime/kit/{name}/meetings/{id}/livestreams`, "Starts a RealtimeKit livestream, whose answer holds its stream key"),
    cfFloor("realtime-participants", "credential", `${CF_ACCOUNT}/realtime/kit/{name}/meetings/{id}/participants/**`, "Adds or changes a RealtimeKit participant, whose answer holds their join token"),
    cfFloor("container-registry-credentials", "credential", `${CF_ACCOUNT}/containers/registries/{name}/credentials`, "Makes image registry credentials"),
    cfFloor("device-override-codes", "credential", `${CF_ACCOUNT}/devices/override_codes`, "Makes a device uninstall override code"),
    cfFloor("device-override-code", "credential", `${CF_ACCOUNT}/devices/{id}/override_codes`, "Reads a device's uninstall override code", READ_METHODS),
    cfFloor("registration-override-code", "credential", `${CF_ACCOUNT}/devices/registrations/{id}/override_codes`, "Reads a registration's uninstall override code", READ_METHODS),
    cfFloor("dlp-datasets", "credential", `${CF_ACCOUNT}/dlp/datasets/**`, "Makes or uploads a DLP dataset, whose answer holds its Exact Data Match secret"),
    cfFloor("ipsec-psk-generate", "credential", `${CF_ACCOUNT}/magic/ipsec_tunnels/{id}/psk_generate`, "Makes an IPsec tunnel's pre-shared key"),
    cfFloor("ipsec-psks", "credential", `${CF_ACCOUNT}/magic/ipsec_tunnels/psk`, "Sets IPsec tunnels' pre-shared keys, whose answer holds them"),
    cfFloor("vulnerability-discovery-repos", "credential", `${CF_ACCOUNT}/managed-defense/vulnerability-discovery/repos/**`, "Adds a repository to vulnerability discovery or makes its token"),
    cfFloor("vpc-flows-token", "credential", `${CF_ACCOUNT}/mnm/vpc-flows/token`, "Makes a VPC flows export token"),
    cfFloor("pipeline-sinks", "credential", `${CF_ACCOUNT}/pipelines/v1/sinks/**`, "Makes or changes a pipeline sink, whose answer holds its bucket credentials"),
    cfFloor("r2-temp-credentials", "credential", `${CF_ACCOUNT}/r2/temp-access-credentials`, "Makes temporary R2 credentials"),
    cfFloor("artifacts-repos", "credential", `${CF_ACCOUNT}/artifacts/namespaces/{name}/repos/**`, "Makes, forks or imports an Artifacts repository, whose answer holds its token"),
    cfFloor("pagerduty-connect", "credential", `${CF_ACCOUNT}/alerting/v3/destinations/pagerduty/**`, "Connects PagerDuty, whose answer is a connection token"),
    cfFloor("alert-unsubscribe", "credential", `${CF_ACCOUNT}/alerting/v3/policies/{id}/email/unsubscribe`, "Reads or uses a notification policy's unsubscribe token", ANSWER_METHODS),
    cfFloor("images-keys", "credential", `${CF_ACCOUNT}/images/v1/keys/**`, "Reads or changes the Images signing keys", ANSWER_METHODS),
    cfFloor("custom-hostnames", "credential", `${CF_ZONE}/custom_hostnames/**`, "Reads or changes custom hostnames, whose answer holds an uploaded certificate's key", ANSWER_METHODS),
    cfFloor("origin-tls-client-auth", "credential", `${CF_ZONE}/origin_tls_client_auth/**`, "Reads or changes origin client certificates, whose answer holds their private key", ANSWER_METHODS),
    cfFloor("zaraz", "credential", `${CF_ZONE}/settings/zaraz/**`, "Reads or changes Zaraz settings, whose answer holds its secret variables", ANSWER_METHODS),
  ],
}

export const POLICY_CATALOGUES: readonly PolicyCatalogue[] = [GITHUB_CATALOGUE, STRIPE_CATALOGUE, CLOUDFLARE_CATALOGUE]

// Vercel and Neon in outline: their areas, entries and floors as the design
// sets them out, waiting on a review of each path and body against the
// provider's reference. They are not in POLICY_CATALOGUES, so nothing reads
// them: no request is classified, floored or skips a check by them, and
// policyCatalogueNamed finds neither, so no task grant or posture can be
// made or cover a request from them. Moving one into POLICY_CATALOGUES is
// the review landing.
const outline = (id: string, area: string, effect: CatalogueEntry["effect"], methods: PolicyHttpMethod[], path: string, words: string, floorKeys?: Record<string, PolicyFloorReason>): CatalogueEntry =>
  ({ id, area, effect, methods, path, body: "json", ...(floorKeys === undefined ? {} : { floorKeys }), words, since: 1, additionalPermission: false })

const VERCEL_OUTLINE: PolicyCatalogue = {
  template: "vercel",
  version: 1,
  hosts: ["api.vercel.com"],
  areas: [
    { id: "deployments", name: "Deployments", words: "Creates deployments" },
    { id: "projects", name: "Projects", words: "Creates and changes projects" },
    { id: "domains", name: "Domains", words: "Adds domains to projects" },
    { id: "edge-config", name: "Edge Config", words: "Creates and changes Edge Config stores and their items" },
  ],
  entries: [
    outline("vercel.deployment-create", "deployments", "routine", ["POST"], "/{v}/deployments", "Creates a deployment", { env: "credential", build: "credential" }),
    outline("vercel.project-create", "projects", "routine", ["POST"], "/{v}/projects", "Creates a project", { environmentVariables: "credential", gitRepository: "persistence" }),
    outline("vercel.project-update", "projects", "routine", ["PATCH"], "/{v}/projects/{name}", "Changes a project", { environmentVariables: "credential", gitRepository: "persistence" }),
    outline("vercel.domain-add", "domains", "destructive", ["POST"], "/{v}/domains", "Adds a domain to the team"),
    outline("vercel.project-domain-add", "domains", "destructive", ["POST"], "/{v}/projects/{name}/domains", "Points a domain at a project"),
    outline("vercel.edge-config-create", "edge-config", "routine", ["POST"], "/{v}/edge-config", "Creates an Edge Config store"),
    outline("vercel.edge-config-update", "edge-config", "routine", ["PUT"], "/{v}/edge-config/{name}", "Renames an Edge Config store"),
    outline("vercel.edge-config-items", "edge-config", "routine", ["PATCH"], "/{v}/edge-config/{name}/items", "Changes an Edge Config store's items"),
  ],
  floor: [],
}

const NEON = "/api/v2/projects"
const NEON_OUTLINE: PolicyCatalogue = {
  template: "neon",
  version: 1,
  hosts: ["console.neon.tech"],
  areas: [
    { id: "branches", name: "Branches", words: "Creates and changes branches" },
    { id: "computes", name: "Computes", words: "Creates, changes, starts and stops computes" },
    { id: "databases", name: "Databases", words: "Creates and changes databases" },
  ],
  entries: [
    outline("neon.branch-create", "branches", "routine", ["POST"], `${NEON}/{name}/branches`, "Creates a branch", { endpoints: "credential" }),
    outline("neon.branch-update", "branches", "routine", ["PATCH"], `${NEON}/{name}/branches/{name}`, "Renames or protects a branch"),
    outline("neon.compute-create", "computes", "routine", ["POST"], `${NEON}/{name}/endpoints`, "Creates a compute"),
    outline("neon.compute-update", "computes", "routine", ["PATCH"], `${NEON}/{name}/endpoints/{name}`, "Changes a compute"),
    ...(["start", "suspend", "restart"] as const).map((act) => outline(`neon.compute-${act}`, "computes", "destructive", ["POST"], `${NEON}/{name}/endpoints/{name}/${act}`, `${act === "start" ? "Starts" : act === "suspend" ? "Suspends" : "Restarts"} a compute`)),
    outline("neon.database-create", "databases", "routine", ["POST"], `${NEON}/{name}/branches/{name}/databases`, "Creates a database"),
    outline("neon.database-update", "databases", "routine", ["PATCH"], `${NEON}/{name}/branches/{name}/databases/{name}`, "Renames a database or changes its owner"),
  ],
  floor: [
    { id: "neon.branch-restore", reason: "destructive", methods: ["POST"], path: `${NEON}/{name}/branches/{name}/restore`, words: "Restores a branch to an earlier point", since: 1 },
    { id: "neon.roles", reason: "credential", methods: ["POST", "PUT", "PATCH", "DELETE"], path: `${NEON}/{name}/branches/{name}/roles/**`, words: "Creates a role or resets its password, which the answer holds", since: 1 },
    { id: "neon.project-create", reason: "credential", methods: ["POST"], path: NEON, words: "Creates a project, whose answer holds its owner's password", since: 1 },
  ],
}

export const POLICY_CATALOGUE_OUTLINES: readonly PolicyCatalogue[] = [VERCEL_OUTLINE, NEON_OUTLINE]

// The catalogue for a host, or null when nobody has reviewed its routes.
export function policyCatalogueFor(host: string): PolicyCatalogue | null {
  return POLICY_CATALOGUES.find((c) => c.hosts.includes(host)) ?? null
}

export function policyCatalogueNamed(template: string): PolicyCatalogue | null {
  return POLICY_CATALOGUES.find((c) => c.template === template) ?? null
}

// The floor reason a catalogue reason id gives (policyCatalogueVerdict's
// floor ids): a catalogue floor's own id, or an entry's id and the reason
// its floor key or reader gave, joined by ":".
export function catalogueFloorReason(id: string): PolicyFloorReason | null {
  for (const catalogue of POLICY_CATALOGUES) {
    const floor = catalogue.floor.find((f) => f.id === id)
    if (floor !== undefined) return floor.reason
    const entry = catalogue.entries.find((e) => id.startsWith(`${e.id}:`))
    if (entry !== undefined) return (POLICY_FLOOR_REASONS as readonly string[]).find((r) => r === id.slice(entry.id.length + 1)) as PolicyFloorReason | undefined ?? null
  }
  return null
}

// Each character lower-cased then upper-cased, so a key folds at least as
// broadly as Go's encoding/json matches a field (unicode.ToUpper of
// unicode.ToLower, which reads "env_var\u017f" as "env_vars" and the
// Kelvin sign as "k"). Folding wider only adds floor. U+0130 (capital I
// with dot above) is the one character this would fold more narrowly than
// Go: Go lower-cases it to "i", JavaScript to "i" and U+0307, so it is
// read as "I" here, and "b\u0130ndings" still reaches "bindings".
export const foldedKey = (key: string): string => Array.from(key, (c) => (c === "\u0130" ? "I" : c.toLowerCase().toUpperCase())).join("")

const CATALOGUE_FLOOR_KEY_BODY_MAX = 64 * 1024

// reasons: those of an entry's floor keys found in a body read as strict
// JSON (a byte order mark skipped), every key at every depth, compared
// folded (foldedKey), walked without recursion so no depth can throw; none
// when the body is not JSON. readable: there is no body, or it is one
// strict JSON document in UTF-8 with no byte order mark and at most 64 KiB.
// An entry with floor keys matches only a readable body, so a body whose
// keys a parser could read differently never makes a request routine.
export type CatalogueFloorKeys = { reasons: PolicyFloorReason[]; readable: boolean }

export function catalogueFloorKeys(floorKeys: Record<string, PolicyFloorReason> | undefined, body: Uint8Array | null | undefined): CatalogueFloorKeys {
  if (floorKeys === undefined || body === null || body === undefined) return { reasons: [], readable: true }
  let text: string
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body) } catch { return { reasons: [], readable: false } }
  const marked = text.startsWith("\ufeff")
  const parsed = parseJsonStrictly(marked ? text.slice(1) : text)
  if (!parsed.ok) return { reasons: [], readable: false }
  const wanted = new Map(Object.entries(floorKeys).map(([key, reason]) => [foldedKey(key), reason]))
  const found = new Set<PolicyFloorReason>()
  const pending: unknown[] = [parsed.value]
  while (pending.length > 0) {
    const value = pending.pop()
    if (Array.isArray(value)) for (const inner of value) pending.push(inner)
    else if (typeof value === "object" && value !== null) {
      for (const [key, inner] of Object.entries(value)) {
        const reason = wanted.get(foldedKey(key))
        if (reason !== undefined) found.add(reason)
        pending.push(inner)
      }
    }
  }
  return { reasons: [...found], readable: !marked && body.length <= CATALOGUE_FLOOR_KEY_BODY_MAX }
}
