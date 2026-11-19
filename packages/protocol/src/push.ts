// Where the vault may put a stored secret: one secret in one provider's
// secret store. The CLI reads the grammar below and sends the JSON; MCP
// and the vault take only the JSON, which must already be canonical, so a
// destination has exactly one spelling everywhere: in the approval digest,
// on the card and in the push records.
//
//   github:<owner>/<repo>/<NAME>                      Actions repository secret
//   github:<owner>/<repo>/env/<environment>/<NAME>    Actions environment secret
//   github:<owner>/<repo>/dependabot/<NAME>           Dependabot secret
//   vercel:<project>[@<team>]/<target>/<NAME>         Vercel variable for one target
//   cloudflare:<account>/<script>/<NAME>              Worker secret
//   fly:<app>/<NAME>                                  Fly app secret
//
// ASCII only, checked before any case folding (non-ASCII letters such as
// the long s or the Kelvin sign fold into ASCII ones), so a deceptive
// character can never reach a destination. Segment counts make every form
// unambiguous; a segment of dots alone is refused, since a URL parser
// would read it as a step up the path.

import { z } from "zod"

export type PushDestination =
  | { provider: "github"; owner: string; repo: string; store: "actions" | "dependabot" | "environment"; environment: string | null; name: string }
  | { provider: "vercel"; project: string; team: string | null; target: "production" | "preview" | "development"; name: string }
  | { provider: "cloudflare"; account: string; script: string; name: string }
  | { provider: "fly"; app: string; name: string }

export type PushProvider = PushDestination["provider"]

// The templates (and OAuth providers) whose credential may carry a push to
// each provider: the "via".
export const PUSH_VIA: Record<PushProvider, readonly string[]> = {
  github: ["github-pat", "github-oauth"],
  vercel: ["vercel"],
  cloudflare: ["cloudflare-api-token"],
  fly: ["fly"],
}

const notDots = (segment: string) => !/^\.+$/.test(segment)
const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,254}$/
// GitHub stores names upper case and reserves the GITHUB_ prefix.
const GITHUB_NAME = /^(?!GITHUB_)[A-Z_][A-Z0-9_]{0,254}$/
const GITHUB_OWNER = /^[a-z0-9-]{1,39}$/
const GITHUB_REPO = /^[a-z0-9._-]{1,100}$/
// GitHub environment names are not case-sensitive, so the canonical one is lower case.
const GITHUB_ENVIRONMENT = /^[a-z0-9._-]{1,255}$/
const VERCEL_PROJECT_ID = /^prj_[A-Za-z0-9]{1,64}$/
const VERCEL_PROJECT_NAME = /^[a-z0-9._-]{1,100}$/
const VERCEL_TEAM_ID = /^team_[A-Za-z0-9]{1,64}$/
const VERCEL_TEAM_SLUG = /^[a-z0-9-]{1,48}$/
const CLOUDFLARE_ACCOUNT = /^[0-9a-f]{32}$/
const CLOUDFLARE_SCRIPT = /^[a-z0-9_][a-z0-9_-]{0,62}$/
const FLY_APP = /^[a-z0-9-]{1,63}$/

const GitHubDestinationSchema = z
  .strictObject({
    provider: z.literal("github"),
    owner: z.string().regex(GITHUB_OWNER),
    repo: z.string().regex(GITHUB_REPO).refine(notDots),
    store: z.enum(["actions", "dependabot", "environment"]),
    environment: z.string().regex(GITHUB_ENVIRONMENT).refine(notDots).nullable(),
    name: z.string().regex(GITHUB_NAME),
  })
  .refine((d) => (d.store === "environment") === (d.environment !== null), "An environment is named only for an environment secret")

const VercelDestinationSchema = z.strictObject({
  provider: z.literal("vercel"),
  project: z.string().refine((p) => VERCEL_PROJECT_ID.test(p) || (VERCEL_PROJECT_NAME.test(p) && notDots(p))),
  team: z.string().refine((t) => VERCEL_TEAM_ID.test(t) || VERCEL_TEAM_SLUG.test(t)).nullable(),
  target: z.enum(["production", "preview", "development"]),
  name: z.string().regex(NAME),
})

const CloudflareDestinationSchema = z.strictObject({
  provider: z.literal("cloudflare"),
  account: z.string().regex(CLOUDFLARE_ACCOUNT),
  script: z.string().regex(CLOUDFLARE_SCRIPT),
  name: z.string().regex(NAME),
})

const FlyDestinationSchema = z.strictObject({
  provider: z.literal("fly"),
  app: z.string().regex(FLY_APP),
  name: z.string().regex(NAME),
})

export const PushDestinationSchema: z.ZodType<PushDestination> = z.discriminatedUnion("provider", [GitHubDestinationSchema, VercelDestinationSchema, CloudflareDestinationSchema, FlyDestinationSchema])

const lower = (s: string) => s.toLowerCase()

// An id keeps its case; a name is lower case.
function vercelRef(raw: string, id: RegExp): string {
  return id.test(raw) ? raw : lower(raw)
}

function readSegments(provider: string, segments: string[]): unknown {
  switch (provider) {
    case "github": {
      const [owner, repo] = segments
      if (owner === undefined || repo === undefined) return null
      const base = { provider: "github", owner: lower(owner), repo: lower(repo) }
      if (segments.length === 3) return { ...base, store: "actions", environment: null, name: segments[2]!.toUpperCase() }
      if (segments.length === 4 && lower(segments[2]!) === "dependabot") return { ...base, store: "dependabot", environment: null, name: segments[3]!.toUpperCase() }
      if (segments.length === 5 && lower(segments[2]!) === "env") return { ...base, store: "environment", environment: lower(segments[3]!), name: segments[4]!.toUpperCase() }
      return null
    }
    case "vercel": {
      if (segments.length !== 3) return null
      const [where, target, name] = segments as [string, string, string]
      const at = where.indexOf("@")
      const project = at === -1 ? where : where.slice(0, at)
      const team = at === -1 ? null : where.slice(at + 1)
      return { provider: "vercel", project: vercelRef(project, VERCEL_PROJECT_ID), team: team === null ? null : vercelRef(team, VERCEL_TEAM_ID), target: lower(target), name }
    }
    case "cloudflare": {
      if (segments.length !== 3) return null
      const [account, script, name] = segments as [string, string, string]
      return { provider: "cloudflare", account: lower(account), script: lower(script), name }
    }
    case "fly": {
      if (segments.length !== 2) return null
      const [app, name] = segments as [string, string]
      return { provider: "fly", app: lower(app), name }
    }
    default:
      return null
  }
}

// The CLI's grammar to a canonical destination; null for anything else.
export function parsePushDestination(text: string): PushDestination | null {
  if (!/^[\x21-\x7e]+$/.test(text)) return null
  const colon = text.indexOf(":")
  if (colon <= 0) return null
  const segments = text.slice(colon + 1).split("/")
  const parsed = PushDestinationSchema.safeParse(readSegments(lower(text.slice(0, colon)), segments))
  return parsed.success ? parsed.data : null
}

export function formatPushDestination(d: PushDestination): string {
  switch (d.provider) {
    case "github":
      if (d.store === "environment") return `github:${d.owner}/${d.repo}/env/${d.environment}/${d.name}`
      if (d.store === "dependabot") return `github:${d.owner}/${d.repo}/dependabot/${d.name}`
      return `github:${d.owner}/${d.repo}/${d.name}`
    case "vercel":
      return `vercel:${d.project}${d.team === null ? "" : `@${d.team}`}/${d.target}/${d.name}`
    case "cloudflare":
      return `cloudflare:${d.account}/${d.script}/${d.name}`
    case "fly":
      return `fly:${d.app}/${d.name}`
  }
}

// "GitHub example/mehen, Actions secret OPENAI_API_KEY": where the value
// goes, as the card and the records say it.
export function pushDestinationWords(d: PushDestination): string {
  switch (d.provider) {
    case "github": {
      const repo = `GitHub ${d.owner}/${d.repo}`
      if (d.store === "environment") return `${repo}, environment ${d.environment}, Actions secret ${d.name}`
      if (d.store === "dependabot") return `${repo}, Dependabot secret ${d.name}`
      return `${repo}, Actions secret ${d.name}`
    }
    case "vercel":
      return `Vercel ${d.project}${d.team === null ? "" : ` in team ${d.team}`}, ${d.target} variable ${d.name}`
    case "cloudflare":
      return `Cloudflare Worker ${d.script} in account ${d.account}, secret ${d.name}`
    case "fly":
      return `Fly app ${d.app}, secret ${d.name}`
  }
}

// What the provider said about the destination before anyone decides, read
// with the via under its own policy. Only these fields are ever read from a
// provider's answer; a read the via's policy does not allow, or that failed
// without refusing the push, leaves its fields null.
export type PushPreview =
  | {
      provider: "github"
      // owner.login and owner.type ("User" or "Organization") as GitHub gives them.
      owner: string | null
      ownerType: string | null
      private: boolean | null
      fork: boolean | null
      // parent.full_name, set only for a fork.
      parent: string | null
      exists: boolean | null
      updatedAt: string | null
    }
  | { provider: "vercel"; projectId: string | null; projectName: string | null; accountId: string | null; repo: string | null; exists: null; updatedAt: null }
  | { provider: "cloudflare"; accountName: string | null; exists: boolean | null; updatedAt: null }
  | { provider: "fly"; organization: string | null; exists: boolean | null; updatedAt: null }

// "created" or "replaced" when the provider says which; "set" when it does not.
export type PushOutcome = "created" | "replaced" | "set"

// What POST /v1/push answers once the push is done.
export type PushResult = { push: string; item: string; field: string; version: number; destination: string; via: string; outcome: PushOutcome; at: string }

// One push as the credential page and `mehen show` list it: the latest per
// destination. `current` is false when the item has a newer version. `via`
// is null when the viewer may not see the credential that carried it; `by`
// is absent from a machine's answer.
export type PushRecordView = {
  push: string
  destination: string
  words: string
  field: string
  version: number
  current: boolean
  via: string | null
  state: "done" | "failed" | "unknown" | "not_sent"
  outcome: PushOutcome | null
  providerStatus: number | null
  at: string
  by?: string | null
}

export type PushApprovalState = "pending" | "queued" | "sending" | PushRecordView["state"]

// ApprovalStatus.push: how far the push an approval asked for has got.
export type PushApprovalStatus = { destination: string; field: string; version: number; state: PushApprovalState; outcome?: PushOutcome; providerStatus?: number }

// ApprovalView.push: what the card shows about a push. `newDestination`:
// the workspace has neither bound this repository nor pushed to its owner.
export type PushApprovalView = PushApprovalStatus & { words: string; via: string; preview: PushPreview | null; newDestination: boolean }
