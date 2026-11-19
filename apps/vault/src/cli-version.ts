// The /v1 version seam. Every /v1 request from an
// identified `mehen/<version>` client below CLI_MINIMUM_VERSION is refused
// 426 cli_outdated before any route runs, enrolment and renewal included;
// freeze and self-revoke are never blocked by a version. A request with no
// User-Agent, or one that is not `mehen/...` (0.2.0 sends Bun's), passes by
// policy: this is a compatibility aid, not a boundary. Every /v1 response
// carries the advice in Mehen-Cli so a client learns the minimum before it
// is enforced. The minimum is only ever the hand-set var; the recommended
// version follows the published release (published-release.ts), with
// CLI_RECOMMENDED_VERSION as its floor.

import { compareVersions } from "@mehen/protocol/version"
import type { Env } from "./env.ts"
import { VaultError } from "./http.ts"
import { publishedCliVersion, refreshPublishedRelease } from "./published-release.ts"

export const CLI_ADVICE_HEADER = "Mehen-Cli"

const EXEMPT = new Set(["POST /v1/freeze", "POST /v1/devices/self/revoke"])
const AGENT = /^mehen\/(\d{1,6}\.\d{1,6}\.\d{1,6})(?![\d.])/
const VERSION = /^\d{1,6}\.\d{1,6}\.\d{1,6}$/

// The version a `mehen/<x.y.z>` User-Agent names, else null.
export function cliVersionOf(userAgent: string | null): string | null {
  return AGENT.exec((userAgent ?? "").slice(0, 256))?.[1] ?? null
}

function configured(value: string | undefined): string | null {
  const v = value?.trim()
  return v && VERSION.test(v) ? v : null
}

export function assertCliVersion(request: Request, url: URL, env: Env): void {
  if (!url.pathname.startsWith("/v1/") || EXEMPT.has(`${request.method} ${url.pathname}`)) return
  const minimum = configured(env.CLI_MINIMUM_VERSION)
  const version = cliVersionOf(request.headers.get("user-agent"))
  if (minimum === null || version === null || compareVersions(version, minimum) >= 0) return
  throw new VaultError("cli_outdated", `This machine's mehen ${version} is older than the vault supports (${minimum}).`, {
    next: { command: "mehen update --json", say: "Update mehen on this machine, then run the command again." },
  })
}

// The higher of CLI_RECOMMENDED_VERSION and the verified published release;
// either alone when the other is missing.
export function recommendedCliVersion(env: Env, now: number): string | null {
  const floor = configured(env.CLI_RECOMMENDED_VERSION)
  const release = publishedCliVersion(now)
  if (release === null) return floor
  return floor !== null && compareVersions(floor, release) >= 0 ? floor : release
}

// A /v1 request starts the read of the published release when one is due,
// off the request path: the request never waits for it.
export function refreshCliAdvice(url: URL, env: Env, ctx: ExecutionContext): void {
  if (!url.pathname.startsWith("/v1/")) return
  const refresh = refreshPublishedRelease(env, Date.now())
  if (refresh !== null) ctx.waitUntil(refresh)
}

// What the Machines page marks each machine's version against.
export type CliAdvice = { minimum: string | null; recommended: string | null }
export function cliAdvice(env: Env): CliAdvice {
  return { minimum: configured(env.CLI_MINIMUM_VERSION), recommended: recommendedCliVersion(env, Date.now()) }
}

// `Mehen-Cli: minimum=<v>; recommended=<v>` on every /v1 response, success or
// error; never on /api, /app/v1 or pages.
export function withCliAdvice(response: Response, url: URL, env: Env): Response {
  const minimum = configured(env.CLI_MINIMUM_VERSION)
  if (!url.pathname.startsWith("/v1/") || minimum === null) return response
  const recommended = recommendedCliVersion(env, Date.now())
  const out = new Response(response.body, response)
  out.headers.set(CLI_ADVICE_HEADER, recommended ? `minimum=${minimum}; recommended=${recommended}` : `minimum=${minimum}`)
  return out
}

// Connect codes ship with the 0.3.0 CLI: `mehen enrol --connect` is unknown to
// 0.2.0, so the issuer answers only once the deployment recommends 0.3.0 or
// later (CLI_RECOMMENDED_VERSION itself, not the published release,
// MANIFEST section 7 step 6). Until then the Connect an agent page keeps the
// boxes without --connect.
export const CONNECT_CODE_CLI = "0.3.0"

// The first mehen that reads an approval status of superseded, with the
// newer ask in replacedBy; an older one is answered stale (approvals.status).
export const SUPERSEDED_CLI = "0.3.17"

// The first mehen that reads a task grant (a standing rule of kind area).
// To an older one, or a machine whose version is unknown, a grant does not
// exist: never listed, and its id answers not_found (policy.rules,
// policy.rules.revoke); nor may it propose one, and a task grant's proposal
// is never listed to it and answers not_found (policy.propose, policy.status,
// policy.cancel, pending.list).
export const AREA_GRANT_CLI = "0.3.17"

// The first mehen that reads /v1/pending's top-level `groups` (its review
// groups of two or more open asks) and approval_required's `group`; an
// older one is never sent either.
export const PENDING_GROUPS_CLI = "0.3.17"

export function connectCodesOffered(env: Env): boolean {
  const recommended = configured(env.CLI_RECOMMENDED_VERSION)
  return recommended !== null && compareVersions(recommended, CONNECT_CODE_CLI) >= 0
}

// The first mehen that knows provider_refused (ruling X1); an older or
// unknown one is answered upstream_failed with the same sentence (routes/push.ts).
export const PUSH_CLI = "0.3.18"
