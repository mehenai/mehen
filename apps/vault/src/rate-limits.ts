// Which rate limits a request meets before anything else runs. Signing in
// and every unauthenticated route keep the per-address limits. Signed
// traffic is counted by the identity its proof claims, behind a much higher
// limit per address, because many platforms' servers and agents' devices
// can reach the vault from one shared address:
// - a platform call (/v1/platform) meets only its outer per-address limit
//   here; the platform's own limits are counted after its proof verifies,
//   by its PlatformVault;
// - a device or workload call (a /v1 route signed with a Mehen-Proof that
//   names a workspace) meets the outer per-address limit, then one keyed
//   by the workspace and device its proof claims. The claim is not yet
//   verified, so it only chooses whose budget is spent; the outer limit
//   bounds what one address can spend. A device call whose proof the
//   workspace then refuses is charged after the fact against the
//   per-address limit unsigned traffic meets (chargeRefusedDeviceProof), so
//   forged proofs from one address are held to that floor while genuine
//   devices behind it keep their own limits.
// A limiter the configuration leaves unbound refuses, as the routes that
// spend AUTH_RATE_LIMITER themselves do: a vault missing a binding answers
// rate_limited, never unlimited.

import { PUBLIC_SEAL_KEY_PATH, parseProof } from "@mehen/protocol"
import { ERROR_HEADER } from "@mehen/protocol/api"
import type { Env } from "./env.ts"
import { errorResponse } from "./http.ts"
import { PROOF_HEADER } from "./routes/context.ts"
import { isPlatformPath } from "./routes/platform.ts"
import { TENANT_ID } from "./vault/client.ts"

export type RateLimiterBinding = "RATE_LIMITER" | "AUTH_RATE_LIMITER" | "PLATFORM_IP_RATE_LIMITER" | "DEVICE_IP_RATE_LIMITER" | "DEVICE_RATE_LIMITER"

export type RateLimitStep = { binding: RateLimiterBinding; limiter: RateLimit | undefined; key: string }

function signingIn(pathname: string): boolean {
  return pathname.startsWith("/api/auth/") || pathname === "/app/v1/session" || pathname.startsWith("/app/v1/session/")
}

// The workspace and device a device route's proof claims, or null for a
// route that takes no device proof or a proof that does not parse.
function claimedDevice(request: Request, pathname: string): string | null {
  if (!pathname.startsWith("/v1/") || pathname === PUBLIC_SEAL_KEY_PATH || pathname === "/v1/enrol" || pathname.startsWith("/v1/enrol/")) return null
  const proof = request.headers.get(PROOF_HEADER)
  if (!proof) return null
  try {
    const { claims } = parseProof(proof)
    return TENANT_ID.test(claims.ten) ? `${claims.ten}:${claims.dev}` : null
  } catch {
    return null
  }
}

function callerAddress(request: Request): string {
  return request.headers.get("cf-connecting-ip") ?? "local"
}

// The device a call is limited by, or null when it meets the per-address
// limits instead.
function deviceLimited(request: Request, url: URL): string | null {
  if (signingIn(url.pathname) || isPlatformPath(url.pathname)) return null
  return claimedDevice(request, url.pathname)
}

export function rateLimitedResponse(): Response {
  return errorResponse({ error: "rate_limited", message: "Too many requests; slow down." }, 429)
}

function logUnbound(binding: RateLimiterBinding): void {
  console.error(JSON.stringify({ at: "rate_limit", error: "limiter_unbound", binding }))
}

export function rateLimitSteps(request: Request, url: URL, env: Env): RateLimitStep[] {
  const address = callerAddress(request)
  const step = (binding: RateLimiterBinding, key: string): RateLimitStep => ({ binding, limiter: env[binding], key })
  if (signingIn(url.pathname)) return [step("AUTH_RATE_LIMITER", address)]
  if (isPlatformPath(url.pathname)) return [step("PLATFORM_IP_RATE_LIMITER", address)]
  const device = deviceLimited(request, url)
  if (device !== null) return [step("DEVICE_IP_RATE_LIMITER", address), step("DEVICE_RATE_LIMITER", device)]
  return [step("RATE_LIMITER", address)]
}

// True when every limit the request meets is bound and lets it through.
export async function withinRateLimits(request: Request, url: URL, env: Env): Promise<boolean> {
  for (const step of rateLimitSteps(request, url, env)) {
    if (!step.limiter) {
      logUnbound(step.binding)
      return false
    }
    const { success } = await step.limiter.limit({ key: step.key })
    if (!success) return false
  }
  return true
}

// A device-limited call the vault refused for its proof (a 401 vault
// refusal: proof_invalid or unauthenticated) is charged against
// RATE_LIMITER by address, and answered as rate limited once that
// address's budget is spent, or at once when RATE_LIMITER is unbound.
// Upstream answers never carry the vault's error header, so a relayed 401 is
// never charged.
export async function chargeRefusedDeviceProof(request: Request, url: URL, env: Env, response: Response): Promise<Response> {
  if (response.status !== 401 || response.headers.get(ERROR_HEADER) !== "1") return response
  if (deviceLimited(request, url) === null) return response
  if (env.RATE_LIMITER) {
    let spent: boolean
    try {
      spent = !(await env.RATE_LIMITER.limit({ key: callerAddress(request) })).success
    } catch {
      console.error(JSON.stringify({ at: "rate_limit.refused_proof", error: "limiter_failed" }))
      return response
    }
    if (!spent) return response
  } else logUnbound("RATE_LIMITER")
  await response.body?.cancel()
  return rateLimitedResponse()
}
