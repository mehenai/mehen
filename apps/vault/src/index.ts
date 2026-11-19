// app.mehen.dev: one Worker in front of one fresh Durable Object per workspace.

import type { Env } from "./env.ts"
import { VaultError, errorResponse, responseFor, withSecurityHeaders } from "./http.ts"
import { assertSameOrigin } from "./directory/session.ts"
import { findRoute } from "./router.ts"
import { workspacePrefix } from "./routes/workspace-prefix.ts"
import { workspaceDirectoryPrefix } from "./routes/directory.ts"
import { maintainWorkspaceDirectory } from "./directory/workspace-maintenance.ts"
import { currentAccountSession } from "./directory/account-session.ts"
import { workspaceNotFoundPage } from "./ui/pages/workspaces.ts"
import { pageResponse } from "./ui/layout.ts"
import { ROUTES } from "./routes/index.ts"
import { servedAccountPages, workspacePagePrefix } from "./routes/ui.ts"
import { NOT_FOUND_ERROR, errorPage } from "./ui/layout.ts"

export { WorkspaceVault } from "./vault/workspace-vault.ts"
export { PlatformVault } from "./platform/platform-vault.ts"
import { assertPlatformRoutesClaimed, handlePlatformRequest, isPlatformPath } from "./routes/platform.ts"
import { platformOAuthRoutes } from "./routes/platform-oauth.ts"
import { chargeRefusedDeviceProof, rateLimitedResponse, withinRateLimits } from "./rate-limits.ts"
import { assertWorkspaceCutover } from "./directory/workspace-cutover.ts"
import { assertCliVersion, refreshCliAdvice, withCliAdvice } from "./cli-version.ts"
import { carriesServerTiming, timedEnv, timesRequest, withServerTiming } from "./server-timing.ts"

// Every platform OAuth route is claimed by the OAuth areas, and nothing else:
// a worker out of step fails at start, never answers a route by accident.
assertPlatformRoutesClaimed(platformOAuthRoutes)

// What browsers fetch from the root on their own, answered from the built
// assets: the favicon, and the home-screen icon build-ui.ts draws from it.
const ROOT_ICONS: Record<string, string> = {
  "/favicon.ico": "/assets/favicon.svg",
  "/apple-touch-icon.png": "/assets/apple-touch-icon.png",
  "/apple-touch-icon-precomposed.png": "/assets/apple-touch-icon.png",
}

// A browser asking for a page at an address the vault does not have gets
// a page back; the API, the agents' /v1 and a native app's /app/v1 routes keep
// their JSON error.
function wantsPage(request: Request, url: URL): boolean {
  if (request.method !== "GET" && request.method !== "HEAD") return false
  if (["/api/", "/v1/", "/app/", "/assets/"].some((prefix) => url.pathname.startsWith(prefix))) return false
  return (request.headers.get("accept") ?? "").includes("text/html")
}

async function notFoundPage(request: Request, env: Env): Promise<Response> {
  const account = await currentAccountSession(request, env)
  return account ? pageResponse(workspaceNotFoundPage({ origin: env.VAULT_ORIGIN, account: account.account, name: account.name, accountPages: servedAccountPages() }), 404) : errorPage(null, 404, NOT_FOUND_ERROR)
}

async function handle(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url)
  if (!(await withinRateLimits(request, url, env))) return rateLimitedResponse()
  await assertWorkspaceCutover(env)
  // The /v1 version seam, before any prefix dispatch.
  assertCliVersion(request, url, env)
  // A platform's own API, signed with its platform proof.
  if (isPlatformPath(url.pathname)) return handlePlatformRequest({ request, env, ctx, url, params: {} })
  // Every state-changing browser route, whoever wrote it, is same-origin only.
  if (url.pathname.startsWith("/api/") && request.method !== "GET" && request.method !== "HEAD") assertSameOrigin(request, env)
  const workspaceResponse = await workspacePrefix({ request, env, ctx, url, params: {} })
  if (workspaceResponse) return workspaceResponse
  const directoryResponse = await workspaceDirectoryPrefix({ request, env, ctx, url, params: {} })
  if (directoryResponse) return directoryResponse
  const pageResponse = await workspacePagePrefix({ request, env, ctx, url, params: {} })
  if (pageResponse) return pageResponse
  const found = findRoute(ROUTES, request.method, url.pathname)
  if (found === null) {
    // HEAD as GET, as findRoute treats it: the assets binding answers it with the headers and no body.
    const reads = request.method === "GET" || request.method === "HEAD"
    if (env.ASSETS && reads && url.pathname.startsWith("/assets/")) return env.ASSETS.fetch(request)
    const icon = Object.hasOwn(ROOT_ICONS, url.pathname) ? ROOT_ICONS[url.pathname] : undefined
    if (env.ASSETS && reads && icon !== undefined) return env.ASSETS.fetch(new Request(new URL(icon, url), request))
    if (wantsPage(request, url)) return notFoundPage(request, env)
    throw new VaultError("not_found", "No such route.")
  }
  if (found === "method") return errorResponse({ error: "bad_request", message: "Method not allowed." }, 405)
  return found.route.handler({ request, env, ctx, url, params: found.params })
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    const url = new URL(request.url)
    refreshCliAdvice(url, env, ctx)
    const answer = async (env: Env): Promise<Response> => {
      try {
        return await handle(request, env, ctx)
      } catch (error) {
        if (!(error instanceof VaultError)) console.error(JSON.stringify({ at: "fetch", error: error instanceof Error ? error.name : "unknown" }))
        return responseFor(error)
      }
    }
    const timedPage = timesRequest(request, url) && !isPlatformPath(url.pathname) && !Object.hasOwn(ROOT_ICONS, url.pathname)
    const response = timedPage ? await withServerTiming(() => answer(timedEnv(env)), (answered) => carriesServerTiming(url, answered)) : await answer(env)
    return withCliAdvice(withSecurityHeaders(await chargeRefusedDeviceProof(request, url, env, response)), url, env)
  },
  async scheduled(_controller, env): Promise<void> {
    await assertWorkspaceCutover(env)
    await maintainWorkspaceDirectory(env)
  },
} satisfies ExportedHandler<Env>
