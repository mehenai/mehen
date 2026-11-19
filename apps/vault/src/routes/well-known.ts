// /.well-known/apple-app-site-association: the apps that may run passkey
// ceremonies for this RP id (webcredentials), from APPLE_WEBCREDENTIAL_APPS.
// Served straight, with no redirect, as application/json; absent (404)
// when no app is configured.
//
// /.well-known/security.txt: the RFC 9116 disclosure contact, as mehen.dev
// (apps/web) and docs.mehen.dev (apps/docs) serve it, with this host as the
// canonical URL. Keep the three in step; Expires is about a year out, so renew
// it in all three before then (the test fails once it has passed).

import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import type { Route } from "../router.ts"
import type { Handler } from "./context.ts"

export function webCredentialApps(env: Env): string[] {
  return (env.APPLE_WEBCREDENTIAL_APPS ?? "")
    .split(",")
    .map((app) => app.trim())
    .filter((app) => app !== "")
}

export function securityTxt(origin: string): string {
  return [
    "Contact: mailto:security@mehen.dev",
    "Expires: 2027-10-29T00:00:00.000Z",
    "Policy: https://docs.mehen.dev/security/disclosure",
    "Preferred-Languages: en",
    `Canonical: ${origin}/.well-known/security.txt`,
    "",
  ].join("\n")
}

export const wellKnownRoutes: Route<Handler>[] = [
  {
    method: "GET",
    path: "/.well-known/apple-app-site-association",
    handler: async (rc) => {
      const apps = webCredentialApps(rc.env)
      if (apps.length === 0) throw new VaultError("not_found", "No such route.")
      return new Response(JSON.stringify({ webcredentials: { apps }, applinks: { apps: [], details: apps.map(appID => ({ appID, paths: ["/app/v1/gate/callback"] })) } }), { status: 200, headers: { "content-type": "application/json" } })
    },
  },
  {
    method: "GET",
    path: "/.well-known/security.txt",
    handler: async (rc) => new Response(rc.request.method === "HEAD" ? null : securityTxt(rc.env.VAULT_ORIGIN), { status: 200, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=300" } }),
  },
]
