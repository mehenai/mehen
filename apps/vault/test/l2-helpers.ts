import { importSealPublicKey, seal, type SealedBox } from "@mehen/protocol"
import type { MemberPrincipal } from "../src/vault/core.ts"
import { ORIGIN,fetchWorker } from "./helpers.ts"
export type Browser = { member: string; get(path: string): Promise<Response>; post(path: string, body?: unknown, headers?: Record<string,string>): Promise<Response> }

export function memberPrincipal(stepUp: MemberPrincipal["stepUp"] = null): MemberPrincipal {
  return { kind: "member", member: "mem_test", role: "owner", stepUp }
}

export async function sealToVault(value: string, context: string): Promise<SealedBox> {
  const { jwk } = (await (await fetchWorker("/v1/seal-key")).json()) as { jwk: JsonWebKey }
  return seal(await importSealPublicKey(jwk), value, context)
}

export function workspaceBrowser(env: import("../src/env.ts").Env, cookie: string, slug: string): Pick<Browser, "get" | "post"> {
  const prefix = `/api/w/${encodeURIComponent(slug)}`
  const headers = { cookie, origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "application/json" }
  return {
    get: async (path) => (await import("./helpers.ts")).fetchWorkspaceWorker(env, `${prefix}${path}`, { headers }),
    post: async (path, body = {}, extraHeaders = {}) => (await import("./helpers.ts")).fetchWorkspaceWorker(env, `${prefix}${path}`, { method: "POST", headers: { ...headers, ...extraHeaders }, body: JSON.stringify(body) }),
  }
}
