import { expect } from "vitest"
import { sha256Text } from "../../src/directory/session.ts"
import { fakeGoogle } from "../oidc-google.ts"
import { body, type Person, workJourney } from "./workspace-journey.ts"
import { assertion } from "./passkeys.ts"
function browserCookie(person: Person,cookie: string) { return [...person.cookie.split(";").map(value => value.trim()).filter(value => !value.startsWith("__Host-mehen_oidc=")),cookie].join("; ") }
export type OidcJourney = Pick<Awaited<ReturnType<typeof workJourney>>, "env" | "db" | "alex" | "work" | "request" | "proof" | "signed">
export async function googleFlow(f: OidcJourney,google: Awaited<ReturnType<typeof fakeGoogle>>,person: Person,input: Record<string, unknown>,claims: Record<string, unknown> = {}) {
  f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
  const started = await f.request("/api/auth/oidc/google/start",person,input),cookie = started.headers.get("set-cookie")!.split(";")[0]!,{ url } = await body<{ url: string }>(started),callback = await f.request(`/auth/oidc/google/callback?${new URLSearchParams(google.authorise(url,claims))}`,person,undefined,{ cookie: browserCookie(person,cookie) })
  expect(callback.status).toBe(303)
  return { id: oidcResultOf(callback,f.env.VAULT_ORIGIN),cookie }
}
// The result id the Google callback hands back: in /signup's fragment for an
// invitation, in the result page's query for every other purpose.
export function oidcResultOf(callback: Response,origin: string): string {
  const location = new URL(callback.headers.get("location")!,origin)
  if (location.pathname === "/signup") return decodeURIComponent(location.hash.replace(/^#oidc=/,""))
  return location.searchParams.get("result")!
}
export async function linkGoogle(f: OidcJourney,google: Awaited<ReturnType<typeof fakeGoogle>>,person = f.alex,claims: Record<string, unknown> = {}) {
  const proof = await f.proof(person,{ type: "identity.link",provider: "google" }),result = await googleFlow(f,google,person,{ purpose: "link",stepUp: proof },claims)
  expect(await body(await f.request("/api/account/identities/link",person,{ result: result.id,email: claims.email ?? "alex@northwind.example",subject: claims.sub ?? "google-alex" },{ cookie: browserCookie(person,result.cookie) }))).toEqual({ linked: true })
}
export async function webGate(f: OidcJourney,google: Awaited<ReturnType<typeof fakeGoogle>>,person = f.alex,input: Record<string, unknown> = {},claims: Record<string, unknown> = {}) {
  const result = await googleFlow(f,google,person,{ purpose: "gate",workspace: f.work.slug,...input },claims)
  const response = await f.request("/api/auth/oidc/google/gate",person,{ result: result.id },{ cookie: browserCookie(person,result.cookie) })
  expect(await body(response)).toEqual({ verified: true })
  return result
}
export const googleRule = { provider: "google" as const,domains: ["northwind.example"],roles: ["owner" as const,"admin" as const,"member" as const] }
export async function setGoogleRule(f: OidcJourney,google: Awaited<ReturnType<typeof fakeGoogle>>,rule = googleRule) {
  await webGate(f,google,f.alex,{ rule })
  const response = await f.signed(`/api/w/${f.work.slug}/identity-rule`,f.alex,{ rule },{ type: "workspace.identity_rule",rule },f.work.slug)
  expect(await body(response)).toMatchObject({ identityRule: rule })
}
export async function nativeSession(f: OidcJourney,person = f.alex) {
  const started = await body<{ flow: string; options: { challenge: string } }>(await f.request("/app/v1/session/options",undefined,{})),opened = await body<{ token: string }>(await f.request("/app/v1/session",undefined,{ flow: started.flow,response: await assertion(person.passkey,started.options.challenge,++person.counter),client: "Jeff on iPhone" }))
  return { token: opened.token,headers: { authorization: `Bearer ${opened.token}` } }
}
export async function appGate(f: OidcJourney,google: Awaited<ReturnType<typeof fakeGoogle>>,native: Awaited<ReturnType<typeof nativeSession>>,claims: Record<string, unknown> = {}) {
  const verifier = "native-test-pkce-verifier-".padEnd(64,"v"),started = await body<{ url: string }>(await f.request("/app/v1/gate/start",undefined,{ workspace: f.work.slug,pkceChallenge: await sha256Text(verifier) },native.headers)),params = new URLSearchParams(new URL(started.url).hash.slice(1)),input = { state: params.get("state")!,flow: params.get("flow")! }
  const launched = await f.request("/api/auth/oidc/google/app/start",undefined,input),cookie = launched.headers.get("set-cookie")!.split(";")[0]!,{ url } = await body<{ url: string }>(launched)
  expect((await f.request("/api/auth/oidc/google/app/start",undefined,input)).status).toBe(403)
  const callback = await f.request(`/auth/oidc/google/callback?${new URLSearchParams(google.authorise(url,claims))}`,undefined,undefined,{ cookie })
  return { callback,verifier,code: new URL(callback.headers.get("location") ?? "/",f.env.VAULT_ORIGIN).hash.replace(/^#code=/,"") }
}
