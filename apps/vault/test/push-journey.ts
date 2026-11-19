// A push end to end through the vault's routes (design push-providers 3.1
// and 3.2): two credentials stored as the intake page stores them, the
// allowance turned on with a passkey, an enrolled machine, a fake GitHub
// behind the relay's fetch, and a person's passkey decision. Shared by the
// route tests and the page tests.
import { canonicalJson, importSealPublicKey, seal, sha256B64, type ApprovalViewProjection, type CredentialHome, type WorkspaceRef, type WorkspaceStepUpAction } from "@mehen/protocol"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { body, workJourney, type Person } from "./e2e/workspace-journey.ts"

export const VALUE = "sk-push-sentinel-never-shown-0001"
export const VIA_TOKEN = "ghp_push-via-sentinel-never-shown"
// A Curve25519 public key as GitHub hands one out: any 32 bytes do.
const PUBLIC_KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)))

type WorkJourney = Awaited<ReturnType<typeof workJourney>>
export type PushJourney = Awaited<ReturnType<typeof pushJourney>>

// An intake stored with its value sealed on this side, as the page does.
export async function stored(f: Pick<WorkJourney, "request" | "signed">, person: Person, ws: WorkspaceRef, slug: string, provider: string, value: string, home: CredentialHome = { kind: "workspace" }): Promise<void> {
  const created = await body<{ intake: string }>(await f.request(`/api/w/${ws.slug}/intakes`, person, { provider, slug, home: home.kind === "member" ? "private" : home.kind }), 201)
  const view = await body<{ binding: { value: { hosts: string[] } } }>(await f.request(`/api/w/${ws.slug}/intakes/${created.intake}`, person))
  const sealKey = await body<{ jwk: JsonWebKey }>(await f.request("/v1/seal-key"))
  const input = { slug, home, binding: view.binding.value, publicFields: {}, tags: [], sealed: { key: await seal(await importSealPublicKey(sealKey.jwk), value, `intake/${created.intake}/key`) } }
  await body(await f.signed(`/api/w/${ws.slug}/intakes/${created.intake}/submit`, person, input, { type: "intake.submit", intake: created.intake, digest: await sha256B64(canonicalJson(input)) }, ws.slug))
}

export async function allowPush(f: WorkJourney, person: Person, ws: WorkspaceRef, slug: string): Promise<void> {
  const change = { pushable: true }
  const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${ws.slug}/items/${slug}/action`, person, { action: "update", change }))
  await body(await f.signed(`/api/w/${ws.slug}/items/${slug}/update`, person, change, action, ws.slug))
}

// A fake GitHub: the repository, the secret not there yet, the public key,
// and the write. Every request is kept with its Authorization and body.
export function fakeGitHub(put: () => Response = () => new Response(null, { status: 201 })) {
  const sent: { method: string; url: string; authorization: string | null; body: string }[] = []
  setUpstreamFetch(async (request) => {
    sent.push({ method: request.method, url: request.url, authorization: request.headers.get("authorization"), body: await request.text() })
    const path = new URL(request.url).pathname
    if (request.method === "GET" && path === "/repos/acme/api") return Response.json({ owner: { login: "acme", type: "Organization" }, private: true, fork: false })
    if (request.method === "GET" && path.endsWith("/public-key")) return Response.json({ key_id: "k1", key: PUBLIC_KEY })
    if (request.method === "GET") return Response.json({ message: "Not Found" }, { status: 404 })
    if (request.method === "PUT") return put()
    return new Response(null, { status: 500 })
  })
  return sent
}

export const to = { provider: "github", owner: "acme", repo: "api", store: "actions", environment: null, name: "OPENAI_API_KEY" }

export async function pushJourney() {
  const f = await workJourney()
  await stored(f, f.alex, f.work, "openai-prod", "openai", VALUE)
  await stored(f, f.alex, f.work, "gh-token", "github-pat", VIA_TOKEN)
  await allowPush(f, f.alex, f.work, "openai-prod")
  const machine = await f.machine(f.alex, f.work)
  const decide = async (approval: string) => {
    const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${f.work.slug}/approvals/${approval}/action`, f.alex, { decision: "approve" }))
    return body<ApprovalViewProjection>(await f.signed(`/api/w/${f.work.slug}/approvals/${approval}/decide`, f.alex, { decision: "approve" }, action, f.work.slug))
  }
  return { ...f, machine, decide, enrolMachine: f.machine }
}
