// Helpers for the workspace project and credential page journeys: pages
// fetched as HTML through worker.fetch, and changes sent with the bodies and
// checks the browser's own logic builds, signed with a real software
// passkey. The browser's signing code itself is driven in
// src/ui/workspace-sign.test.ts; this copy proves the vault's side.
import { expect } from "vitest"
import { importSealPublicKey, seal, type CredentialHome, type WorkspaceIntakeView, type WorkspaceRef, type WorkspaceStepUpAction } from "@mehen/protocol"
import { type IntakeBoot, buildIntakeSubmission } from "../../src/ui/client/logic.ts"
import { CHANGED_SINCE_SHOWN, type ProjectChange, createdAskPath, credentialStart, identityRefusal, intakeWithHome, projectCreate, sameAction } from "../../src/ui/client/workspace-logic.ts"
import { body, journey, type Person } from "./workspace-journey.ts"

export type Journey = Awaited<ReturnType<typeof journey>>
// What signing a change and filling an ask need of a journey.
type JourneyCalls = Pick<Journey, "request" | "signed" | "proof">
export const WS = "northwind"

export async function page(f: Journey, path: string, person: Person): Promise<{ status: number; text: string }> {
  const response = await f.request(path, person, undefined, { accept: "text/html" })
  return { status: response.status, text: await response.text() }
}

// The browser's signed(): ask, check, confirm the workspace, sign, send.
export async function uiSigned(f: JourneyCalls, person: Person, shown: WorkspaceRef, prepare: { path: string; body: unknown }, matches: (action: unknown) => boolean, mutation: { path: string; body: Record<string, unknown> }) {
  const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}${prepare.path}`, person, prepare.body, { "Mehen-Workspace": shown.id }))
  if (!matches(action)) throw new Error(CHANGED_SINCE_SHOWN.message)
  const now = await body<WorkspaceRef>(await f.request(`/api/w/${WS}`, person, undefined, { "Mehen-Workspace": shown.id }))
  const renamed = identityRefusal(shown, now)
  if (renamed !== null) throw new Error(renamed.message)
  return f.request(`/api/w/${WS}${mutation.path}`, person, { ...mutation.body, stepUp: await f.proof(person, action, WS) }, { "Mehen-Workspace": shown.id })
}

export async function projectSigned(f: Journey, person: Person, shown: WorkspaceRef, change: ProjectChange) {
  const expected = await change.expected
  return uiSigned(f, person, shown, { path: "/projects/action", body: { change: change.change, input: change.input } }, (a) => sameAction(expected, a), { path: change.path, body: change.input })
}

// A credential added the way the credentials page and the intake page do it.
export async function addCredential(f: Journey, person: Person, shown: WorkspaceRef, slug: string, home: CredentialHome) {
  const start = credentialStart("openai", "intake", slug, home)
  const created = await body<{ intake: string }>(await f.request(`/api/w/${WS}${start.path}`, person, start.body), 201)
  expect(createdAskPath(WS, created)).toBe(`/w/${WS}/i/${created.intake}`)
  const intakePage = await page(f, `/w/${WS}/i/${created.intake}`, person)
  expect(intakePage.status).toBe(200)
  expect(intakePage.text).toContain('data-region="home-choice"')
  await fillIntake(f, person, created.intake, home)
}

// The intake page's submit: seal every field on this side, sign the
// submission with the chosen home.
export async function fillIntake(f: JourneyCalls, person: Person, intake: string, home: CredentialHome) {
  const view = await body<WorkspaceIntakeView>(await f.request(`/api/w/${WS}/intakes/${intake}`, person))
  const boot: IntakeBoot = { intake: view.intake, slug: view.slug, binding: view.binding.value, verified: view.binding.verified, rotates: view.rotates, tags: view.tags, fields: view.fields.map((x) => ({ name: x.name, label: x.label, secret: x.secret, required: x.required, multiline: x.multiline })), customPolicy: view.customPolicy }
  const key = await importSealPublicKey(view.sealKey.jwk)
  const values = Object.fromEntries(view.fields.map((x) => [x.name, x.name === "key" ? "sk-ui-journey-not-a-real-secret" : `ui-journey-${x.name}`]))
  const built = await buildIntakeSubmission(boot, values, false, (value, context) => seal(key, value, context))
  if (!built.ok) throw new Error(built.problems.join(" "))
  const { body: submission, digest } = await intakeWithHome(built.value.submission, home)
  await body(await f.signed(`/api/w/${WS}/intakes/${intake}/submit`, person, submission, { type: "intake.submit", intake, digest }, WS))
}

export async function setup() {
  const f = await journey()
  await f.recoverySetup(f.alex)
  const work = await f.createWorkspace(f.alex, WS, "Northwind")
  const envs = [{ name: "dev", protected: false, fourEyes: false }, { name: "staging", protected: false, fourEyes: false }, { name: "prod", protected: true, fourEyes: false }]
  const create = projectCreate("platform", "", envs, "dev")
  if (!create.ok) throw new Error(create.problems.join(" "))
  const project = await body<{ id: string; slug: string }>(await projectSigned(f, f.alex, work, create.value), 201)
  return { ...f, work, platform: project }
}


// A connection completed the way its pages do it: the client intake, the
// signed start, then the provider's callback answered by a fake upstream at
// the relay's existing seam (no real network).
export async function completeConnect(f: Journey, person: Person, shown: WorkspaceRef, slug: string, home: CredentialHome, subject: string) {
  const start = credentialStart("google-gmail", "connect", slug, home)
  const created = await body<{ connect: string; intake?: { intake: string } }>(await f.request(`/api/w/${WS}${start.path}`, person, start.body), 201)
  if (created.intake) await fillIntake(f, person, created.intake.intake, home)
  await completeStartedConnect(f, person, shown, created.connect, home, subject)
  return created.connect
}

// The signed start of a connection already asked for, whoever asked, then
// the provider's callback answered by a fake upstream.
export async function completeStartedConnect(f: JourneyCalls, person: Person, shown: WorkspaceRef, connect: string, home: CredentialHome, subject: string) {
  const { setUpstreamFetch } = await import("../../src/relay/upstream.ts")
  const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/connect/${connect}/action`, person, { home }))
  const started = await body<{ authorizeUrl: string }>(await uiSigned(f, person, shown, { path: `/connect/${connect}/action`, body: { home } }, (a) => sameAction(action, a), { path: `/connect/${connect}/start`, body: { home } }))
  setUpstreamFetch(async (request) => (request.url.includes("/token") ? Response.json({ access_token: `access-${subject}`, refresh_token: `refresh-${subject}`, expires_in: 3600, scope: "openid email https://www.googleapis.com/auth/gmail.modify" }) : Response.json({ sub: subject, email: `${subject}@example.test`, email_verified: true })))
  try {
    const state = new URL(started.authorizeUrl).searchParams.get("state") ?? ""
    expect((await f.request(`/oauth/callback?state=${encodeURIComponent(state)}&code=code-${subject}`, person)).status).toBe(302)
  } finally {
    setUpstreamFetch(null)
  }
}
