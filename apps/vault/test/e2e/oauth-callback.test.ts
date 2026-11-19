// The provider's redirect back to /oauth/callback lands in the person's
// browser: a refusal there is a page that says what happened and links to
// the connection's page, never the vault's raw JSON.
import { expect, it } from "vitest"
import type { WorkspaceStepUpAction } from "@mehen/protocol"
import { credentialStart, sameAction } from "../../src/ui/client/workspace-logic.ts"
import { OAUTH_CALLBACK_HEADING } from "../../src/routes/oauth-workspace.ts"
import { body } from "./workspace-journey.ts"
import { WS, fillIntake, setup, uiSigned } from "./ui-projects-journey.ts"

async function startedConnect() {
  const f = await setup(), home = { kind: "workspace" } as const
  const start = credentialStart("google-gmail", "connect", "gmail-callback", home)
  const created = await body<{ connect: string; intake?: { intake: string } }>(await f.request(`/api/w/${WS}${start.path}`, f.alex, start.body), 201)
  if (created.intake) await fillIntake(f, f.alex, created.intake.intake, home)
  const action = await body<WorkspaceStepUpAction>(await f.request(`/api/w/${WS}/connect/${created.connect}/action`, f.alex, { home }))
  const started = await body<{ authorizeUrl: string }>(await uiSigned(f, f.alex, f.work, { path: `/connect/${created.connect}/action`, body: { home } }, (a) => sameAction(action, a), { path: `/connect/${created.connect}/start`, body: { home } }))
  return { f, connect: created.connect, state: new URL(started.authorizeUrl).searchParams.get("state") ?? "" }
}

async function callbackPage(response: Response) {
  return { status: response.status, type: response.headers.get("content-type"), text: await response.text() }
}

it("a declined consent at the provider answers a page linking back to the connection, and the spent state then says so", async () => {
  const { f, connect, state } = await startedConnect()
  const declined = await callbackPage(await f.request(`/oauth/callback?state=${encodeURIComponent(state)}&error=access_denied`, f.alex, undefined, { accept: "text/html" }))
  expect(declined).toMatchObject({ status: 400, type: "text/html; charset=utf-8" })
  expect(declined.text).toContain(OAUTH_CALLBACK_HEADING)
  expect(declined.text).toContain("The provider did not complete sign-in.")
  expect(declined.text).toContain(`href="/w/${WS}/c/${connect}"`)
  const again = await callbackPage(await f.request(`/oauth/callback?state=${encodeURIComponent(state)}&code=late`, f.alex, undefined, { accept: "text/html" }))
  expect(again).toMatchObject({ status: 400, type: "text/html; charset=utf-8" })
  expect(again.text).toContain("This connection attempt has expired or was already used.")
})

it("a callback with no state or an unknown one answers a page, not JSON", async () => {
  const { f } = await startedConnect()
  for (const query of ["", "?state=unknown-state&code=x"]) {
    const page = await callbackPage(await f.request(`/oauth/callback${query}`, f.alex, undefined, { accept: "text/html" }))
    expect(page).toMatchObject({ status: 400, type: "text/html; charset=utf-8" })
    expect(page.text).toContain(OAUTH_CALLBACK_HEADING)
    expect(page.text).toContain(`href="/"`)
  }
})
