// Not now on the home's nudge lines in the browser path: the home the
// server renders (the gallery's workspace-home-nudges), run in
// test/mini-dom.ts with the production initNudges wiring it. Not now posts
// nudge-quiet with no passkey and the line goes, the card with its last
// line; a refusal keeps the line and says why.
import { afterEach, expect, it } from "vitest"
import { renderDocument } from "../src/ui/layout.ts"
import { shellGallery } from "../src/ui/shell-gallery.ts"
import { initNudges } from "../src/ui/client/pages/nudges.ts"
import { ShellState } from "../src/ui/client/shell-logic.ts"
import { GALLERY_WORKSPACE } from "../src/ui/workspace-projects-gallery.ts"
import { type MiniBrowser, installPage, settle } from "./mini-dom.ts"

let browser: MiniBrowser | null = null
afterEach(() => {
  browser?.restore()
  browser = null
})

function open(respond: MiniBrowser["respond"]): MiniBrowser {
  const entry = shellGallery().find((e) => e.id === "workspace-home-nudges")!
  browser = installPage(renderDocument(entry.page).value, respond)
  const workspace = (entry.page.workspace as { identity: { workspace: typeof GALLERY_WORKSPACE } }).identity.workspace
  initNudges(new ShellState({ origin: "https://vault.test", account: "acc_4Hq9Tz2Lm7Vb1Nc8", workspace, pages: [], reads: [] }))
  return browser
}
const notNow = (b: MiniBrowser, slug: string) => b.document.querySelector(`[data-action="nudge-quiet"][data-slug="${slug}"]`)!

it("quietens a line with no passkey, then the card once its last line goes", async () => {
  const b = open(() => ({ status: 200, body: {} }))
  notNow(b, "github-work").click()
  await settle()
  expect(b.calls).toEqual([{ path: expect.stringMatching(/^\/api\/w\/[a-z0-9-]+\/items\/github-work\/nudge-quiet$/), body: {} }])
  expect(b.document.querySelector('[data-region="nudge"][data-slug="github-work"]')).toBeNull()
  expect(b.document.querySelector('[data-region="home-nudges"]')).not.toBeNull()
  notNow(b, "cloudflare-api-token-local-secrets-2").click()
  await settle()
  expect(b.document.querySelector('[data-region="home-nudges"]')).toBeNull()
})

it("keeps the line and says why when the vault refuses", async () => {
  const b = open(() => ({ status: 403, body: { error: "forbidden", message: "How careful a credential is cannot be set here yet." } }))
  notNow(b, "github-work").click()
  await settle()
  expect(b.document.querySelector('[data-region="nudge"][data-slug="github-work"]')).not.toBeNull()
  expect(b.document.querySelector("#notice")!.textContent).toContain("How careful a credential is cannot be set here yet.")
})
