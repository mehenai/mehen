// The account and account setup pages as rendered: the account page apart
// from every workspace, recovery that has not committed, joining from an
// invitation, and creating a workspace only when the account read allows it.
import { describe, expect, it } from "vitest"
import { AccountSessionSchema } from "@mehen/protocol/workspace"
import { renderDocument } from "./layout.ts"
import { workspaceCreatePage } from "./pages/account-setup.ts"
import { pickerPage } from "./pages/workspaces.ts"
import { ACCOUNT_PAGES, accountGallery } from "./account-gallery.ts"
import { PEOPLE_SESSION } from "./people-gallery.ts"
import { GALLERY_ORIGIN } from "./shell-gallery.ts"
import { EMAIL_CODE_LEAD } from "./pages/email-code.ts"

const GALLERY_SCRIPT = Object.values(import.meta.glob<string>("../../scripts/ui-gallery.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""

function page(id: string): string {
  const entry = accountGallery().find((e) => e.id === id)
  if (!entry) throw new Error(`no gallery entry ${id}`)
  return renderDocument(entry.page).value
}

describe("the account gallery", () => {
  it("is registered in the gallery script, with every account page once per id", () => {
    expect(GALLERY_SCRIPT).toContain('import { accountGallery } from "../src/ui/account-gallery.ts"')
    expect(GALLERY_SCRIPT).toContain("...accountGallery(),")
    const entries = accountGallery()
    expect(new Set(entries.map((e) => e.id)).size).toBe(entries.length)
    const pages = new Set(entries.map((e) => e.page.boot.page))
    for (const kind of ACCOUNT_PAGES) expect(pages, kind).toContain(kind)
  })

  it("shows the vault's origin on the account page and never offers Google sign-in or a destructive control", () => {
    const body = page("account")
    expect(body).toContain(GALLERY_ORIGIN)
    expect(body).not.toMatch(/with Google|\/auth\/oidc|data-action="(delete|remove|leave)"/)
  })
})

describe("account setup", () => {
  it("says until recovery completes for an uncommitted recovery, never the sentinel's year", () => {
    const body = page("account-pending-recovery")
    expect(body).toContain("Until recovery completes you can read, deny, narrow and freeze")
    expect(body).not.toMatch(/275760|285616|Invalid Date/)
  })

  it("warns to set up recovery again and keeps workspaces open", () => {
    expect(page("account-recovery-required")).toContain("Set up recovery again")
    expect(page("account-recovery-required")).toContain("Your workspaces stay open meanwhile.")
    expect(page("account-status-fallback")).toContain("2 of 3 workspaces have it so far")
  })

  it("offers creating a workspace only when the account read allows it", () => {
    expect(page("workspaces-create-link")).toContain('href="/workspaces/new"')
    const picker = accountGallery().find((e) => e.id === "workspaces-create-link")
    expect(picker).toBeDefined()
  })

  it("says the operator turned workspace creation off only for an account the operator denied", () => {
    const denied = page("workspaces-new-denied")
    expect(denied).toContain('data-region="create-not-allowed"><p>The operator has turned off workspace creation for this account; ask them, or ask to be invited to a workspace.</p>')
    expect(denied).not.toContain('data-form="workspace-create"')
    const undecided = page("workspaces-new-not-allowed")
    expect(undecided).toContain("This account cannot create workspaces. The deployment&#39;s operator decides who can; ask to be invited to one instead.")
    expect(undecided).not.toContain("turned off")
    const shell = { origin: "https://app.mehen.dev", account: PEOPLE_SESSION.account, name: "Alex", accountPages: ["workspaces" as const, "account" as const] }
    const none = { ...PEOPLE_SESSION, memberships: [] }
    expect(renderDocument(pickerPage(shell, { ...none, workspaceCreation: "operator-denied" }, "https://app.mehen.dev")).value).toContain("The operator has turned off workspace creation for this account")
    expect(renderDocument(pickerPage(shell, none, "https://app.mehen.dev")).value).toContain("ask the operator of this deployment to let your account create one")
  })

  it("leaves the account page's inactive, unlabelled slot for Google verification, no live control", () => {
    const body = page("account-recovery-required")
    expect(body).toMatch(/class="oidc-slot" data-slot="oidc-[a-z-]+" hidden><\/div>/)
    expect(body).not.toMatch(/with Google|\/auth\/oidc/)
  })

  it("offers workspace creation only to an allowed account that is ready", () => {
    for (const [id, region] of [["workspaces-new-not-allowed", "create-not-allowed"]] as const) {
      const body = page(id)
      expect(body).toContain(`data-region="${region}"`)
      expect(body).not.toContain('data-form="workspace-create"')
    }
    expect(page("workspaces-new")).toContain('data-form="workspace-create"')
    const shell = { origin: "https://app.mehen.dev", account: PEOPLE_SESSION.account, name: "Alex", accountPages: ["workspaces" as const, "account" as const] }
    const allowed = { ...PEOPLE_SESSION, canCreateWorkspaces: true }
    const cases = [
      { session: { ...allowed, recoverySetupRequired: true }, region: "create-recovery", link: 'href="/account/recovery"' },
      { session: { ...allowed, restricted: { reason: "recovery" as const, until: null, notice: "ntc_1" } }, region: "create-held", link: null },
      { session: { ...allowed, pendingTransition: { id: "trn_1", reservedEpoch: 2, targets: 1, acknowledged: 0, state: "pending" as const } }, region: "create-held", link: null },
    ]
    for (const c of cases) {
      const body = renderDocument(workspaceCreatePage(shell, c.session)).value
      expect(body).toContain(`data-region="${c.region}"`)
      expect(body).not.toContain('data-form="workspace-create"')
      const picker = renderDocument(pickerPage(shell, c.session, "https://app.mehen.dev")).value
      if (c.link === null) expect(picker).not.toContain('data-region="create-link"')
      else expect(picker).toContain(c.link)
      expect(picker).not.toContain('href="/workspaces/new"')
    }
    expect(renderDocument(pickerPage(shell, PEOPLE_SESSION, "https://app.mehen.dev")).value).not.toContain('data-region="create-link"')
  })

  it("the picker renders a membership, which carries no pending count, as nothing waiting", () => {
    const shell = { origin: "https://app.mehen.dev", account: PEOPLE_SESSION.account, name: "Alex", accountPages: ["workspaces" as const, "account" as const] }
    const [listed] = PEOPLE_SESSION.memberships
    if (listed === undefined) throw new Error("the gallery session lists a membership")
    const absent = AccountSessionSchema.parse(PEOPLE_SESSION)
    expect(absent.memberships[0]).not.toHaveProperty("pending")
    // The field is gone from the protocol: a session that still carries it is refused.
    expect(AccountSessionSchema.safeParse({ ...PEOPLE_SESSION, memberships: [{ ...listed, pending: 9 }] }).success).toBe(false)
    const picker = renderDocument(pickerPage(shell, absent, "https://app.mehen.dev")).value
    expect(picker).toContain("Northwind")
    expect(picker).not.toMatch(/needs? you/)
    expect(picker).not.toContain("undefined")
    expect(picker).not.toContain("NaN")
    // The count comes from the account inbox, never from the membership.
    const inbox = { workspaces: [{ workspace: listed.workspace, role: listed.role, state: "ok" as const, reason: null, count: 2, truncated: false }], items: [], notices: [], count: 2, complete: true }
    const two = renderDocument(pickerPage(shell, PEOPLE_SESSION, "https://app.mehen.dev", inbox)).value
    expect(two).toContain("2 things need you")
  })

  it("/signup names the four steps in the vault's order and keeps the invitation out of every link", () => {
    for (const id of ["signup-step-1", "signup-step-2", "signup-step-3", "signup-step-4", "signup-waiting"]) {
      const body = page(id)
      expect(body.match(/<span class="step-title">([^<]+)<\/span>/g)?.map((t) => t.replace(/<[^>]+>/g, "")), id).toEqual(["Verify your email", "Create your passkey", "Set up recovery", "Join"])
      expect(body, id).toContain("You are invited to <b data-fill=\"workspace-name\">Northwind</b> as <span data-fill=\"invite-role\">a member</span>.")
      expect(body, id).not.toMatch(/\/auth\/oidc|href="[^"]*#/)
    }
    expect(page("signup-step-1")).toContain('data-action="verify-google"')
    expect(page("signup-step-1")).toContain("Google only identifies you, your passkey signs everything.")
    expect(page("signup-step-1-lapsed")).toContain("Your email check has lapsed. Verify again to join.")
    expect(page("signup-step-1")).toMatch(/data-action="verify-google">Verify with Google<[\s\S]*data-region="email-code" hidden>[\s\S]*data-action="email-code-send">Email me a code</)
    expect(page("signup-step-1")).toContain(EMAIL_CODE_LEAD)
    expect(page("signup-step-1")).toMatch(/data-region="email-code-google-only" hidden>This workspace asks for a Google Workspace account for this role, so only Google can verify this invitation.</)
    expect(page("signup-step-1")).toMatch(/data-input="email-code" inputmode="numeric" autocomplete="one-time-code"/)
    expect(page("signup-step-3")).toMatch(/data-action="make-codes">[\s\S]*?Save recovery codes[\s\S]*?data-action="add-second-passkey">Or add a second passkey</)
  })

  it("the wait names the workspace, gives the message to send, and has the retry and session-ended lines", () => {
    const body = page("signup-waiting")
    expect(body).toContain("Waiting for <span data-fill=\"workspace-name\">Northwind</span> to confirm you")
    expect(body).toContain("This page moves on by itself.")
    expect(body).toMatch(/<code>I have joined <span data-fill="workspace-name">Northwind<\/span> on Mehen; please confirm me on the People page.<\/code><button[^>]*data-copy/)
    expect(body).toContain('data-region="confirm-retrying" hidden>Could not check just now; retrying.')
    expect(body).toMatch(/data-region="confirm-ended" hidden>Your session has ended. Sign in to keep waiting. <a [^>]*href="\/signin\?next=%2Fworkspaces"/)
    expect(page("signup-no-invitation")).toContain("Open the invitation link you were sent. Mehen never creates accounts on its own.")
  })

  it("a pending recovery waits honestly, never says the code ran out, and offers no form", () => {
    const body = page("signup-pending-recovery")
    expect(body).toContain("Your code was accepted")
    expect(body).toContain("Do not use another code.")
    expect(body).not.toMatch(/ran out|data-form="recover-passkey"/)
  })
})
