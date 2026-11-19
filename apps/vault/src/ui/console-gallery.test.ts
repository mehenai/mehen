// The consoles as rendered: the operator's pages offer what the platform's
// status allows, with the slug typed back on every destructive change and
// every key added, and a passkey on every change; a platform admin's pages never offer an
// operator's change; a key made in the browser is never server-rendered;
// hostile strings are spelled; and the console links show only for an
// account that has them.
import { describe, expect, it } from "vitest"
import { SLUG_CONFIRMED_PLATFORM_COMMANDS } from "@mehen/protocol/platform-console"
import { CONSOLE_ACCOUNT_SHELL, CONSOLE_PAGES, consoleGallery } from "./console-gallery.ts"
import { renderDocument } from "./layout.ts"
import { jsonForEditing } from "./pages/platform-admin.ts"
import { GALLERY_ACCOUNT_SHELL } from "./shell-gallery.ts"
import { pickerPage } from "./pages/workspaces.ts"
import { GALLERY_SESSION, GALLERY_ORIGIN } from "./shell-gallery.ts"

const GALLERY_SCRIPT = Object.values(import.meta.glob<string>("../../scripts/ui-gallery.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""

function page(id: string): string {
  const entry = consoleGallery().find((e) => e.id === id)
  if (!entry) throw new Error(`no gallery entry ${id}`)
  return renderDocument(entry.page).value
}

// Each form's markup, by its data-form name.
function form(body: string, name: string): string | null {
  return new RegExp(`<form[^>]*data-form="${name}"[\\s\\S]*?</form>`).exec(body)?.[0] ?? null
}

const forms = (body: string) => [...body.matchAll(/data-form="([a-z-]+)"/g)].map((m) => m[1])

// The page's form name for each command the protocol has the slug typed
// back for.
const SLUG_CONFIRMED_FORMS: Readonly<Record<(typeof SLUG_CONFIRMED_PLATFORM_COMMANDS)[number], string>> = {
  register: "platform-register",
  "rotate-key": "rotate-key",
  suspend: "platform-suspend",
  "revoke-key": "revoke-key",
  "delete-subjects": "delete-subjects",
  retire: "retire",
  remove: "remove",
  "delete-subject": "delete-subject",
}

describe("the console gallery", () => {
  it("is registered in the gallery script, every console page once per id", () => {
    expect(GALLERY_SCRIPT).toContain('import { consoleGallery } from "../src/ui/console-gallery.ts"')
    expect(GALLERY_SCRIPT).toContain("...consoleGallery(),")
    const entries = consoleGallery()
    expect(new Set(entries.map((e) => e.id)).size).toBe(entries.length)
    const pages = new Set(entries.map((e) => e.page.boot.page))
    for (const kind of CONSOLE_PAGES) expect(pages, kind).toContain(kind)
  })
})

describe("the operator's pages", () => {
  it("lists each platform linked by its slug, with Register", () => {
    const body = page("operator-list")
    expect(body).toContain('href="/operator/platforms/globex"')
    expect(body).toContain('href="/operator/register"')
    expect(body).toContain("globex freed")
  })

  it("asks the slug back on every destructive change and every key added, and a passkey on every change", () => {
    const body = page("operator-platform")
    for (const [command, name] of Object.entries(SLUG_CONFIRMED_FORMS)) {
      if (command === "delete-subject" || command === "register") continue
      const markup = form(body, name)
      expect(markup, name).not.toBeNull()
      expect(markup, name).toContain('data-input="confirm"')
      expect(markup, name).toContain("Type <code>globex</code> to confirm")
    }
    const register = form(page("operator-register"), "platform-register")
    expect(register).toContain('data-input="confirm"')
    expect(register).toContain("Type the slug again to confirm")
    // A key added is the platform, and the form says so before the passkey.
    for (const markup of [register, form(body, "rotate-key"), form(page("platform-admin"), "rotate-key")]) expect(markup).toContain("is the platform until the key is revoked")
    for (const name of forms(body)) expect(form(body, name ?? ""), name).toMatch(/with passkey/)
    for (const name of ["platform-resume", "platform-limits", "add-admin"]) {
      const markup = form(page(name === "platform-resume" ? "operator-platform-suspended" : "operator-platform"), name)
      expect(markup, name).not.toBeNull()
      expect(markup, name).not.toContain('data-input="confirm"')
    }
  })

  it("offers what the status allows, as the script plans it", () => {
    const active = forms(page("operator-platform"))
    expect(active).toEqual(expect.arrayContaining(["platform-suspend", "rotate-key", "revoke-key", "platform-limits", "add-admin", "delete-subjects", "retire", "remove"]))
    expect(active).not.toContain("platform-resume")
    const suspended = page("operator-platform-suspended")
    expect(forms(suspended)).toContain("platform-resume")
    expect(forms(suspended)).not.toContain("platform-suspend")
    expect(suspended).toContain('data-region="retire-now"')
    expect(forms(page("operator-platform-retiring"))).toEqual(expect.arrayContaining(["platform-resume", "platform-suspend"]))
    expect(forms(page("operator-platform-retiring"))).not.toContain("retire")
    // Resuming a retiring platform cancels its retirement, and says so first.
    expect(page("operator-platform-retiring")).toContain('data-region="resume-retiring"')
    expect(suspended).not.toContain('data-region="resume-retiring"')
    // A key rotated out says until when it still works.
    expect(page("operator-platform")).toMatch(/Ending<\/span> <span class="small muted">works until <time/)
  })

  it("offers nothing while a platform is being removed or once it is, and says what is kept", () => {
    for (const id of ["operator-platform-removing", "operator-platform-removed"]) {
      expect(forms(page(id)), id).toEqual([])
      expect(page(id), id).toContain('data-region="removal"')
    }
    expect(page("operator-platform-removing")).toContain("frees the slug <code>globex</code>")
    // How long the slug stays taken, so the operator knows when to register it again.
    expect(page("operator-platform-removing")).toContain("with 50 subjects or fewer that is within 30 minutes")
    expect(form(page("operator-platform"), "remove")).toContain("within 30 minutes for 50 subjects or fewer")
    expect(page("operator-platform-removed")).toContain("removed-x7Kq2mP9vR4tLw8zN3bY5cJh")
    expect(form(page("operator-platform"), "remove")).toContain("each subject's tombstone")
  })

  it("never server-renders a private key: the made key's box is empty and no field carries one", () => {
    const body = renderDocument(consoleGallery().find((e) => e.id === "operator-register")!.page).value
    expect(body).toContain('<code data-region="private-key"></code>')
    expect(body).toMatch(/data-region="key-make" hidden/)
    expect(body).not.toMatch(/name="[^"]*private/)
    expect(body).toContain("It is shown once.")
    // Page translation never sends it out, and the clipboard is named.
    expect(body).toMatch(/data-region="key-made" translate="no" hidden/)
    expect(body).toContain("clear your clipboard")
    expect(body).toContain("once the form is accepted")
  })

  it("spells hostile names, reasons and event details, and leaves nested details out", () => {
    const body = page("operator-platform-hostile")
    expect(body).not.toMatch(/<b>name<\/b>|<i>markup<\/i>|<script>x|<b>odd<\/b>/)
    expect(body).toContain('<mark class="marker">')
    expect(body).not.toContain("shown</code>")
  })
})

describe("the Operators view", () => {
  it("offers Approve and Decline on another's proposal, Cancel on your own, and only Decline on one waiting for its target", () => {
    const body = page("operator-operators")
    expect(body).toContain('data-action="approve" data-proposal="opp_4Rt8Yq2Wm6Lk1Nz9"')
    expect(body).not.toContain('data-action="approve" data-proposal="opp_8Hc3Vb5Nm1Qx7Kw2"')
    expect(body).toContain('data-action="cancel" data-proposal="opp_8Hc3Vb5Nm1Qx7Kw2"')
    expect(body).not.toContain('data-action="approve" data-proposal="opp_1Zx9Cv3Bn7Ml5Kj4"')
    expect(body).toContain('data-action="decline" data-proposal="opp_1Zx9Cv3Bn7Ml5Kj4"')
    expect(body).toContain("1 security key")
    expect(forms(body)).toEqual(["grant"])
  })

  it("revokes only others and resigns only you, and with one operator disables both and the grant, saying why", () => {
    const body = page("operator-operators")
    expect(body).toContain(`data-kind="operator.resign" data-target="${CONSOLE_ACCOUNT_SHELL.account}"`)
    expect(body).not.toContain(`data-kind="operator.revoke" data-target="${CONSOLE_ACCOUNT_SHELL.account}"`)
    const alone = page("operator-operators-alone")
    expect(alone).toContain("Needs a second operator; use the script.")
    expect(alone).toMatch(/data-kind="operator.resign"[^>]* disabled title="Mehen needs at least one operator; use the script."/)
    expect(alone).toMatch(/<button type="submit" class="btn secondary" disabled/)
  })

  it("says what an operator's account lacks, yours at the top", () => {
    const body = page("operator-operators-missing")
    expect(body).toContain('data-region="operator-requirements"')
    expect(body).toContain("Your account cannot act as an operator yet: none of its passkeys is a security key.")
    expect(body).toContain("Ravi Okafor&#39;s account cannot act as an operator yet: recovery is not set up.")
  })

  it("puts the acceptance on Your account, disabled while the account lacks something", () => {
    expect(page("account-operator-invitation")).toMatch(/data-action="accept-operator" data-proposal="opp_1Zx9Cv3Bn7Ml5Kj4" data-digest="[^"]+">/)
    expect(page("account-operator-invitation-missing")).toMatch(/data-action="accept-operator"[^>]* disabled>/)
  })
})

describe("the Audit view", () => {
  it("names actor and approver, a proposal's outcome and who decided it, says it is a D1 record, and pages with the filters kept", () => {
    const body = page("operator-audit")
    expect(body).toContain('data-region="audit-record"')
    expect(body).toContain("not a hash chain")
    expect(body).toMatch(/data-event="dpe_a5"[\s\S]*approved by Alex Rae/)
    expect(body).toContain("proposed by Tom Barker <code>acc_7Tn2Qw5Er8Ty1Ui4</code>, approved by Alex Rae")
    expect(body).toContain("declined by Alex Rae")
    expect(body).toMatch(/href="\/operator\/audit\?before=\d+\.dpe_a0" data-region="older"/)
    expect(forms(body)).toEqual(["audit-filters"])
    const filtered = page("operator-audit-filtered")
    expect(filtered).toContain('value="platform."')
    expect(filtered).toContain("Nothing recorded matches")
    expect(page("operator-audit-refused")).toContain("Those filters are not ones this view takes.")
  })
})

describe("the Settings view", () => {
  it("narrows with one passkey and proposes a widening, never offering a value not built or past the ceiling", () => {
    const body = page("operator-settings")
    expect(body).toMatch(/data-action="setting" data-kind="settings.widen" data-key="workspace_creation" data-value="accounts" data-from="operator"[^>]*>/)
    expect(body).not.toMatch(/data-value="accounts"[^>]* disabled/)
    expect(body).toMatch(/data-key="signup_mode" data-value="request"[^>]* disabled title="Not available yet."/)
    expect(body).toContain("<code>SIGNUP_MODE_MAX</code> is <code>open</code>")
    const ceiling = page("operator-settings-ceiling")
    expect(ceiling).toMatch(/data-key="workspace_creation" data-value="accounts"[^>]* disabled title="This deploy allows at most Only accounts an operator allows \(WORKSPACE_CREATION is operator\)/)
    expect(ceiling).toContain("The deploy's ceiling caps it at Only accounts an operator allows.")
    expect(ceiling).toMatch(/data-choice="operator"><span class="row-main"><span class="row-title">Only accounts an operator allows <span[^>]*>in force<\/span>/)
    expect(ceiling).toMatch(/data-kind="settings.narrow" data-key="workspace_creation" data-value="operator" data-label=[^>]*>/)
    expect(ceiling).not.toMatch(/data-kind="settings.narrow"[^>]* disabled/)
  })

  it("alone, disables every widening saying why, still narrows, and warns before narrowing", () => {
    const alone = page("operator-settings-alone")
    expect(alone).toMatch(/data-kind="settings.narrow" data-key="workspace_creation" data-value="operator" data-label=[^>]*>/)
    expect(alone).not.toMatch(/data-kind="settings.narrow"[^>]* disabled/)
    expect(alone).toContain('data-region="alone"')
    expect(alone).toContain("scripts/operator.ts setting")
  })

  it("offers Approve and Decline on another operator's proposal", () => {
    const body = page("operator-settings-open")
    expect(body).toContain('data-action="approve" data-proposal="opp_7Wd3Ns5Kq9Lx2Vb4"')
    expect(body).toContain('data-action="decline" data-proposal="opp_7Wd3Ns5Kq9Lx2Vb4"')
    expect(body).toContain("Widen workspace creation to Every account")
  })
})

describe("the Accounts view", () => {
  it("lists each account linked to its page, with its pills and the next page", () => {
    const body = page("operator-accounts")
    expect(body).toContain('href="/operator/accounts/acc_6Km1Nr3Vt5Yc7Xb2"')
    for (const words of ["operator", "suspended", "cooling off until", "transition pending", "no recovery"]) expect(body, words).toContain(words)
    expect(body).toContain('data-region="next-page"')
    expect(page("operator-accounts-failed")).toContain("The accounts could not be read just now.")
  })

  it("offers workspace creation and suspension with a passkey, and recovering and deleting only with a second operator", () => {
    const body = page("operator-account")
    for (const creation of ["allow", "deny", "default"]) expect(body).toContain(`data-kind="account.workspace_creation" data-creation="${creation}"`)
    expect(body).toMatch(/data-creation="default" disabled title="It follows the default already."/)
    expect(body).toContain('data-kind="account.suspend"')
    expect(form(body, "break-glass")).toContain('data-input="verified"')
    expect(body).toContain('data-region="delete-blocked"')
    expect(forms(body)).not.toContain("delete-account")
    const alone = page("operator-account-deletable")
    expect(form(alone, "delete-account")).toContain('data-input="confirm-name"')
    expect(form(alone, "delete-account")).toMatch(/<button type="submit" class="btn danger" disabled/)
    expect(form(alone, "break-glass")).toContain("Needs a second operator; use the script.")
  })

  it("lifts a suspension, and never suspends, recovers or deletes an operator or your own account", () => {
    expect(page("operator-account-suspended")).toContain('data-kind="account.lift_suspension"')
    const operator = page("operator-account-operator")
    expect(operator).not.toContain('data-kind="account.suspend"')
    expect(forms(operator)).not.toContain("break-glass")
    expect(operator).toContain("access is never recovered here. End their operator role first, or use the script.")
    expect(forms(operator)).not.toContain("delete-account")
    expect(page("operator-account-yours")).not.toContain('data-action="account-propose"')
  })

  it("shows the recovery link's button to its proposer only, the link itself never server-rendered", () => {
    const mine = page("operator-account-link")
    expect(mine).toContain('data-action="break-glass-link"')
    expect(mine).toMatch(/<code data-region="link"><\/code>/)
    expect(page("operator-account-link-theirs")).not.toContain('data-action="break-glass-link"')
  })
})

describe("a platform admin's pages", () => {
  it("never offers an operator's change, and reads status and limits only", () => {
    const body = page("platform-admin")
    expect(forms(body).sort()).toEqual(["defaults", "delete-subject", "revoke-key", "rotate-key"])
    expect(body).not.toContain("/operator")
    expect(body).toContain("Only Mehen's operator changes these.")
  })

  it("asks the slug back for adding or revoking a key and deleting a subject", () => {
    const body = page("platform-admin")
    for (const name of ["rotate-key", "revoke-key", "delete-subject"]) expect(form(body, name), name).toContain('data-input="confirm"')
    expect(form(body, "delete-subject")).toContain('data-input="subject"')
  })

  it("keeps the last live key: no revoke form, and why", () => {
    const body = page("platform-admin-last-key")
    expect(forms(body)).not.toContain("revoke-key")
    expect(body).toContain('data-region="last-key"')
  })

  it("offers nothing on a retired platform", () => {
    expect(forms(page("platform-admin-retired"))).toEqual([])
  })

  it("puts the defaults into the editor with every hidden character escaped", () => {
    expect(jsonForEditing({ tags: ["a\u202eb"] })).toBe('{\n  "tags": [\n    "a\\u202eb"\n  ]\n}')
    expect(page("platform-admin")).toContain("&quot;templates&quot;")
  })
})

describe("the console links", () => {
  it("show Operator and Platforms only for an account that has them", () => {
    const withConsoles = renderDocument(pickerPage(CONSOLE_ACCOUNT_SHELL, GALLERY_SESSION, GALLERY_ORIGIN)).value
    expect(withConsoles).toContain('href="/operator"')
    expect(withConsoles).toContain('href="/platforms"')
    const plain = renderDocument(pickerPage(GALLERY_ACCOUNT_SHELL, GALLERY_SESSION, GALLERY_ORIGIN)).value
    expect(plain).not.toContain('href="/operator"')
    expect(plain).not.toContain('href="/platforms"')
    const rail = page("console-links-workspace")
    expect(rail.match(/href="\/operator"/g)?.length ?? 0).toBeGreaterThanOrEqual(2)
  })
})
