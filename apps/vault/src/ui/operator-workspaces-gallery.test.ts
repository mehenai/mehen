// The Workspaces view as rendered: every workspace linked to its page, the
// filters and search kept in the address; one workspace with the runbook's
// checklist before any restore, the workspace id typed back and a passkey
// on every change, a restore disabled for the only operator, no Freeze on
// a frozen or unread workspace, and never an Unfreeze.
import { describe, expect, it } from "vitest"
import { NEEDS_SECOND_OPERATOR_WORDS } from "@mehen/protocol/operator-proposals"
import { consoleGallery } from "./console-gallery.ts"
import { renderDocument } from "./layout.ts"

function page(id: string): string {
  const entry = consoleGallery().find((e) => e.id === id)
  if (!entry) throw new Error(`no gallery entry ${id}`)
  return renderDocument(entry.page).value
}

function form(body: string, name: string): string | null {
  return new RegExp(`<form[^>]*data-form="${name}"[\\s\\S]*?</form>`).exec(body)?.[0] ?? null
}

const forms = (body: string) => [...body.matchAll(/data-form="([a-z-]+)"/g)].map((m) => m[1])

describe("the Workspaces list", () => {
  it("links each workspace to its page, spells a hostile name and offers the next page", () => {
    const body = page("operator-workspaces")
    for (const id of ["tn_Northwind8Qw2", "tn_Northwind4Lk9", "tn_Fernhill7Bv3x", "tn_Personal2Zx5"]) expect(body).toContain(`href="/operator/workspaces/${id}"`)
    expect(body).toContain("Fernhill &amp; Co &lt;script&gt;")
    expect(body).not.toContain("Co <script>")
    expect(body).toContain('href="/operator/workspaces?before=eyJhdCI6MSwiaWQiOiJ0bl94In0"')
    expect(body).toContain("owners not read")
    expect(forms(body)).toEqual(["workspace-search"])
  })

  it("keeps the search in each filter and marks the current one", () => {
    const body = page("operator-workspaces-searched")
    expect(body).toContain('<a class="chip" href="/operator/workspaces?q=acme&amp;filter=active" aria-current="page">Active</a>')
    expect(body).toContain('href="/operator/workspaces?q=acme"')
    expect(body).toContain('<input type="hidden" name="filter" value="active">')
    expect(body).toContain("Nothing matches")
  })

  it("lists a platform's workspaces by platform, linked to the platform", () => {
    const body = page("operator-workspaces-managed")
    expect(body).toContain('href="/operator/platforms/globex"')
    expect(body).not.toContain('href="/operator/workspaces/tn_Managed')
  })

  it("says plainly when the list could not be read", () => {
    expect(page("operator-workspaces-failed")).not.toContain('data-region="workspaces"')
  })
})

describe("one workspace", () => {
  it("shows the runbook's checklist before both restore forms, each with the id typed back and a passkey", () => {
    const body = page("operator-workspace")
    const checklist = body.indexOf('data-region="restore-checklist"')
    expect(checklist).toBeGreaterThan(-1)
    expect(checklist).toBeLessThan(body.indexOf('data-form="restore-pitr"'))
    for (const step of ["Freeze it first", "save the audit tail", "re-apply"]) expect(body).toContain(step)
    for (const name of ["restore-pitr", "restore-dump"]) {
      const markup = form(body, name)
      expect(markup, name).toContain("Type <code>tn_Northwind8Qw2</code> to confirm")
      expect(markup, name).toContain("Propose with passkey")
      expect(markup, name).not.toContain("disabled")
    }
    expect(form(body, "restore-dump")).toContain('<option value="2026-09-01">')
    expect(form(body, "freeze")).toContain("Freeze with passkey")
    expect(body).toContain("leaves no record here")
  })

  it("never offers unfreeze, nor anything inside the workspace", () => {
    for (const id of ["operator-workspace", "operator-workspace-frozen", "operator-workspace-alone", "operator-workspace-unread"]) {
      const body = page(id)
      expect(forms(body).filter((name) => !["freeze", "restore-pitr", "restore-dump"].includes(name ?? "")), id).toEqual([])
      expect(body, id).not.toMatch(/data-form="unfreeze"|Unfreeze with|credential\.(use|reveal)/)
    }
  })

  it("offers no Freeze on a frozen workspace, and points a waiting restore to Operators instead of a second form", () => {
    const body = page("operator-workspace-frozen")
    expect(forms(body)).toEqual([])
    expect(body).toContain('data-region="frozen-already"')
    expect(body).toContain('data-region="restore-open"')
    expect(body).toContain('href="/operator/operators"')
    expect(body).toContain('data-region="backup-failure"')
  })

  it("disables restoring for the only operator, saying so, and still offers Freeze", () => {
    const body = page("operator-workspace-alone")
    expect(body).toContain(NEEDS_SECOND_OPERATOR_WORDS.change)
    expect(form(body, "restore-pitr")).toContain("disabled")
    expect(form(body, "freeze")).not.toBeNull()
  })

  it("offers no Freeze when the object did not answer whether it is frozen", () => {
    const body = page("operator-workspace-unread")
    expect(form(body, "freeze")).toBeNull()
    expect(body).toContain('data-region="no-dumps"')
    expect(body).toContain("could not be read")
  })
})
