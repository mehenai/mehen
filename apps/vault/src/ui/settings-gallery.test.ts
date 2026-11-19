// The workspace settings page's gallery entries and its rule: controls by
// the read's rights, never by the viewer's role.
import { describe, expect, it } from "vitest"
import { renderDocument } from "./layout.ts"
import { ELSEWHERE_WORDS, workspaceSettingsPage } from "./pages/workspace-settings.ts"
import { SETTINGS_GALLERY_IDS, backupsView, settingsGallery } from "./settings-gallery.ts"
import { APPROVAL_DIAL_WORK_LIMITS, approvalDialSignsWords } from "./approval-dial-words.ts"
import { GALLERY_HOSTILE, GALLERY_MEMBERSHIPS, GALLERY_ORIGIN } from "./shell-gallery.ts"
import type { WorkspaceShell } from "./shell.ts"

const rendered = (id: string) => renderDocument((settingsGallery().find((e) => e.id === id) ?? { page: null }).page ?? (() => { throw new Error(id) })()).value

function shellFor(workspace = GALLERY_HOSTILE.workspace): WorkspaceShell {
  return { identity: { origin: GALLERY_ORIGIN, account: "acc_x", workspace }, accountName: "Alex", memberships: GALLERY_MEMBERSHIPS, pages: ["home", "settings", "audit"], reads: [], accountPages: [], accountHeld: false }
}

describe("the workspace settings gallery", () => {
  it("has every listed state, each a settings page with its boot", () => {
    expect(settingsGallery().map((e) => e.id)).toEqual([...SETTINGS_GALLERY_IDS])
    for (const id of SETTINGS_GALLERY_IDS) expect(rendered(id), id).toContain("&quot;page&quot;:&quot;workspace-settings&quot;")
  })

  it("draws the four rights states as the evaluator answers them", () => {
    const owner = rendered("ws-settings-owner")
    expect(owner).toMatch(/data-form="workspace-name"[\s\S]*data-form="workspace-slug"[\s\S]*data-action="freeze-start"/)
    const member = rendered("ws-settings-member")
    expect(member).not.toContain('data-form="workspace-')
    expect(member).toContain('data-action="freeze-start"')
    expect(rendered("ws-settings-frozen-owner")).toContain('data-action="workspace-unfreeze"')
    const frozenMember = rendered("ws-settings-frozen-member")
    expect(frozenMember).not.toMatch(/data-action="(workspace-unfreeze|freeze-start)"/)
    expect(frozenMember).toContain("Ask an owner to unfreeze it.")
  })
})

describe("the workspace settings page", () => {
  it("says what no page offers yet without sending anyone to ask the operator, who cannot do it either", () => {
    const page = renderDocument((settingsGallery().find((e) => e.id === "ws-settings-owner") as { page: Parameters<typeof renderDocument>[0] }).page).value
    expect(page).toContain(ELSEWHERE_WORDS)
    expect(page).not.toContain("operator")
  })

  it("follows the rights, never the role", () => {
    const shell = shellFor()
    const granted = renderDocument(workspaceSettingsPage(shell, { settings: { frozen: true, rights: { rename: true, freeze: true, unfreeze: true } }, role: "member" })).value
    expect(granted).toContain('data-form="workspace-name"')
    expect(granted).toContain('data-action="workspace-unfreeze"')
    const refused = renderDocument(workspaceSettingsPage(shell, { settings: { frozen: false, rights: { rename: false, freeze: false, unfreeze: false } }, role: "owner" })).value
    expect(refused).not.toMatch(/data-form="workspace-|data-action="(freeze-start|workspace-freeze|workspace-unfreeze)"/)
  })

  it("keeps the confirm step hidden until Freeze is pressed, the filled button only inside it", () => {
    const page = rendered("ws-settings-member")
    const confirm = /data-region="freeze-confirm" hidden>[\s\S]*?<\/div>\s*<\/div>/.exec(page)?.[0] ?? ""
    expect(confirm).toContain('class="btn danger" data-action="workspace-freeze"')
    expect(page.match(/class="btn danger"/g)).toHaveLength(1)
    expect(page).toContain('class="btn danger-quiet" data-action="freeze-start"')
  })

  it("spells a hostile name as text in the facts and never puts it raw into the rename field", () => {
    const page = renderDocument(workspaceSettingsPage(shellFor(), { settings: { frozen: false, rights: { rename: true, freeze: true, unfreeze: true } }, role: "owner" })).value
    expect(page).not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u202a-\u202e]/)
    expect(page).not.toContain("<b>admin</b>")
    expect(page).toContain('<input type="text" data-input="workspace-name" maxlength="64" required autocomplete="off">')
    expect(page).toContain('<mark class="marker">[RLO U+202E]</mark>&quot; &lt;b&gt;admin&lt;/b&gt;')
  })
})

describe("how often Mehen asks on the settings page", () => {
  it("offers both levels by the read's rights, the stored one chosen, and Save only after a change", () => {
    const owner = rendered("ws-settings-owner")
    expect(owner).toContain('data-region="approvals" data-level="writes"')
    expect(owner.match(/data-input="approvals-level" value="(writes|work)"(?! disabled)/g)).toHaveLength(2)
    expect(owner).not.toContain("Ask every time")
    expect(owner).toContain('value="writes" checked')
    expect(owner).toContain('data-region="approvals-signs" hidden></p>')
    expect(owner).toContain('data-action="approvals-save" disabled>Save<')
    for (const name of ["Ask on writes", "Let it work"]) expect(owner).toContain(`<b>${name}</b>`)
    expect(rendered("ws-settings-approvals-work")).toContain('value="work" checked')
  })

  it("says in one line each what Let it work never covers, and that it follows the reviewed templates as they are updated", () => {
    for (const id of ["ws-settings-owner", "ws-settings-member", "ws-settings-approvals-work"]) {
      const page = rendered(id)
      for (const line of APPROVAL_DIAL_WORK_LIMITS) expect(page, id).toContain(`<li>${line.replaceAll("'", "&#39;")}</li>`)
    }
    expect(APPROVAL_DIAL_WORK_LIMITS).toEqual([
      "Protected environments still need a person.",
      "Browser fill still needs a person.",
      "Pushes into other services still need a person.",
      "Machines trust does not reach, such as team machines and guests', are refused, not asked.",
      "It follows Mehen's reviewed service templates as they are updated, without a new passkey.",
    ])
  })

  it("lets an owner frozen at Ask on writes read why it cannot ask less, and frozen at Let it work still ask more", () => {
    const frozen = rendered("ws-settings-frozen-owner")
    expect(frozen).toContain("While the workspace is frozen it can only be set to ask more often.")
    expect(frozen).not.toContain('data-input="approvals-level"')
    const more = rendered("ws-settings-approvals-more")
    expect(more).toContain('value="work" checked')
    expect(more).not.toMatch(/value="writes"[^>]* disabled/)
  })

  it("gives a member the level in a sentence and nothing to press, and draws nothing when the read leaves it out", () => {
    const member = rendered("ws-settings-member")
    expect(member).toContain("This workspace is set to <b>Ask on writes</b>")
    expect(member).toContain("Only an owner or admin can change it.")
    expect(member).not.toMatch(/data-input="approvals-level"|data-action="approvals-save"/)
    const off = rendered("ws-settings-approvals-off")
    expect(off).not.toContain('data-region="approvals"')
    expect(off).not.toContain("how often it asks")
    expect(rendered("ws-settings-owner")).toContain("how often it asks")
  })

  it("says what a change signs, with both levels, or that asking more needs no passkey", () => {
    expect(approvalDialSignsWords("writes", "work", true)).toBe("Your passkey signs this change: from Ask on writes to Let it work.")
    expect(approvalDialSignsWords("work", "writes", false)).toBe("No passkey needed to ask more often: from Let it work to Ask on writes.")
    const swapped = (settingsGallery().find((e) => e.id === "ws-settings-approvals-less")?.swap ?? []).map(([, to]) => to)
    expect(swapped).toContain('data-action="approvals-save">Save with passkey<')
  })
})

describe("the backup keys on the settings page", () => {
  it("draws each key with its state, and the owner's export, stale warning, remove and add as the read's rights say", () => {
    const owner = rendered("ws-settings-backups-owner")
    expect(owner).toContain('data-region="backups"')
    expect(owner).toContain('<code>age177alz07n...gqryyulm</code>')
    expect(owner.match(/data-action="backup-export"/g)).toHaveLength(1)
    expect(owner.match(/data-action="backup-remove"/g)).toHaveLength(2)
    expect(owner).toContain("The last export is more than a week old and things have changed since.")
    expect(owner).toContain("41 credentials; 14 changed since")
    expect(owner).toContain('data-form="backup-add"')
    expect(owner).toMatch(/Waiting[\s\S]*can receive exports from/)
    const admin = rendered("ws-settings-backups-admin")
    expect(admin).toContain("1Password and the safe")
    expect(admin).not.toMatch(/data-action="backup-(export|remove)"|data-form="backup-add"|data-region="backup-last"|week old/)
  })

  it("is not drawn when the read was refused, and a key whose export is fresh carries no warning", () => {
    const shell = shellFor()
    expect(renderDocument(workspaceSettingsPage(shell, { settings: { frozen: false, rights: { rename: true, freeze: true, unfreeze: true } }, role: "owner", backups: null })).value).not.toContain('data-region="backups"')
    const fresh = backupsView("owner")
    fresh.recipients = [{ ...fresh.recipients[0]!, lastExport: { id: "bkx_new", at: "2026-11-09T09:00:00.000Z", items: 41 } }]
    expect(renderDocument(workspaceSettingsPage(shell, { settings: { frozen: false, rights: { rename: true, freeze: true, unfreeze: true } }, role: "owner", backups: fresh })).value).not.toContain("week old")
  })
})
