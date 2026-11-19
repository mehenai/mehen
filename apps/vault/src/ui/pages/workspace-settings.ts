// /w/:ws/settings: the workspace's facts, its
// name and short name, and the brake. Controls follow the vault's `rights`
// from GET /api/w/:ws/settings, never the viewer's role: rename and the
// short name need `rights.rename` and a passkey (workspace.update), Freeze
// needs `rights.freeze` and only a confirm step (the brake is cheap on
// purpose), Unfreeze needs `rights.unfreeze` and a passkey. How often Mehen
// asks (the approval dial) is drawn only when the read carries it, its
// choices by `approvals.askLess` and `askMore`; asking less is signed with a
// passkey over both levels, asking more is not. Backups follow
// GET /api/w/:ws/backup/recipients the same way. The write routes keep
// their own guards; hiding a control is never the check.

import { type BackupRecipientView, type BackupStatus, backupIsStale } from "@mehen/protocol/backup"
import { APPROVAL_DIALS, type WorkspaceApprovalsView, type WorkspaceRole, type WorkspaceSettingsView } from "@mehen/protocol/workspace"
import { APPROVAL_DIAL_CHOICES, APPROVAL_DIAL_FROZEN, APPROVAL_DIAL_LABEL, APPROVAL_DIAL_LEAD, APPROVAL_DIAL_READ_ONLY, APPROVAL_DIAL_SAVE, APPROVAL_DIAL_TITLE, APPROVAL_DIAL_WORK_LIMITS, APPROVAL_DIAL_WORK_LIMITS_LABEL } from "../approval-dial-words.ts"
import { cardText, kv, notice, pageHead, pill, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import { type WorkspaceShell, identityLine, workspaceHref } from "../shell.ts"

// `settings` is null when the read was refused or failed; `role` is the
// viewer's own role from the account read, null when that is not served.
// `backups` is null when that read was refused (a guest, a platform-managed
// workspace) or failed: the section is then not drawn.
export type WorkspaceSettingsData = { settings: WorkspaceSettingsView | null; role: WorkspaceRole | null; backups?: BackupStatus | null }

export const BACKUP_WORDS = "A backup key is an age key whose private half lives off every enrolled machine, in a password manager no agent reads and on paper. An owner adds one with a passkey; it can receive exports a day later, and every owner and admin is told when it is added, starts working and is removed. Each export is encrypted by the vault itself, so whoever fetches it, a machine included, gets only ciphertext; stock age -d opens it."

export const FREEZE_CONSEQUENCE = "Every machine in this workspace is refused at once: no credential is used, no request is sent and no run starts. People can still sign in, read and deny. Only an owner can unfreeze it, with a passkey."

// What the vault can do that no page offers yet. Nobody, the operator
// included, does these for a workspace from elsewhere, so the line sends no
// one to ask.
export const ELSEWHERE_WORDS = "Setting the identity rule (which roles must also verify a Google account here), leaving this workspace and deleting it are not in the web app yet."

function activityLink(shell: WorkspaceShell, words: string): Html {
  return shell.pages.includes("audit") ? html`<a href="${workspaceHref(shell.identity.workspace.slug, "/audit")}">${words}</a>` : html`${words}`
}

// Who the workspace is, for a person and for an agent's mehen.toml, and
// where the controls that are not on this page live.
function factsCard(shell: WorkspaceShell, rename: boolean): Html {
  const { workspace, origin } = shell.identity
  return html`<section class="card" data-region="facts"><h2>This workspace</h2>
    <div class="stack">${kv([
      ["Name", cardText(workspace.name)],
      ["Short name", html`<code>${workspace.slug}</code>`],
      [html`Workspace id, for <code>mehen.toml</code>`, html`<code>${workspace.id}</code>`],
      ["Vault", html`<span class="identity-origin">${origin}</span>`],
    ], "facts")}
    <p class="small muted" data-region="slug-how">The short name is in every link and in <code>mehen enrol --workspace</code>. ${rename ? "Change it under Name and short name below; links with the old one still open this workspace." : "Only an owner can change it, or the name."}</p>
    <p class="small muted" data-region="elsewhere">${ELSEWHERE_WORDS}</p></div>
  </section>`
}

// Two forms, each signed with a passkey for the exact new name and short
// name. Owners only, by right; the server checks again.
// The name field starts empty: the facts above show the name spelled, and a
// name holding a hidden character is never put raw into an input.
function renameCard(shell: WorkspaceShell): Html {
  const { workspace } = shell.identity
  return html`<section class="card" data-region="rename"><h2>Name and short name</h2>
    <div class="stack"><form class="stack" data-form="workspace-name" novalidate>
      <label class="field"><span class="label">New name</span><input type="text" data-input="workspace-name" maxlength="64" required autocomplete="off"><span class="hint">What people see. It may repeat another workspace's; the short name never does.</span></label>
      <div class="actions"><button type="submit" class="btn secondary">${icon("passkey")}<span>Rename with passkey</span></button></div>
    </form>
    <form class="stack" data-form="workspace-slug" novalidate>
      <label class="field"><span class="label">Short name</span><input type="text" data-input="workspace-slug" maxlength="40" required autocapitalize="off" autocomplete="off" spellcheck="false" value="${workspace.slug}"><span class="hint">Lower case letters, digits and single dashes; three to forty characters. Agents set up with the old one keep working; tell people the new one for new machines.</span></label>
      <div class="actions"><button type="submit" class="btn secondary">${icon("passkey")}<span>Change short name with passkey</span></button></div>
    </form></div>
  </section>`
}

// Frozen: what that means, and Unfreeze for whoever may (an owner), after
// reading what tripped it.
function frozenCard(shell: WorkspaceShell, unfreeze: boolean): Html {
  const action = unfreeze ? html`<button type="button" class="btn widen" data-action="workspace-unfreeze">${icon("passkey")}<span>Unfreeze with passkey</span></button>` : undefined
  return html`<div id="unfreeze" data-region="frozen">
    ${notice("error", "This workspace is frozen: every machine use is refused.", unfreeze ? html`${activityLink(shell, "Read Activity first")} to see what tripped it; unfreezing lets every machine work again at once.` : html`${activityLink(shell, "See Activity")} for what tripped it. Ask an owner to unfreeze it.`, action)}
  </div>`
}

// The brake, as the quiet outline button; pressing it shows the
// consequence and the one filled confirm. No passkey.
function freezeCard(): Html {
  return html`<section class="card danger-zone" id="freeze" data-region="freeze"><h2>Freeze</h2>
    <p>If an agent or a machine is doing something it should not, freeze the workspace. Anyone here but a guest can.</p>
    <div class="actions" data-region="freeze-start"><button type="button" class="btn danger-quiet" data-action="freeze-start">${icon("snowflake")}<span>Freeze this workspace</span></button></div>
    <div class="stack" data-region="freeze-confirm" hidden>
      <p class="warning">${FREEZE_CONSEQUENCE}</p>
      <div class="actions"><button type="button" class="btn danger" data-action="workspace-freeze">${icon("snowflake")}<span>Freeze now</span></button><button type="button" class="btn quiet" data-action="freeze-cancel">Cancel</button></div>
    </div>
  </section>`
}

// What Let it work does not cover, one line each, on every dial card.
function workLimits(): Html {
  return html`<div class="stack" data-region="approvals-work-limits"><span class="label">${APPROVAL_DIAL_WORK_LIMITS_LABEL}</span>
    <ul class="plain small">${APPROVAL_DIAL_WORK_LIMITS.map((line) => html`<li>${line}</li>`)}</ul></div>`
}

// How often Mehen asks: both levels, the stored one chosen, and a level the
// caller may not move to now shown but not offered. Whoever may move it
// neither way reads the level and who can change it, or, while frozen, that
// it can only ask more often. The line under the
// choices says what a change signs; the client fills it.
function approvalsCard(approvals: WorkspaceApprovalsView, frozen: boolean): Html {
  const current = APPROVAL_DIAL_CHOICES[approvals.level]
  if (!approvals.askLess && !approvals.askMore) {
    return html`<section class="card" id="approvals" data-region="approvals"><h2>${APPROVAL_DIAL_TITLE}</h2>
      <div class="stack"><p data-region="approvals-level">This workspace is set to <b>${current.name}</b>: ${current.words}</p>
      ${workLimits()}
      <p class="small muted" data-region="${frozen ? "approvals-frozen" : "approvals-read-only"}">${frozen ? APPROVAL_DIAL_FROZEN : APPROVAL_DIAL_READ_ONLY}</p></div>
    </section>`
  }
  const at = APPROVAL_DIALS.indexOf(approvals.level)
  const offered = (index: number) => index === at || (index > at ? approvals.askLess : approvals.askMore)
  return html`<section class="card" id="approvals" data-region="approvals" data-level="${approvals.level}"><h2>${APPROVAL_DIAL_TITLE}</h2>
    <div class="stack"><p class="small muted">${APPROVAL_DIAL_LEAD}</p>
    <fieldset class="field" data-region="approvals-levels"><legend class="label">${APPROVAL_DIAL_LABEL}</legend>
      ${APPROVAL_DIALS.map((level, index) => html`<label class="tick"><input type="radio" name="approvals-level" data-input="approvals-level" value="${level}"${level === approvals.level ? html` checked` : ""}${offered(index) ? "" : html` disabled`}><span><b>${APPROVAL_DIAL_CHOICES[level].name}</b> <span class="muted small">${APPROVAL_DIAL_CHOICES[level].words}</span></span></label>`)}
    </fieldset>
    ${workLimits()}
    <p class="small" data-region="approvals-signs" hidden></p>
    <div class="actions"><button type="button" class="btn primary" data-action="approvals-save" disabled>${APPROVAL_DIAL_SAVE}</button></div></div>
  </section>`
}

function recipientRow(r: BackupRecipientView, now: number): Html {
  const state = r.status === "active" ? pill("Active", "ok") : pill("Waiting", "warn")
  const when = r.status === "active" ? html`active since ${timeTag(r.activeAt)}` : html`can receive exports from ${timeTag(r.activeAt)}`
  const last = r.mine ? r.lastExport === null ? html`<p class="small muted" data-region="backup-last">No export yet.</p>` : html`<p class="small muted" data-region="backup-last">Last export ${timeTag(r.lastExport.at)}, ${r.lastExport.items === 1 ? "1 credential" : `${r.lastExport.items} credentials`}${r.changedSince ? `; ${r.changedSince} changed since` : ""}.</p>` : ""
  const stale = r.mine && backupIsStale(r, now) ? notice("warn", r.lastExport === null ? "Nothing has been exported to this key yet." : "The last export is more than a week old and things have changed since.", html`Export now, or run <code>mehen backup export --to &lt;dir&gt;</code> from one of your machines.`) : ""
  const actions = [
    r.rights.export ? html`<button type="button" class="btn secondary" data-action="backup-export" data-recipient="${r.id}">Download an export</button>` : "",
    r.rights.remove ? html`<button type="button" class="btn quiet" data-action="backup-remove" data-recipient="${r.id}">Remove with passkey</button>` : "",
  ]
  return html`<li class="stack" data-recipient="${r.id}"><div><strong>${cardText(r.label)}</strong> ${state} <code>${r.fingerprint}</code></div>
    <p class="small muted">Added by ${cardText(r.registrant.name)} ${timeTag(r.registeredAt)}; ${when}.</p>${last}${stale}
    ${r.rights.export || r.rights.remove ? html`<div class="actions">${actions}</div>` : ""}</li>`
}

// Backup keys: who added each, when it starts working, the last export and
// whether it is stale, for the person who added it; add, remove and
// download as the read's rights say.
function backupCard(backups: BackupStatus): Html {
  const now = Date.parse(backups.now)
  const list = backups.recipients.length === 0 ? html`<p class="small muted" data-region="backup-none">No backup key yet.</p>` : html`<ul class="stack" data-region="backup-recipients">${backups.recipients.map((r) => recipientRow(r, now))}</ul>`
  const add = backups.rights.add ? html`<form class="stack" data-form="backup-add" novalidate>
      <label class="field"><span class="label">Recipient</span><input type="text" data-input="backup-recipient" maxlength="100" required autocapitalize="off" autocomplete="off" spellcheck="false" placeholder="age1..."><span class="hint">The public half, from <code>mehen backup keygen</code> or <code>age-keygen</code> on a machine no agent reaches. X25519 keys only.</span></label>
      <label class="field"><span class="label">Label</span><input type="text" data-input="backup-label" maxlength="64" required autocomplete="off"><span class="hint">Where the private half is kept, for example "1Password and the safe".</span></label>
      <div class="actions"><button type="submit" class="btn widen">${icon("passkey")}<span>Add with passkey</span></button></div>
    </form>` : ""
  return html`<section class="card" id="backups" data-region="backups"><h2>Backups</h2>
    <div class="stack"><p class="small muted">${BACKUP_WORDS}</p>${list}${add}</div>
  </section>`
}

export function workspaceSettingsPage(shell: WorkspaceShell, data: WorkspaceSettingsData): PageInput {
  const base = { title: "Settings", viewer: null, workspace: shell, current: "settings" as const, boot: { page: "workspace-settings" } }
  const head = pageHead({ title: "Settings", lead: html`${identityLine(shell.identity)}: its name, its short name, ${data.settings?.approvals ? "how often it asks, " : ""}its backup keys and the brake.` })
  const settings = data.settings
  if (settings === null) {
    return { ...base, body: html`${head}<section class="card" data-region="settings-unavailable">${notice("warn", "The settings could not be read just now.", "Reload the page to try again. Freezing still works from a machine: mehen freeze.")}</section>` }
  }
  if (data.role === "guest") {
    return { ...base, body: html`${head}${settings.frozen ? frozenCard(shell, false) : ""}<section class="card" data-region="guest"><p>Settings are for the workspace's members. As a guest you have nothing to change here; ask the person who invited you.</p></section>` }
  }
  const { rights } = settings
  return {
    ...base,
    body: html`${head}
      ${settings.frozen ? frozenCard(shell, rights.unfreeze) : ""}
      ${factsCard(shell, rights.rename)}
      ${rights.rename ? renameCard(shell) : ""}
      ${settings.approvals ? approvalsCard(settings.approvals, settings.frozen) : ""}
      ${data.backups ? backupCard(data.backups) : ""}
      ${!settings.frozen && rights.freeze ? freezeCard() : ""}`,
  }
}
