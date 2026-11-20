// The workspace project and credential pages, and Needs you, in the
// browser: their forms and buttons (the ask pages are workspace-asks.ts).
// Every change is signed through workspace-sign.ts, which refuses before
// the passkey unless the vault's action is the one this page rebuilt from
// what it showed and the workspace and credential are still the ones shown.
// Calls go through workspaceApi, so a stale tab sends nothing.

import { canonicalJson } from "@mehen/protocol/canonical-json"
import type { ApiError } from "@mehen/protocol/api"
import { ORIGIN_LIST_MAX } from "@mehen/protocol/fill"
import type { CredentialHome, EnvironmentState, ShareSubject } from "@mehen/protocol/workspace"
import { VaultFailure, workspaceApi } from "../api.ts"
import { type Boot, all, clearNotice, el, find, must, showInfo, showProblems, withBusy } from "../dom.ts"
import { parseFences } from "../logic.ts"
import type { ShellState } from "../shell-logic.ts"
import { initPushControls } from "./push-credential.ts"
import {
  type NewEnvironment,
  type OverrideSource,
  type ProjectChange,
  type ShareTerms,
  type ShownItem,
  type VariableSource,
  type WebPages,
  createdAskPath,
  credentialStart,
  environmentChange,
  homeFromValue,
  itemChangedRefusal,
  itemDeleteAction,
  itemUpdateAction,
  itemRehomeAction,
  itemRestoreAction,
  itemRestoreRefusal,
  nameRefusalWords,
  overrideChange,
  projectCreate,
  projectDelete,
  purgeMatches,
  remoteChange,
  rotationStart,
  sameAction,
  shareChange,
  shareEndChangeWords,
  shareEndDay,
  shareFormTerms,
  variableChange,
  webPageOrigin,
  webPagesChange,
} from "../workspace-logic.ts"
import { WEB_PAGES_AT_MOST, WEB_PAGE_HTTPS_ONLY } from "../../wording.ts"
import { signed } from "../workspace-sign.ts"
import { initList } from "./manage.ts"
import { initPolicyRules } from "./policy-rules.ts"
import { initPostureCard } from "./posture.ts"

async function projectSigned(shell: ShellState, change: ProjectChange): Promise<unknown> {
  const expected = await change.expected
  return signed(shell, { prepare: { path: "/projects/action", body: { change: change.change, input: change.input } }, matches: (a) => sameAction(expected, a), mutation: { path: change.path, body: change.input } })
}

export function onClick(selector: string, waiting: string, action: (button: HTMLButtonElement) => Promise<void>, root: ParentNode = document): void {
  for (const button of all<HTMLButtonElement>(selector, root)) button.addEventListener("click", () => void withBusy(button, waiting, () => action(button)))
}

function value(selector: string, root: ParentNode): string {
  return find<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(selector, root)?.value.trim() ?? ""
}

function checked(selector: string, root: ParentNode): boolean | null {
  const box = find<HTMLInputElement>(selector, root)
  return box === null ? null : box.checked
}

export function needShell(shell: ShellState | null): ShellState {
  if (shell === null) throw new Error("This page has no workspace.")
  return shell
}

// ---------------------------------------------------------------- projects

export function initWorkspaceProjects(_boot: Boot, maybe: ShellState | null): void {
  initList()
  const shell = needShell(maybe)
  const form = find('[data-form="create-project"]')
  if (form === null) return
  onClick('[data-action="create-project"]', "Waiting for your passkey...", async () => {
    const envs: NewEnvironment[] = [{ name: "dev", protected: false, fourEyes: false }]
    if (checked('[data-env="staging"]', form) === true) envs.push({ name: "staging", protected: false, fourEyes: false })
    envs.push({ name: "prod", protected: true, fourEyes: checked('[data-input="prod-four-eyes"]', form) === true })
    const built = projectCreate(value('[data-input="slug"]', form), value('[data-input="remote"]', form), envs, "dev")
    if (!built.ok) return showProblems(built.problems)
    try {
      const created = (await projectSigned(shell, built.value)) as { id: string }
      location.assign(`/w/${encodeURIComponent(shell.identity.workspace.slug)}/projects/${encodeURIComponent(created.id)}`)
    } catch (error) {
      const words = error instanceof VaultFailure ? nameRefusalWords(error.body) : null
      if (words !== null) return showProblems([words])
      throw error
    }
  }, form)
}

type ProjectBoot = {
  project: { id: string; slug: string }
  environments: { name: string; protected: boolean; fences: string[]; fourEyes: boolean }[]
  vars: { env: string; name: string; item: string | null; field: string | null; plain?: string }[]
  shares: { subject: ShareSubject; level: ShareTerms["level"]; protected: boolean; expiresAt: string | null }[]
  guests: string[]
}

// The variable's source as the page showed it, the before-state its change
// is checked against: a credential, a plain value, or nothing.
function liveSource(boot: ProjectBoot, env: string, name: string): VariableSource {
  const v = boot.vars.find((x) => x.env === env && x.name === name)
  if (v === undefined) return null
  if (v.item !== null) return { kind: "item", item: v.item, field: v.field ?? "" }
  return v.plain !== undefined ? { kind: "plain", value: v.plain } : null
}

export function initWorkspaceProject(raw: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  const boot = raw as unknown as ProjectBoot
  const project = boot.project.id
  const done = () => location.reload()

  for (const form of all('[data-form="environment"]')) {
    const name = form.dataset.env ?? ""
    const env = boot.environments.find((e) => e.name === name)
    if (env === undefined) continue
    const before: EnvironmentState = { protected: env.protected, fences: env.fences, fourEyes: env.fourEyes }
    onClick('[data-action="save-environment"]', "Waiting for your passkey...", async () => {
      const protect = checked('[data-input="protected"]', form)
      const fourEyes = checked('[data-input="four-eyes"]', form)
      const fences = find('[data-input="fences"]', form) === null ? env.fences : parseFences(value('[data-input="fences"]', form))
      const after: EnvironmentState = { protected: protect ?? env.protected, fourEyes: fourEyes ?? env.fourEyes, fences }
      await projectSigned(shell, environmentChange(project, name, before, after))
      done()
    }, form)
  }

  for (const form of all('[data-form="var"]')) {
    const env = form.dataset.env ?? ""
    onClick('[data-action="set-var"]', "Waiting for your passkey...", async () => {
      const name = value('[data-input="name"]', form)
      const item = value('[data-input="item"]', form)
      const plain = value('[data-input="plain"]', form)
      if (!/^[A-Z_][A-Z0-9_]*$/.test(name)) return showProblems(["Name the variable in capitals, digits and underscores."])
      if (item !== "" && plain !== "") return showProblems(["Choose a credential or a plain value, not both."])
      const after: VariableSource = item !== "" ? { kind: "item", item, field: value('[data-input="field"]', form) } : plain !== "" ? { kind: "plain", value: plain } : null
      await projectSigned(shell, variableChange(project, env, name, liveSource(boot, env, name), after))
      done()
    }, form)
  }

  // "Use my own": the caller's own override, signed like any change.
  const own = async (env: string, variable: string, source: OverrideSource) => {
    const change = overrideChange(project, env, variable, source)
    await signed(shell, { prepare: { path: `${change.path}/action`, body: change.body }, matches: change.matches, mutation: { path: change.path, body: change.body } })
    done()
  }
  for (const form of all('[data-form="own"]')) {
    onClick('[data-action="use-own"]', "Waiting for your passkey...", async () => {
      const item = value('[data-input="item"]', form)
      const plain = value('[data-input="plain"]', form)
      if ((item === "") === (plain === "")) return showProblems(["Choose one of your own credentials or a plain value."])
      const field = value('[data-input="field"]', form)
      if (item !== "" && field === "") return showProblems(["Name the credential's field, as in key."])
      await own(form.dataset.env ?? "", form.dataset.var ?? "", item !== "" ? { kind: "item", item, field } : { kind: "plain", value: plain })
    }, form)
  }
  onClick('[data-action="clear-own"]', "Waiting for your passkey...", (button) => own(button.dataset.env ?? "", button.dataset.var ?? "", null))

  const share = find('[data-form="share"]')
  if (share !== null) {
    const subject = must<HTMLSelectElement>('[data-input="subject"]', share)
    const level = must<HTMLSelectElement>('[data-input="level"]', share)
    const tick = find('[data-region="protected-tick"]', share)
    const reach = find('[data-region="guest-reach"]', share)
    const teamReach = find('[data-region="team-reach"]', share)
    const protect = find<HTMLInputElement>('[data-input="protected"]', share)
    const ends = must<HTMLInputElement>('[data-input="ends"]', share)
    const endChange = find('[data-region="share-end-change"]', share)
    // The chosen subject: a person or a team, by the option's own kind.
    const chosen = (): ShareSubject | null => {
      const option = subject.selectedOptions[0]
      if (option === undefined || subject.value === "") return null
      return option.dataset.kind === "team" ? { kind: "team", team: subject.value } : { kind: "member", member: subject.value }
    }
    const current = (who: ShareSubject | null): ShareTerms | null => {
      const old = who === null ? undefined : boot.shares.find((s) => canonicalJson(s.subject) === canonicalJson(who))
      return old === undefined ? null : { level: old.level, protected: old.protected, expiresAt: old.expiresAt }
    }
    const terms = () => shareFormTerms(current(chosen()), { level: level.value as ShareTerms["level"], protected: protect?.checked === true, ends: ends.value }, Date.now())
    // The form starts from the chosen subject's current terms, its end included.
    const prefill = () => {
      const before = current(chosen())
      level.value = before?.level ?? "use"
      if (protect) protect.checked = before?.protected ?? false
      ends.value = shareEndDay(before?.expiresAt ?? null)
    }
    const sayEnd = () => {
      const built = terms()
      const words = built.ok ? shareEndChangeWords(current(chosen()), built.value) : null
      if (endChange === null) return
      endChange.textContent = words ?? ""
      endChange.hidden = words === null
    }
    const refresh = () => {
      const who = chosen()
      const guest = who?.kind === "member" && boot.guests.includes(who.member)
      for (const option of Array.from(level.options)) if (option.value === "manage") option.disabled = guest
      if (guest && level.value === "manage") level.value = "edit"
      if (tick) tick.hidden = level.value === "manage"
      if (reach) reach.hidden = !guest
      if (teamReach) teamReach.hidden = who?.kind !== "team"
    }
    // A share request's member (?share=): until the person changes the
    // choice themselves, Share signs for that member or for no one.
    const requested = share.dataset.requested ?? null
    let chosenByPerson = false
    subject.addEventListener("change", () => {
      chosenByPerson = true
      prefill()
      refresh()
      sayEnd()
    })
    level.addEventListener("change", refresh)
    ends.addEventListener("input", sayEnd)
    ends.addEventListener("change", sayEnd)
    prefill()
    refresh()
    sayEnd()
    onClick('[data-action="share"]', "Waiting for your passkey...", async () => {
      const who = chosen()
      if (who === null) return showProblems(["Choose who to share with."])
      if (requested !== null && !chosenByPerson && !(who.kind === "member" && who.member === requested)) return showProblems(["Choose who to share with."])
      const built = terms()
      if (!built.ok) return showProblems(built.problems)
      sayEnd()
      await projectSigned(shell, shareChange(project, who, current(who), built.value))
      done()
    }, share)
  }
  onClick('[data-action="unshare"]', "Waiting for your passkey...", async (button) => {
    const who = JSON.parse(button.dataset.subject ?? "null") as ShareSubject | null
    const old = boot.shares.find((s) => canonicalJson(s.subject) === canonicalJson(who))
    if (who === null || old === undefined) return showProblems(["Reload the page: this share has changed."])
    await projectSigned(shell, shareChange(project, who, { level: old.level, protected: old.protected, expiresAt: old.expiresAt }, null))
    done()
  })

  const remote = find('[data-form="remote"]')
  if (remote !== null) {
    onClick('[data-action="bind-remote"]', "Waiting for your passkey...", async () => {
      const change = remoteChange(project, value('[data-input="remote"]', remote), true)
      if (change === null) return showProblems(["That is not a git remote."])
      showInfo(`Binding ${String(change.input.remote)}`)
      await projectSigned(shell, change)
      done()
    }, remote)
  }
  onClick('[data-action="unbind-remote"]', "Waiting for your passkey...", async (button) => {
    const change = remoteChange(project, button.dataset.remote ?? "", false)
    if (change === null) return showProblems(["That is not a git remote."])
    await projectSigned(shell, change)
    done()
  })
  onClick('[data-action="delete-project"]', "Waiting for your passkey...", async () => {
    await projectSigned(shell, projectDelete(project))
    location.assign(`/w/${encodeURIComponent(shell.identity.workspace.slug)}/projects`)
  })
}

// ---------------------------------------------------------------- credentials

export function askPage(shell: ShellState, path: "/intakes" | "/connect", id: string): string {
  return `/w/${encodeURIComponent(shell.identity.workspace.slug)}/${path === "/intakes" ? "i" : "c"}/${encodeURIComponent(id)}`
}

// The add sheet: the page head's button opens it; the close button, a click on the scrim and Escape close it and
// give focus back to the button. Tab stays inside it while it is open.
function initAddSheet(): void {
  const sheet = find('[data-region="add-credential"]')
  const opener = find<HTMLButtonElement>('[data-action="open-add"]')
  if (sheet === null || opener === null) return
  sheet.addEventListener("keydown", (event) => {
    if (event.key !== "Tab" || sheet.hidden) return
    const controls = all<HTMLElement>("input, select, textarea, button", sheet).filter((c) => !(c as HTMLInputElement).disabled)
    const first = controls[0]
    const last = controls[controls.length - 1]
    if (first === undefined || last === undefined) return
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first.focus()
    }
  })
  const sheetNotice = find('[data-region="sheet-notice"]', sheet)
  const open = () => {
    if (sheetNotice !== null) clearNotice(sheetNotice)
    sheet.hidden = false
    document.body.classList.add("sheet-open")
    find<HTMLSelectElement>('[data-input="provider"]', sheet)?.focus()
  }
  const close = () => {
    if (sheet.hidden) return
    sheet.hidden = true
    document.body.classList.remove("sheet-open")
    opener.focus()
  }
  opener.addEventListener("click", open)
  sheet.addEventListener("click", (event) => {
    const target = event.target as HTMLElement
    if (target === sheet || target.closest('[data-action="close-sheet"]') !== null) close()
  })
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") close()
  })
}

export function initWorkspaceCredentials(raw: Boot, maybe: ShellState | null): void {
  initList()
  initAddSheet()
  const shell = needShell(maybe)
  const member = String(raw.member ?? "")
  const form = find('[data-form="add-credential"]')
  if (form !== null) {
    // The sheet's own notice; the fields keep what was typed so it can be corrected.
    const sheetNotice = must('[data-region="sheet-notice"]', form)
    const select = must<HTMLSelectElement>('[data-input="provider"]', form)
    const customRegion = find<HTMLElement>('[data-region="custom-host"]', form)
    const syncCustom = () => {
      if (customRegion !== null) customRegion.hidden = select.selectedOptions[0]?.dataset.way !== "custom-host"
    }
    select.addEventListener("change", syncCustom)
    syncCustom()
    const button = must<HTMLButtonElement>('[data-action="add-credential"]', form)
    button.addEventListener("click", () => void withBusy(button, "Starting...", async () => {
      const rawWay = select.selectedOptions[0]?.dataset.way
      const way = rawWay === "connect" || rawWay === "custom-host" || rawWay === "lease" ? rawWay : "intake"
      const home = homeFromValue(find<HTMLInputElement>('[data-input="home"]:checked', form)?.value ?? "", member)
      const slug = value('[data-input="slug"]', form)
      const host = value('[data-input="host"]', form)
      const header = value('[data-input="header"]', form)
      if (home === null || slug === "") return showProblems(["Name the credential and choose where it belongs."], sheetNotice)
      if (way === "custom-host" && host === "") return showProblems(["Enter the destination host this key may be sent to, such as api.example.com."], sheetNotice)
      const start = credentialStart(select.value, way, slug, home, { host, header })
      try {
        const created = await workspaceApi<{ intake?: string | { intake: string }; connect?: string }>(shell, start.path, start.body)
        const next = createdAskPath(shell.identity.workspace.slug, created)
        if (next !== null) location.assign(next)
      } catch (error) {
        const words = error instanceof VaultFailure ? nameRefusalWords(error.body) : null
        if (words !== null) return showProblems([words], sheetNotice)
        throw error
      }
    }, sheetNotice))
  }
  const purge = find('[data-form="purge"]')
  if (purge !== null) {
    onClick('[data-action="purge"]', "Waiting for your passkey...", async () => {
      const slug = value('[data-input="slug"]', purge)
      if (slug === "") return showProblems(["Type the credential's name."])
      const path = `/items/${encodeURIComponent(slug)}`
      await signed(shell, { prepare: { path: `${path}/action`, body: { action: "delete" } }, matches: purgeMatches, mutation: { path: `${path}/delete`, body: {} } })
      showInfo("Removed.")
      must<HTMLInputElement>('[data-input="slug"]', purge).value = ""
    }, purge)
  }
}

export function initWorkspaceCredential(raw: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  const slug = String(raw.slug ?? "")
  const home = raw.home as CredentialHome
  const shown: ShownItem = { id: String(raw.id ?? ""), kind: String(raw.kind ?? ""), version: Number(raw.version), configRevision: Number(raw.configRevision), dependencyRevision: Number(raw.dependencyRevision) }
  const path = `/items/${encodeURIComponent(slug)}`
  const member = home.kind === "member" ? home.member : ""
  // Read again just before signing: the page signs only for the credential
  // it showed, never a replacement under the same name or a changed one.
  const stillShown = async () => itemChangedRefusal(shown, await workspaceApi<Partial<ShownItem>>(shell, path))
  onClick('[data-action="rotate"]', "Starting...", async (button) => {
    const start = rotationStart(slug, home, button.dataset.starts === "connect" ? (button.dataset.provider ?? null) : null)
    const created = await workspaceApi<{ intake?: string | { intake: string }; connect?: string }>(shell, start.path, start.body)
    const next = createdAskPath(shell.identity.workspace.slug, created)
    if (next !== null) location.assign(next)
  })
  const rehome = find('[data-form="rehome"]')
  if (rehome !== null) {
    onClick('[data-action="rehome"]', "Waiting for your passkey...", async () => {
      const to = homeFromValue(find<HTMLInputElement>('[data-input="rehome"]:checked', rehome)?.value ?? "", member)
      if (to === null) return showProblems(["Choose where it belongs."])
      const expected = itemRehomeAction(shown, home, to)
      await signed(shell, { prepare: { path: `${path}/action`, body: { action: "rehome", home: to } }, matches: (a) => sameAction(expected, a), stillShown, mutation: { path: `${path}/rehome`, body: { home: to } } })
      location.reload()
    }, rehome)
  }
  const previous = typeof raw.previous === "number" ? raw.previous : null
  if (previous !== null) {
    onClick('[data-action="restore"]', "Waiting for your passkey...", async () => {
      const expected = await itemRestoreAction(shown, previous)
      const terms = { version: shown.version, previous }
      const unchanged = async () => itemRestoreRefusal(shown, previous, await workspaceApi<Partial<ShownItem> & { previous?: { version: number } | null }>(shell, path))
      await signed(shell, { prepare: { path: `${path}/action`, body: { action: "restore", ...terms } }, matches: (a) => sameAction(expected, a), stillShown: unchanged, mutation: { path: `${path}/restore`, body: terms } })
      location.reload()
    })
  }
  if (raw.web !== undefined) initWebPages(shell, raw.web as WebPages, shown, path, stillShown)
  onClick('[data-action="delete"]', "Waiting for your passkey...", async () => {
    const expected = itemDeleteAction(shown)
    await signed(shell, { prepare: { path: `${path}/action`, body: { action: "delete" } }, matches: (a) => sameAction(expected, a), stillShown, mutation: { path: `${path}/delete`, body: {} } })
    location.assign(`/w/${encodeURIComponent(shell.identity.workspace.slug)}/credentials`)
  })
  initPostureCard(shell)
  initPushControls(shell, shown, path, stillShown)
  initPolicyRules(shell)
}

// A row as the server renders it (pages/workspace-credentials.ts webPageRow).
function webPageNode(origin: string, sub: string | null, remove: string): HTMLElement {
  const row = el("li", "row")
  row.setAttribute("data-origin", origin)
  const main = el("span", "row-main")
  const title = el("span", "row-title")
  title.append(el("code", null, origin))
  main.append(title)
  if (sub !== null) main.append(el("span", "row-sub", sub))
  const side = el("span", "row-side")
  const button = el("button", "btn danger-quiet sm", "Remove")
  button.setAttribute("type", "button")
  button.setAttribute("data-action", remove)
  button.setAttribute("data-origin", origin)
  side.append(button)
  row.append(main, side)
  return row
}

// The In web pages card: the ceiling's choice, the sign-in pages a person
// added and the pages of other services, edited here and saved together
// through item.update, signing only what changed.
function initWebPages(shell: ShellState, shown: WebPages, item: ShownItem, path: string, stillShown: () => Promise<ApiError | null>): void {
  const card = must('[data-region="in-web-pages"]')
  const save = must<HTMLButtonElement>('[data-action="save-web-pages"]', card)
  const now: WebPages = { ceiling: shown.ceiling, signinOrigins: [...shown.signinOrigins], typeInto: [...shown.typeInto] }
  const change = () => webPagesChange(shown, now)
  const refresh = () => {
    save.disabled = change() === null
    const signinNone = find('[data-region="signin-pages-none"]', card)
    if (signinNone !== null) signinNone.hidden = find('[data-region="signin-pages"] li', card) !== null
    must('[data-region="type-into-none"]', card).hidden = now.typeInto.length > 0
  }
  for (const radio of all<HTMLInputElement>('[data-input="web-ceiling"]', card)) radio.addEventListener("change", () => {
    now.ceiling = radio.value
    refresh()
  })
  const adder = (input: string, list: "signinOrigins" | "typeInto", region: string, remove: string, refused: string, sub: string | null, added?: () => void) => {
    const field = find<HTMLInputElement>(`[data-input="${input}"]`, card)
    if (field === null) return
    must(`[data-action="add-${input}"]`, card).addEventListener("click", () => {
      clearNotice()
      const origin = webPageOrigin(field.value)
      if (origin === null) return showProblems([refused])
      const shownAlready = all(`[data-region="${region}"] li[data-origin]`, card).some((li) => li.getAttribute("data-origin") === origin)
      if (!shownAlready) {
        if (now[list].length >= ORIGIN_LIST_MAX) return showProblems([WEB_PAGES_AT_MOST])
        now[list].push(origin)
        must(`[data-region="${region}"]`, card).append(webPageNode(origin, sub, remove))
      }
      field.value = ""
      added?.()
      refresh()
    })
  }
  adder("signin-page", "signinOrigins", "signin-pages", "remove-signin-page", WEB_PAGE_HTTPS_ONLY.signin, "added")
  adder("type-into", "typeInto", "type-into", "remove-type-into", WEB_PAGE_HTTPS_ONLY.typeInto, null, () => {
    must('[data-region="type-into-warning"]', card).hidden = false
  })
  // Remove is listened for on the card, so a row added here removes too.
  card.addEventListener("click", (event) => {
    const button = (event.target as HTMLElement | null)?.closest<HTMLElement>('[data-action="remove-signin-page"], [data-action="remove-type-into"]')
    if (button === null || button === undefined) return
    const origin = button.getAttribute("data-origin") ?? ""
    const list = button.getAttribute("data-action") === "remove-signin-page" ? now.signinOrigins : now.typeInto
    const at = list.indexOf(origin)
    if (at >= 0) list.splice(at, 1)
    button.closest("li")?.remove()
    refresh()
  })
  onClick('[data-action="save-web-pages"]', "Waiting for your passkey...", async () => {
    const body = change()
    if (body === null) return
    const expected = await itemUpdateAction(item, body)
    await signed(shell, { prepare: { path: `${path}/action`, body: { action: "update", change: body } }, matches: (a) => sameAction(expected, a), stillShown, mutation: { path: `${path}/update`, body } })
    location.reload()
  }, card)
  refresh()
}

// ---------------------------------------------------------------- Needs you

// Stop on a request row, listened for on the page, so a row the home's
// Needs you card drew after load (client/pages/needs-you.ts) stops too.
export function initWorkspacePending(_boot: Boot, maybe: ShellState | null): void {
  const shell = needShell(maybe)
  must("main").addEventListener("click", (event) => {
    const button = (event.target as Element | null)?.closest<HTMLButtonElement>('button[data-action="cancel-ask"]')
    if (!button || button.disabled) return
    void withBusy(button, "Stopping...", async () => {
      const kind = button.dataset.kind === "connect" ? "connect" : "intakes"
      await workspaceApi(shell, `/${kind}/${encodeURIComponent(button.dataset.id ?? "")}/cancel`, {})
      location.reload()
    })
  })
}
