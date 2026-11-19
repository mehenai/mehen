// The browser side of the consoles: the operator's register page and
// platform page, and a platform admin's platform page. Every form is
// checked here first (console-logic.ts), so a passkey is only asked for a
// change the vault could take; then the step-up is signed for that exact
// command (its digest) through the console's own step-up start, and the
// command is sent with it once. A key made here keeps its private half in
// this page only: shown once for copying, never sent, and dropped once the
// form is accepted, when another key is made, when the person switches to
// pasting, forgets it, or the page goes.

import { PASTED_KEY_PROBLEMS, readPastedPlatformKey, makePlatformKey, type PlatformPublicJwk } from "../platform-key-logic.ts"
import { CONSOLE_ROUTES, type AdminChangeAnswer, type AdminPlatformCommand, type OperatorChangeAnswer, type OperatorCommand, adminStepUpAction, operatorStepUpAction } from "@mehen/protocol/platform-console"
import type { PlatformLimits } from "@mehen/protocol/platform"
import { api } from "../api.ts"
import { type Boot, all, clearNotice, find, inputValue, must, showProblems, withBusy } from "../dom.ts"
import { consoleStepUp } from "../step-up.ts"
import { type Checked, type HeldSlugs, accountIdOf, afterDaysOf, confirmOf, defaultsOf, limitsChangeOf, overlapHoursOf, reasonOf, registerNameOf, registerSlugOf, subjectOf } from "../console-logic.ts"

function withSlug(pattern: string, slug: string): string {
  return pattern.replace(":slug", encodeURIComponent(slug))
}

const WAITING = "Waiting for your passkey..."

// ---------------------------------------------------------------- sending

// `platformId` is null only for register, whose platform has no id yet.
async function operate(slug: string, platformId: string | null, command: OperatorCommand): Promise<OperatorChangeAnswer> {
  const stepUp = await consoleStepUp(CONSOLE_ROUTES.operatorStepUp, await operatorStepUpAction(slug, platformId, command))
  const path = command.command === "register" ? CONSOLE_ROUTES.operatorPlatforms : withSlug(CONSOLE_ROUTES.operatorPlatform, slug)
  return api<OperatorChangeAnswer>(path, { command, stepUp })
}

async function administer(slug: string, platformId: string, command: AdminPlatformCommand): Promise<AdminChangeAnswer> {
  const stepUp = await consoleStepUp(withSlug(CONSOLE_ROUTES.adminStepUp, slug), await adminStepUpAction(slug, platformId, command))
  return api<AdminChangeAnswer>(withSlug(CONSOLE_ROUTES.adminPlatform, slug), { command, stepUp })
}

// Every check's problems together, or every value. A check may fail with no
// problem to list: the key fields say theirs under the field.
function gather<T extends Record<string, Checked<unknown>>>(checks: T): { ok: true; value: { [K in keyof T]: T[K] extends Checked<infer V> ? V : never } } | { ok: false; problems: string[] } {
  const failed = Object.values(checks).filter((c) => !c.ok)
  if (failed.length > 0) return { ok: false, problems: failed.flatMap((c) => (c.ok ? [] : c.problems)) }
  return { ok: true, value: Object.fromEntries(Object.entries(checks).map(([k, c]) => [k, (c as { value: unknown }).value])) as { [K in keyof T]: T[K] extends Checked<infer V> ? V : never } }
}

// A form's submit: its checks, then the change, with its button busy.
function onSubmit(form: HTMLFormElement, send: () => Promise<void>): void {
  form.addEventListener("submit", (event) => {
    event.preventDefault()
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', form), WAITING, send)
  })
}

class Refused extends Error {
  readonly problems: string[]
  constructor(problems: string[]) {
    super(problems[0] ?? "Check the form.")
    this.problems = problems
  }
}

// A check's value, or a refusal shown as "Check this first".
function valueOf<T>(checked: Checked<T>): T {
  if (!checked.ok) throw new Refused(checked.problems)
  return checked.value
}

// withBusy shows a thrown error as the vault's; a refusal from the checks
// is shown as the list of what to fix instead, unless each was already said
// beside its field.
function showingProblems(send: () => Promise<void>): () => Promise<void> {
  return async () => {
    try {
      await send()
    } catch (error) {
      if (!(error instanceof Refused)) throw error
      if (error.problems.length > 0) showProblems(error.problems)
    }
  }
}

// ---------------------------------------------------------------- the key fields

// `read` answers the key, or a refusal whose sentence it has already put
// under the key fields, so it lists no problem of its own and nothing is
// said twice.
type KeyFields = { read: () => Promise<Checked<PlatformPublicJwk>>; forget: () => void }

const MADE_KEY_PROBLEMS = {
  none: "Make a key pair first, or paste the platform's public key.",
  kept: "Copy the private key into the platform's secret store first, then tick the box to say you have.",
} as const

// The paste or make choice inside `form`. The private half lives only in
// `made` and the one <code> it is shown in.
function wireKeyFields(form: HTMLElement): KeyFields {
  const paste = must('[data-region="key-paste"]', form)
  const make = must('[data-region="key-make"]', form)
  const shown = must('[data-region="key-made"]', form)
  const privateKey = must('[data-region="private-key"]', form)
  const thumbprint = must('[data-region="key-thumbprint"]', form)
  const kept = must<HTMLInputElement>('[data-input="key-kept"]', form)
  const pasted = must<HTMLTextAreaElement>('[data-input="public-jwk"]', form)
  const problem = must('[data-region="key-problem"]', form)
  let made: { jwk: PlatformPublicJwk } | null = null
  const source = () => find<HTMLInputElement>('[data-input="key-source"]:checked', form)?.value === "make" ? "make" : "paste"
  const forget = () => {
    made = null
    privateKey.textContent = ""
    thumbprint.textContent = ""
    kept.checked = false
    shown.hidden = true
  }
  const say = (text: string | null) => {
    problem.textContent = text ?? ""
    problem.hidden = text === null
  }
  for (const radio of all<HTMLInputElement>('[data-input="key-source"]', form)) {
    radio.addEventListener("change", () => {
      paste.hidden = source() !== "paste"
      make.hidden = source() !== "make"
      // A key made and then set aside is dropped, not kept out of sight.
      if (source() === "paste") forget()
      say(null)
    })
  }
  const makeButton = must<HTMLButtonElement>('[data-action="make-key"]', form)
  makeButton.addEventListener("click", () => {
    forget()
    void withBusy(makeButton, "Making the key pair...", async () => {
      const key = await makePlatformKey()
      made = { jwk: key.jwk }
      privateKey.textContent = key.privatePkcs8
      thumbprint.textContent = key.thumbprint
      shown.hidden = false
      say(null)
    })
  })
  must<HTMLButtonElement>('[data-action="forget-key"]', form).addEventListener("click", forget)
  window.addEventListener("pagehide", forget)
  return {
    forget,
    read: async () => {
      say(null)
      if (source() === "paste") {
        const read = await readPastedPlatformKey(pasted.value)
        if (read.ok) return { ok: true, value: read.jwk }
        // A private key is never left in the page, where a restored form
        // or a half-fixed paste could send it.
        if (read.problem === PASTED_KEY_PROBLEMS.private) pasted.value = ""
        say(read.problem)
        return { ok: false, problems: [] }
      }
      if (made === null || !kept.checked) {
        say(made === null ? MADE_KEY_PROBLEMS.none : MADE_KEY_PROBLEMS.kept)
        return { ok: false, problems: [] }
      }
      return { ok: true, value: made.jwk }
    },
  }
}

// ---------------------------------------------------------------- forms both consoles have

function typed(form: HTMLElement, input: string): string {
  return inputValue(`[data-input="${input}"]`, form)
}

// Add a key and rotate: a key, the overlap and the slug typed back.
function wireRotate(slug: string, send: (command: { command: "rotate-key"; key: PlatformPublicJwk; overlapHours: number; confirm: string }) => Promise<unknown>): void {
  const form = find<HTMLFormElement>('[data-form="rotate-key"]')
  if (!form) return
  const keys = wireKeyFields(form)
  onSubmit(form, showingProblems(async () => {
    const terms = valueOf(gather({ key: await keys.read(), overlapHours: overlapHoursOf(typed(form, "overlap-hours")), confirm: confirmOf(typed(form, "confirm"), slug) }))
    await send({ command: "rotate-key", key: terms.key, overlapHours: terms.overlapHours, confirm: terms.confirm })
    keys.forget()
    location.reload()
  }))
}

function wireRevoke(slug: string, send: (command: { command: "revoke-key"; key: string; confirm: string }) => Promise<unknown>): void {
  const form = find<HTMLFormElement>('[data-form="revoke-key"]')
  if (!form) return
  onSubmit(form, showingProblems(async () => {
    const confirm = valueOf(confirmOf(typed(form, "confirm"), slug))
    await send({ command: "revoke-key", key: must<HTMLSelectElement>('[data-input="key"]', form).value, confirm })
    location.reload()
  }))
}

// ---------------------------------------------------------------- the operator

// The slugs the page was drawn with; anything else in the boot is ignored.
function heldSlugsOf(boot: Boot): HeldSlugs {
  const raw = boot.heldSlugs
  if (typeof raw !== "object" || raw === null) return {}
  return Object.fromEntries(Object.entries(raw).filter((entry): entry is [string, "registered" | "removing"] => entry[1] === "registered" || entry[1] === "removing"))
}

export function initOperatorRegister(boot: Boot): void {
  const form = must<HTMLFormElement>('[data-form="platform-register"]')
  const keys = wireKeyFields(form)
  const held = heldSlugsOf(boot)
  onSubmit(form, showingProblems(async () => {
    const terms = valueOf(gather({ name: registerNameOf(typed(form, "name")), slug: registerSlugOf(typed(form, "slug"), held), key: await keys.read() }))
    const confirm = valueOf(confirmOf(typed(form, "confirm"), terms.slug))
    const answer = await operate(terms.slug, null, { command: "register", slug: terms.slug, name: terms.name, key: terms.key, limits: {}, confirm })
    keys.forget()
    const key = answer.platform.keys.find((k) => k.live) ?? answer.platform.keys[0]
    must('[data-region="done-platform"]').textContent = answer.platform.id
    must('[data-region="done-key"]').textContent = key?.id ?? ""
    must<HTMLAnchorElement>('[data-region="done-link"]').href = `/operator/platforms/${encodeURIComponent(answer.platform.slug)}`
    must('[data-region="register"]').hidden = true
    must('[data-region="register-done"]').hidden = false
    clearNotice()
  }))
}

function limitsBefore(boot: Boot): PlatformLimits | null {
  const limits = boot.limits
  return typeof limits === "object" && limits !== null ? (limits as PlatformLimits) : null
}

export function initOperatorPlatform(boot: Boot): void {
  const slug = typeof boot.platform === "string" ? boot.platform : ""
  const platformId = typeof boot.platformId === "string" ? boot.platformId : ""
  if (slug === "" || platformId === "") return
  const send = (command: OperatorCommand) => operate(slug, platformId, command)
  const reload = () => location.reload()
  const formOf = (name: string) => find<HTMLFormElement>(`[data-form="${name}"]`)

  const suspend = formOf("platform-suspend")
  if (suspend) onSubmit(suspend, showingProblems(async () => {
    const terms = valueOf(gather({ reason: reasonOf(typed(suspend, "reason")), confirm: confirmOf(typed(suspend, "confirm"), slug) }))
    await send({ command: "suspend", ...terms })
    reload()
  }))
  const resume = formOf("platform-resume")
  if (resume) onSubmit(resume, async () => {
    await send({ command: "resume" })
    reload()
  })
  wireRotate(slug, send)
  wireRevoke(slug, send)

  const limits = formOf("platform-limits")
  const before = limitsBefore(boot)
  if (limits && before) onSubmit(limits, showingProblems(async () => {
    const typedLimits = Object.fromEntries(all<HTMLInputElement>("[data-limit]", limits).map((input) => [input.dataset.limit ?? "", input.value]))
    await send({ command: "limits", limits: valueOf(limitsChangeOf(before, typedLimits)) })
    reload()
  }))

  const addAdmin = formOf("add-admin")
  if (addAdmin) onSubmit(addAdmin, showingProblems(async () => {
    await send({ command: "add-admin", account: valueOf(accountIdOf(typed(addAdmin, "account"))) })
    reload()
  }))
  for (const button of all<HTMLButtonElement>('[data-action="remove-admin"]')) {
    button.addEventListener("click", () => {
      const account = button.dataset.account ?? ""
      if (!confirm(`Remove ${account} as an admin of ${slug}? They lose its Platforms page at once.`)) return
      void withBusy(button, WAITING, async () => {
        await send({ command: "remove-admin", account })
        reload()
      })
    })
  }

  const deleteSubjects = formOf("delete-subjects")
  if (deleteSubjects) onSubmit(deleteSubjects, showingProblems(async () => {
    const terms = valueOf(gather({ reason: reasonOf(typed(deleteSubjects, "reason")), confirm: confirmOf(typed(deleteSubjects, "confirm"), slug) }))
    await send({ command: "delete-subjects", ...terms })
    reload()
  }))
  const retire = formOf("retire")
  if (retire) onSubmit(retire, showingProblems(async () => {
    const terms = valueOf(gather({ afterDays: afterDaysOf(typed(retire, "after-days")), confirm: confirmOf(typed(retire, "confirm"), slug) }))
    await send({ command: "retire", ...terms })
    reload()
  }))
  const remove = formOf("remove")
  if (remove) onSubmit(remove, showingProblems(async () => {
    const terms = valueOf(gather({ reason: reasonOf(typed(remove, "reason")), confirm: confirmOf(typed(remove, "confirm"), slug) }))
    await send({ command: "remove", ...terms })
    reload()
  }))
}

// ---------------------------------------------------------------- a platform admin

export function initPlatformAdmin(boot: Boot): void {
  const slug = typeof boot.platform === "string" ? boot.platform : ""
  const platformId = typeof boot.platformId === "string" ? boot.platformId : ""
  const revision = typeof boot.defaultsRevision === "number" ? boot.defaultsRevision : 0
  if (slug === "" || platformId === "") return
  const send = (command: AdminPlatformCommand) => administer(slug, platformId, command)
  wireRotate(slug, send)
  wireRevoke(slug, send)

  const defaults = find<HTMLFormElement>('[data-form="defaults"]')
  if (defaults) {
    const list = must('[data-region="defaults-problems"]', defaults)
    onSubmit(defaults, async () => {
      const read = defaultsOf(typed(defaults, "defaults"))
      list.replaceChildren(...(read.ok ? [] : read.problems.map((p) => Object.assign(document.createElement("li"), { textContent: p }))))
      list.hidden = read.ok
      if (!read.ok) return
      await send({ command: "defaults", defaults: read.value, revision })
      location.reload()
    })
  }

  const deleteSubject = find<HTMLFormElement>('[data-form="delete-subject"]')
  if (deleteSubject) onSubmit(deleteSubject, showingProblems(async () => {
    const terms = valueOf(gather({ subject: subjectOf(typed(deleteSubject, "subject")), confirm: confirmOf(typed(deleteSubject, "confirm"), slug) }))
    await send({ command: "delete-subject", ...terms })
    location.reload()
  }))
}
