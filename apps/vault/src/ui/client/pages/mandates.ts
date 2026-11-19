// The mandate pages' wiring (pages/mandates.ts): Pause, Stop and Resume on
// a mandate's page and the machine page's card, and the sign page, whose
// summary follows the form and whose Sign with passkey is enabled only for
// terms the page can build. The flows are mandate-sign.ts.

import type { MandateClass } from "@mehen/protocol"
import { MANDATE_CLASSES } from "@mehen/protocol/mandate-terms"
import { MANDATE_PAUSE_ALL_RELOAD, MANDATE_RESUME_NO_PASSKEY_WORDS, MANDATE_SIGNING_WORDS, MANDATE_WAITING_WORDS, mandatePauseAllRefusedWords, mandateSummaryWords } from "../../wording.ts"
import { type Boot, all, el, find, must, spelledNodes, withBusy } from "../dom.ts"
import { type MandateFormChoice, changeMandate, mandateTermsOf, pauseMandates, resumeMandate, resumeNeedsPasskey, signMandate } from "../mandate-sign.ts"
import type { ShellState } from "../shell-logic.ts"
import { needShell } from "./workspace.ts"

const DAY_MS = 86_400_000

// Pause, Stop and Resume in each region that carries the mandate and the
// revision it shows: the mandate's terms and its Stop fold, or the
// machine page's card.
export function initMandateControls(shell: ShellState): void {
  for (const region of all('[data-mandate][data-rev]')) {
    const id = region.dataset.mandate ?? ""
    const rev = Number(region.dataset.rev)
    const press = (action: string, waiting: string, run: () => Promise<unknown>) => {
      for (const button of all<HTMLButtonElement>(`[data-action="${action}"]`, region)) {
        if (button.closest("[data-mandate]") !== region) continue
        button.addEventListener("click", () => void withBusy(button, waiting, async () => {
          await run()
          location.reload()
        }))
      }
    }
    press("mandate-pause", MANDATE_WAITING_WORDS, () => changeMandate(shell, id, rev, "pause"))
    press("mandate-stop", MANDATE_WAITING_WORDS, () => changeMandate(shell, id, rev, "stop"))
    press("mandate-resume", MANDATE_WAITING_WORDS, () => resumeMandate(shell, id, rev))
    const hint = find('[data-region="mandate-resume-hint"]', region)
    if (hint !== null && hint.closest("[data-mandate]") === region) void showResumeHint(shell, region, hint, id, rev)
  }
}

// No passkey needed under Resume, and no passkey mark on it, when the vault
// plans none for this press.
async function showResumeHint(shell: ShellState, region: HTMLElement, hint: HTMLElement, id: string, rev: number): Promise<void> {
  if (await resumeNeedsPasskey(shell, id, rev)) return
  hint.textContent = MANDATE_RESUME_NO_PASSKEY_WORDS
  for (const button of all('[data-action="mandate-resume"]', region)) if (button.closest("[data-mandate]") === region) button.querySelector("svg")?.remove()
}

// Pause all on the list: after one confirmation, each mandate at the
// revision shown, one request each; one changed since stays as it is. When
// any could not be paused, the page says how many, and the list is shown
// again from the link it gives.
export function initMandates(_boot: Boot, shell: ShellState | null): void {
  const button = find<HTMLButtonElement>('[data-action="mandate-pause-all"]')
  if (button === null) return
  const ws = needShell(shell)
  const notice = must('[data-region="mandates-pause-all-refused"]')
  button.addEventListener("click", () => {
    if (!confirm(button.dataset.confirm ?? "")) return
    void withBusy(button, MANDATE_WAITING_WORDS, async () => {
      const { total, refused } = await pauseMandates(ws, button.dataset.pause ?? "")
      if (refused === 0) {
        location.reload()
        return
      }
      const reload = el("a", null, MANDATE_PAUSE_ALL_RELOAD) as HTMLAnchorElement
      reload.href = location.href
      notice.replaceChildren(`${mandatePauseAllRefusedWords(refused, total)} `, reload)
      notice.hidden = false
    })
  })
}

export function initMandate(_boot: Boot, shell: ShellState | null): void {
  initMandateControls(needShell(shell))
}

// What the sign form holds now, read from its inputs.
function formChoice(form: HTMLElement): MandateFormChoice {
  const classes = all<HTMLInputElement>('[data-input="mandate-class"]', form).filter((c) => c.checked).map((c) => c.value as MandateClass)
  const caps = Object.fromEntries(MANDATE_CLASSES.map((c) => [c, Number(find<HTMLInputElement>(`[data-input="mandate-cap"][data-class="${c}"]`, form)?.value ?? "0")])) as Record<MandateClass, number>
  const listed = find<HTMLInputElement>('[data-input="mandate-items"]:checked', form)?.value !== "all"
  const items = listed ? all<HTMLInputElement>('[data-input="mandate-item"]', form).filter((i) => i.checked).map((i) => i.value) : "all" as const
  const ttlDays = Number(find<HTMLInputElement>('[data-input="mandate-ttl"]:checked', form)?.value ?? "0")
  const scheduled = find<HTMLInputElement>('[data-input="mandate-schedule"]', form)?.checked === true
  const windows = all('[data-region="mandate-window"]', form).map((w) => ({
    days: all<HTMLInputElement>('[data-input="mandate-day"]', w).filter((d) => d.checked).map((d) => Number(d.value)),
    from: must<HTMLInputElement>('[data-input="mandate-from"]', w).value,
    to: must<HTMLInputElement>('[data-input="mandate-to"]', w).value,
  }))
  const schedule = scheduled ? { tz: must<HTMLInputElement>('[data-input="mandate-tz"]', form).value, windows } : null
  return { classes, caps, items, ttlDays, schedule, note: must<HTMLInputElement>('[data-input="mandate-note"]', form).value }
}

export function initMandateSign(boot: Boot, shell: ShellState | null): void {
  if (boot.refused === true) return
  const ws = needShell(shell)
  const form = must('[data-form="mandate-sign"]')
  const summary = must('[data-region="mandate-summary"]')
  const refusal = must('[data-region="mandate-refusal"]')
  const sign = must<HTMLButtonElement>('[data-action="mandate-sign"]')
  const device = String(boot.device ?? "")
  const machine = String(boot.machine ?? "")
  const shown = { signer: String(boot.signer ?? ""), proposal: typeof boot.proposal === "string" ? boot.proposal : null }
  const tz = must<HTMLInputElement>('[data-input="mandate-tz"]', form)
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone
  if (tz.value === "") tz.value = timeZone
  const slugs = new Map(all<HTMLInputElement>('[data-input="mandate-item"]', form).map((i) => [i.value, i.dataset.slug ?? ""]))
  const redraw = () => {
    const choice = formChoice(form)
    for (const field of all('[data-region="mandate-cap"]', form)) field.hidden = !(field.dataset.class === "read" || choice.classes.includes(field.dataset.class as MandateClass))
    for (const tick of all<HTMLInputElement>('[data-input="mandate-item"]', form)) tick.disabled = choice.items === "all"
    must('[data-region="mandate-schedule"]', form).hidden = choice.schedule === null
    const built = mandateTermsOf(device, choice)
    if ("refusal" in built) {
      summary.replaceChildren()
      refusal.textContent = built.refusal
      refusal.hidden = false
      sign.disabled = true
      return
    }
    const t = built.terms
    const items = t.items === "all" ? "all" as const : t.items.map((id) => slugs.get(id) ?? id)
    summary.replaceChildren(...mandateSummaryWords({ machine, classes: t.classes, caps: t.caps, items, endsAt: Date.now() + t.ttlDays * DAY_MS, schedule: t.schedule, timeZone }).map((line) => {
      const p = el("p", null)
      p.append(...spelledNodes(line))
      return p
    }))
    refusal.hidden = true
    sign.disabled = false
  }
  form.addEventListener("change", redraw)
  form.addEventListener("input", redraw)
  redraw()
  // withBusy enables the button again after a refusal; redraw puts back
  // whether the terms can be signed.
  sign.addEventListener("click", () => void withBusy(sign, MANDATE_SIGNING_WORDS, async () => {
    const built = mandateTermsOf(device, formChoice(form))
    if ("refusal" in built) return
    const { mandate } = await signMandate(ws, shown, built.terms)
    location.assign(`/w/${encodeURIComponent(ws.identity.workspace.slug)}/mandates/${encodeURIComponent(mandate.id)}`)
  }).then(redraw))
}
