// An agent asked for a credential: seal each secret on this device, then
// save with a passkey. The guided setup's steps tick as the fields fill (a
// hint, not a gate), a value without the shape the template's hint names
// gets a warning (never a gate either), and a chained connect is opened
// once the save lands.

import { importSealPublicKey, seal } from "@mehen/protocol/seal"
import { api, stepUp } from "../api.ts"
import { type Boot, all, find, must, showProblems, withBusy } from "../dom.ts"
import { type FieldShape, type IntakeBoot, buildIntakeSubmission, intakeNeedsAcceptance, missesFieldShape, setupStepStates } from "../logic.ts"
import { showDone } from "./requests-done.ts"

type IntakeBootFull = IntakeBoot & { sealKey: { jwk: JsonWebKey }; then?: unknown }

// The connect that follows this intake, by id only; the path is built here.
function thenPath(boot: IntakeBootFull): string | null {
  return typeof boot.then === "string" && /^con_[A-Za-z0-9_-]+$/.test(boot.then) ? `/c/${encodeURIComponent(boot.then)}` : null
}

function applyStepStates(items: readonly HTMLElement[], filled: ReadonlySet<string>): void {
  const states = setupStepStates(
    items.map((li) => li.dataset.stepField ?? null),
    filled,
  )
  items.forEach((li, i) => {
    li.classList.toggle("done", states[i] === "done")
    li.classList.toggle("current", states[i] === "current")
  })
}

// The field's warning shows once the value plainly lacks the expected start
// or end, and goes as soon as the value has it. An end is judged when the
// field is left, not while the value is still being typed.
function wireShapeWarning(field: HTMLInputElement | HTMLTextAreaElement): void {
  const warn = field.closest(".field")?.querySelector<HTMLElement>('[data-region="field-warn"]')
  const start = field.dataset.expectStart
  const literals = (start ?? field.dataset.expectEnd ?? "").split(" ").filter((l) => l !== "")
  if (!warn || literals.length === 0) return
  const shape: FieldShape = { at: start !== undefined ? "start" : "end", literals }
  const update = (settled: boolean) => {
    if (!missesFieldShape(shape, field.value, true)) warn.hidden = true
    else if (missesFieldShape(shape, field.value, settled)) warn.hidden = false
  }
  field.addEventListener("input", () => update(false))
  field.addEventListener("change", () => update(true))
}

// Once saved, the page stops counting down and drops what only made sense
// before the save.
function settleSaved(form: HTMLElement): void {
  for (const selector of ['[data-region="intake-head"] .when', '[data-region="intake-tags-advice"]', '[data-region="intake-setup"]', '[data-region="intake-expired"]']) {
    const el = find(selector)
    if (el) el.hidden = true
  }
  const columns = form.closest<HTMLElement>(".two-col")
  if (columns) columns.hidden = false
}

function showExpired(form: HTMLElement, button: HTMLButtonElement): void {
  const expired = find('[data-region="intake-expired"]')
  if (!expired) return
  button.disabled = true
  const columns = form.closest<HTMLElement>(".two-col")
  if (columns) columns.hidden = true
  expired.hidden = false
  expired.scrollIntoView({ block: "start", behavior: "smooth" })
}

export function initIntake(raw: Boot): void {
  const boot = raw as unknown as IntakeBootFull
  const form = must('[data-form="intake"]')
  const button = must<HTMLButtonElement>('[data-action="submit-intake"]')
  const accept = find<HTMLInputElement>('[data-input="accept-destination"]', form)
  const allowReads = find<HTMLInputElement>('[data-input="allow-reads"]', form)
  const needsAcceptance = intakeNeedsAcceptance(boot)
  const fields = all<HTMLInputElement | HTMLTextAreaElement>("[data-field]", form)
  const stepItems = all<HTMLElement>('[data-region="intake-setup"] .step')
  const next = thenPath(boot)
  let expired = false
  let saved = false
  const filled = (): Set<string> => new Set(fields.filter((f) => f.value.trim() !== "").map((f) => f.dataset.field ?? ""))
  const refresh = () => {
    const have = filled()
    const missing = boot.fields.some((f) => f.required && !have.has(f.name))
    button.disabled = expired || missing || (needsAcceptance && !accept?.checked)
    applyStepStates(stepItems, have)
  }
  accept?.addEventListener("change", refresh)
  for (const f of fields) {
    f.addEventListener("input", refresh)
    wireShapeWarning(f)
  }
  document.addEventListener("vault:expired", () => {
    if (saved) return
    expired = true
    showExpired(form, button)
  })
  refresh()
  button.addEventListener("click", () => {
    const values: Record<string, string> = {}
    for (const f of fields) values[f.dataset.field ?? ""] = f.value
    void withBusy(button, "Sealing and waiting for your passkey...", async () => {
      const key = await importSealPublicKey(boot.sealKey.jwk)
      const built = await buildIntakeSubmission(boot, values, accept?.checked ?? false, (value, context) => seal(key, value, context), allowReads?.checked ?? false)
      if (!built.ok) return showProblems(built.problems)
      const proof = await stepUp({ type: "intake.submit", intake: boot.intake, digest: built.value.digest })
      await api(`/api/intakes/${encodeURIComponent(boot.intake)}/submit`, { ...built.value.submission, stepUp: proof })
      saved = true
      for (const f of fields) f.value = ""
      settleSaved(form)
      showDone("intake-done", null, null, form.closest("section"))
      if (next !== null) location.assign(next)
    }).then(refresh)
  })
}
