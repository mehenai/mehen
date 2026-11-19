// /signup's emailed code beside Google (ui/pages/email-code.ts): ask the
// vault to email a code to the invitation's own address, type it back, and
// hand the proof to the page, which keeps it where it keeps Google's result
// (mehen.oidc.result) and passes it to the signup and the join as emailProof.
// The vault binds the proof to this browser by its own cookie.

import { VaultFailure, api } from "./api.ts"
import { must, withBusy } from "./dom.ts"

export type EmailCodeOffer = "offered" | "identity_rule" | "off"

// The vault's email proofs are eml_ ids; Google's results are not.
export function isEmailProof(handle: string): boolean {
  return handle.startsWith("eml_")
}

// The proof as the signup and the join take it.
export function proofBody(handle: string | null): { oidcResult?: string; emailProof?: string } {
  if (handle === null) return {}
  return isEmailProof(handle) ? { emailProof: handle } : { oidcResult: handle }
}

export type EmailCodeStep = { show(offer: EmailCodeOffer): void }

export function wireEmailCode(invite: string, proved: (handle: string, email: string) => void): EmailCodeStep {
  const region = must('[data-region="email-code"]')
  const googleOnly = must('[data-region="email-code-google-only"]')
  const startActions = must('[data-region="email-code-start"]', region)
  const send = must<HTMLButtonElement>('[data-action="email-code-send"]', startActions)
  const failed = must('[data-region="email-code-failed"]', region)
  const form = must<HTMLFormElement>('[data-form="email-code"]', region)
  const input = must<HTMLInputElement>('[data-input="email-code"]', form)
  const error = must('[data-region="email-code-error"]', form)
  const check = must<HTMLButtonElement>('[data-action="email-code-verify"]', form)
  const resend = must<HTMLButtonElement>('[data-action="email-code-resend"]', form)
  const say = (text: string | null) => {
    error.textContent = text ?? ""
    error.hidden = text === null
  }
  // A refused send says so beside the Google button; a limit or a dead
  // invitation is the vault's own message.
  const start = (button: HTMLButtonElement) =>
    withBusy(button, "Sending...", async () => {
      failed.hidden = true
      say(null)
      try {
        await api<{ sent: true; expiresAt: string }>("/api/auth/email/start", { code: invite })
      } catch (failure) {
        if (failure instanceof VaultFailure && failure.body.error === "upstream_failed") {
          failed.hidden = false
          return
        }
        throw failure
      }
      startActions.hidden = true
      form.hidden = false
      input.value = ""
      input.focus()
    })
  send.addEventListener("click", () => void start(send))
  resend.addEventListener("click", () => void start(resend))
  form.addEventListener("submit", (event) => {
    event.preventDefault()
    void withBusy(check, "Checking...", async () => {
      say(null)
      try {
        const verified = await api<{ emailProof: string; email: string }>("/api/auth/email/verify", { code: invite, emailCode: input.value })
        proved(verified.emailProof, verified.email)
      } catch (failure) {
        if (failure instanceof VaultFailure && failure.body.error === "bad_request") {
          say(failure.body.message)
          return
        }
        throw failure
      }
    })
  })
  return {
    show(offer) {
      region.hidden = offer !== "offered"
      googleOnly.hidden = offer !== "identity_rule"
      startActions.hidden = false
      form.hidden = true
      failed.hidden = true
      say(null)
    },
  }
}
