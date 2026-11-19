// Passkey sign in and sign out, signing in with a recovery code to set up
// a new passkey, and the account page's cards (/account): passkeys,
// sessions and appearance.

import { type PublicKeyCredentialCreationOptionsJSON, type PublicKeyCredentialRequestOptionsJSON, startAuthentication, startRegistration } from "@simplewebauthn/browser"
import { normaliseRecoveryCode } from "@mehen/protocol/recovery-code"
import { safeNext } from "../../wording.ts"
import { VaultFailure, api } from "../api.ts"
import { type Appearance, applyAppearance, readAppearance, themeColour } from "../appearance.ts"
import { type Boot, all, clearNotice, find, must, showError, withBusy } from "../dom.ts"
import { accountStepUp } from "../step-up.ts"
import { retryWords } from "../security-logic.ts"
import { announceSignedOut } from "../shell.ts"
import { rememberSigninFragment, takeSigninFragment } from "../signin-fragment.ts"

// Set by sign-in when the passkey came from another device. Only the
// single-vault Home read it, and no route serves that page.
const ADD_HERE_KEY = "mehen-add-here"

export function initSignin(boot: Boot): void {
  const button = must<HTMLButtonElement>('[data-action="signin"]')
  const next = safeNext(typeof boot.next === "string" ? boot.next : "/")
  rememberSigninFragment(next, location.hash)
  button.disabled = false
  button.addEventListener("click", () => {
    void withBusy(button, "Waiting for your passkey...", async () => {
      const { options, flow } = await api<{ options: PublicKeyCredentialRequestOptionsJSON; flow: string }>("/api/auth/signin/options", {})
      const response = await startAuthentication({ optionsJSON: options })
      await api("/api/auth/signin/verify", { flow, response })
      // A passkey from another device (a phone by QR): Home offers to add one here.
      if (response.authenticatorAttachment === "cross-platform") {
        try {
          sessionStorage.setItem(ADD_HERE_KEY, "1")
        } catch {
          // Without storage the card is simply not offered.
        }
      }
      location.assign(takeSigninFragment(next, location.hash))
    })
  })
}

// /recover: the code is checked here first, so a typo never reaches the
// vault, then posted once. A refusal is said under the field.
// With workspaces on, the vault answers a code with { pending, transition }
// (202 while the change is still reaching the account's workspaces), never
// a place to go: the page always goes on to /recover/passkey, whose server
// shows the passkey form or, while pending, an honest waiting page.
export function initRecover(boot: Boot): void {
  const workspaces = boot.workspaces === true
  const form = must<HTMLFormElement>('[data-form="recover"]')
  const button = must<HTMLButtonElement>('[data-action="recover"]')
  const input = must<HTMLInputElement>('[data-input="recovery-code"]', form)
  const error = must('[data-region="recover-error"]', form)
  let busy = false
  const refresh = () => {
    button.disabled = busy || input.value.trim() === ""
  }
  const say = (text: string) => {
    error.textContent = text
    error.hidden = false
  }
  input.addEventListener("input", () => {
    error.hidden = true
    refresh()
  })
  refresh()
  form.addEventListener("submit", (event) => {
    event.preventDefault()
    if (busy || input.value.trim() === "") return
    const parsed = normaliseRecoveryCode(input.value)
    if (!parsed.ok) {
      say(parsed.reason === "typo" ? "That code has a typo. Check each group." : "Enter a recovery code in four groups of four.")
      return
    }
    busy = true
    void withBusy(button, "Checking the code...", async () => {
      try {
        if (workspaces) {
          await api<{ pending: boolean }>("/api/auth/recovery", { code: input.value })
          location.assign("/recover/passkey")
          return
        }
        const { next } = await api<{ next: string }>("/api/auth/recovery", { code: input.value })
        location.assign(safeNext(next))
      } catch (failure) {
        if (!(failure instanceof VaultFailure) || failure.status === 0) throw failure
        say(failure.body.error === "rate_limited" ? `Too many tries from this network. ${retryWords(failure.body.retryAfter, Date.now())}` : failure.body.message)
        input.select()
      }
    }).finally(() => {
      busy = false
      refresh()
    })
  })
}

// /recover/passkey: a passkey on this device or a security key, named by
// the member or by which one they chose. When the 15 minutes have run out
// the page turns into the way back to /recover.
export function initRecoverPasskey(): void {
  const form = find<HTMLFormElement>('[data-form="recover-passkey"]')
  if (!form) return
  form.addEventListener("submit", (event) => event.preventDefault())
  const input = must<HTMLInputElement>('[data-input="passkey-name"]', form)
  const buttons = all<HTMLButtonElement>('[data-action="recover-passkey"]', form)
  for (const button of buttons) {
    button.disabled = false
    button.addEventListener("click", () => {
      const kind = button.dataset.kind === "security-key" ? "security-key" : "device"
      const name = input.value.trim() || (kind === "device" ? "Passkey on this device" : "Security key")
      void withBusy(button, "Creating the passkey...", async () => {
        try {
          const { options } = await api<{ options: PublicKeyCredentialCreationOptionsJSON }>("/api/auth/recovery/passkey/options", { kind })
          const response = await startRegistration({ optionsJSON: options })
          await api("/api/auth/recovery/passkey/verify", { response, name })
          location.assign("/")
        } catch (failure) {
          if (failure instanceof VaultFailure && failure.status === 401) {
            must('[data-region="recover-passkey"]').hidden = true
            must('[data-region="recover-gone"]').hidden = false
            return
          }
          throw failure
        }
      })
    })
  }
}

// The shell has a sign-out button in the rail and one in the top bar, and
// Settings has one; every one is wired. The shell's are icon buttons, so
// the waiting words go in the label and the icon stays.
export function initSignout(): void {
  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-action="signout"]')) {
    button.addEventListener("click", () => {
      const signOut = async () => {
        await api("/api/auth/signout", {})
        announceSignedOut()
        location.assign("/signin")
      }
      if (!button.classList.contains("icon-btn")) {
        void withBusy(button, "Signing out...", signOut)
        return
      }
      const label = button.getAttribute("aria-label") ?? "Sign out"
      button.disabled = true
      button.setAttribute("aria-busy", "true")
      button.setAttribute("aria-label", "Signing out...")
      button.title = "Signing out..."
      clearNotice()
      signOut()
        .catch(showError)
        .finally(() => {
          button.setAttribute("aria-label", label)
          button.removeAttribute("title")
          button.removeAttribute("aria-busy")
          button.disabled = false
        })
    })
  }
}

// ---------------------------------------------------------------- /account

function enabled(action: string): HTMLButtonElement[] {
  const buttons = all<HTMLButtonElement>(`[data-action="${action}"]`)
  for (const button of buttons) if (!button.hasAttribute("data-keep-disabled")) button.disabled = false
  return buttons
}

// Each change goes to the account's own routes. Adding and removing a
// passkey widen or change how you sign in, so each asks for a passkey you
// have first; the vault still refuses removing the last one. Renaming and
// ending sessions only narrow and ask for none.
function initAccountPasskeys(): void {
  for (const row of all<HTMLElement>("[data-passkey-row]")) {
    const passkey = encodeURIComponent(row.dataset.passkeyRow ?? "")
    const open = must<HTMLButtonElement>('[data-action="rename-passkey"]', row)
    const field = must('[data-region="rename"]', row)
    const input = must<HTMLInputElement>('[data-input="rename"]', row)
    const save = must<HTMLButtonElement>('[data-action="save-rename"]', row)
    const cancel = must<HTMLButtonElement>('[data-action="cancel-rename"]', row)
    for (const button of [open, save, cancel]) button.disabled = false
    const editing = (on: boolean) => {
      field.hidden = !on
      open.hidden = on
      if (on) input.focus()
    }
    open.addEventListener("click", () => editing(true))
    cancel.addEventListener("click", () => editing(false))
    save.addEventListener("click", () => {
      const name = input.value.trim()
      if (name === "") return
      void withBusy(save, "Saving...", async () => {
        await api(`/api/account/passkeys/${passkey}/rename`, { name })
        location.reload()
      })
    })
  }
  for (const button of enabled("remove-passkey")) {
    button.addEventListener("click", () => {
      const name = button.dataset.name ?? "this passkey"
      if (!confirm(`Remove ${name}? It stops signing in and confirming at once, in every workspace.`)) return
      void withBusy(button, "Waiting for your passkey...", async () => {
        const passkey = button.dataset.passkey ?? ""
        const stepUp = await accountStepUp({ type: "passkey.remove", passkey })
        await api(`/api/account/passkeys/${encodeURIComponent(passkey)}/remove`, { stepUp })
        location.reload()
      })
    })
  }
  const nameInput = find<HTMLInputElement>('[data-input="passkey-name"]')
  for (const button of enabled("add-passkey")) {
    const kind = button.dataset.kind === "security-key" ? "security-key" : "device"
    button.addEventListener("click", () => {
      void withBusy(button, "Waiting for your passkey...", async () => {
        const stepUp = await accountStepUp({ type: "passkey.add" })
        const { options } = await api<{ options: PublicKeyCredentialCreationOptionsJSON }>("/api/account/passkeys/options", { stepUp, kind })
        const response = await startRegistration({ optionsJSON: options })
        const typed = nameInput?.value.trim() ?? ""
        await api("/api/account/passkeys/verify", { response, ...(typed !== "" ? { name: typed } : {}) })
        location.reload()
      })
    })
  }
}

// Ending this browser's own session signs it out here, so it says so and
// goes to sign in; ending everywhere includes this browser too.
function initAccountSessions(): void {
  for (const button of enabled("end-session")) {
    button.addEventListener("click", () => {
      const current = button.dataset.current === "1"
      if (current && !confirm("Sign out of this browser? You will need your passkey to sign in here again.")) return
      void withBusy(button, current ? "Signing out..." : "Ending...", async () => {
        await api(`/api/account/sessions/${encodeURIComponent(button.dataset.session ?? "")}/end`, {})
        if (current) {
          announceSignedOut()
          location.assign("/signin")
        } else location.reload()
      })
    })
  }
  for (const button of enabled("end-all-sessions")) {
    button.addEventListener("click", () => {
      if (!confirm("Sign out everywhere, this browser too? Every browser and app signed in as you will need a passkey again. Every mandate you signed stops letting work through until you resume it with your passkey; your machines stay enrolled.")) return
      void withBusy(button, "Signing out...", async () => {
        await api("/api/account/sessions/end-all", {})
        announceSignedOut()
        location.assign("/signin")
      })
    })
  }
}

// The appearance chips: kept in this browser's localStorage only and applied
// as data-theme on the document, as theme.ts does at load.
function initAppearanceChips(): void {
  const chips = all<HTMLButtonElement>('[data-region="appearance"] [data-theme-choice]')
  const show = (choice: Appearance) => {
    for (const chip of chips) chip.setAttribute("aria-pressed", chip.dataset.themeChoice === choice ? "true" : "false")
  }
  if (chips.length === 0) return
  show(readAppearance(localStorage))
  for (const chip of chips) {
    chip.addEventListener("click", () => {
      const choice = chip.dataset.themeChoice
      if (choice !== "system" && choice !== "light" && choice !== "dark") return
      applyAppearance(document.documentElement, localStorage, choice)
      find<HTMLMetaElement>('meta[name="theme-color"]')?.setAttribute("content", themeColour(choice, matchMedia("(prefers-color-scheme: dark)").matches))
      show(choice)
    })
  }
}

// Ask every time: ends this browser's passkey grace window, with no passkey.
function initStepUpGrace(): void {
  for (const button of enabled("end-stepup-grace")) {
    button.addEventListener("click", () => {
      void withBusy(button, "Ending...", async () => {
        await api("/api/account/stepup/grace/end", {})
        location.reload()
      })
    })
  }
}

export function initAccount(): void {
  initAccountPasskeys()
  initStepUpGrace()
  initAccountSessions()
  initAppearanceChips()
}
