// Wires a workspace page's tab state (shell-logic.ts) to the browser. Other
// tabs report their account or a sign-out on the `mehen-shell` channel. A
// page leaving for the back-forward cache locks itself and drops its cache
// first, because whoever is signed in when it comes back is unknown: a
// workspace read cannot say which account the cookie now belongs to. Brought
// back, it shows nothing of the old screen and reloads; nothing it sends in
// between leaves the tab. Once stale, every call but sign-out is refused
// before it is sent.

import { STALE_TAB_STATUS, VaultFailure, setCallGuard } from "./api.ts"
import type { Boot } from "./dom.ts"
import { showError } from "./dom.ts"
import { SHELL_CHANNEL, ShellState, parseShellMessage, readShellIdentity } from "./shell-logic.ts"

export const SIGN_OUT_PATH = "/api/auth/signout"

export type ShellChannel = { postMessage(message: unknown): void; addEventListener(type: "message", listener: (event: { data: unknown }) => void): void; close(): void }

// What the shell needs from the browser, so its wiring can be tested
// without one.
export type ShellHost = {
  origin: string
  channel(): ShellChannel | null
  onPageHide(listener: (persisted: boolean) => void): void
  onPageShow(listener: (persisted: boolean) => void): void
  // Removes the page's content, title included, leaving one plain line.
  clearScreen(): void
  showRefusal(error: VaultFailure): void
  reload(): void
}

const RELOADING = "Reloading this page to show who is signed in now."

export function browserShellHost(): ShellHost {
  return {
    origin: location.origin,
    channel: () => (typeof BroadcastChannel === "function" ? new BroadcastChannel(SHELL_CHANNEL) : null),
    onPageHide: (listener) => window.addEventListener("pagehide", (event) => listener(event.persisted)),
    onPageShow: (listener) => window.addEventListener("pageshow", (event) => listener(event.persisted)),
    clearScreen: () => {
      document.title = "Mehen"
      const line = document.createElement("p")
      line.textContent = RELOADING
      document.body.replaceChildren(line)
    },
    showRefusal: (error) => {
      document.body.classList.add("tab-stale")
      showError(error)
    },
    reload: () => location.reload(),
  }
}

// Any page that signs out says so, workspace page or not, so every other
// tab of this browser stops acting for the account that left.
export function announceSignedOut(host: ShellHost = browserShellHost()): void {
  const c = host.channel()
  c?.postMessage({ kind: "signed-out", origin: host.origin })
  c?.close()
}

// An account page (the picker, the account page) has no workspace but still
// tells the other tabs which account this browser is signed in as now.
function announceAccount(boot: Boot, host: ShellHost): void {
  const signedIn = boot.signedIn as { origin?: unknown; account?: unknown } | undefined
  if (typeof signedIn !== "object" || signedIn === null || signedIn.origin !== host.origin || typeof signedIn.account !== "string") return
  const c = host.channel()
  c?.postMessage({ kind: "account", origin: host.origin, account: signedIn.account })
  c?.close()
}

export function initShell(boot: Boot, host: ShellHost = browserShellHost()): ShellState | null {
  const identity = readShellIdentity(boot.shell, host.origin)
  if (identity === null) {
    announceAccount(boot, host)
    return null
  }
  const shell = new ShellState(identity)
  setCallGuard((path) => (path === SIGN_OUT_PATH ? null : shell.refusal()))
  const showStale = () => {
    const refusal = shell.refusal()
    if (refusal !== null) host.showRefusal(new VaultFailure(STALE_TAB_STATUS, refusal))
  }
  const c = host.channel()
  c?.addEventListener("message", (event) => {
    if (shell.receive(parseShellMessage(event.data))) showStale()
  })
  c?.postMessage({ kind: "account", origin: identity.origin, account: identity.account })
  // Locked and emptied on the way out, before anything can run as whoever
  // signs in meanwhile; a page kept for the back-forward cache also drops
  // its screen, so it never comes back showing the old account's data.
  host.onPageHide((persisted) => {
    shell.markStale("restored")
    if (persisted) host.clearScreen()
  })
  host.onPageShow((persisted) => {
    if (!persisted) return
    shell.markStale("restored")
    host.clearScreen()
    host.reload()
  })
  return shell
}

// The phone's More tab: a <details> that opens and closes with no script.
// Here: Escape closes it and puts focus back on the tab, a tap outside
// closes it, and Tab past its last link (or back before it) closes it as
// focus moves on. A disclosure, not a modal: nothing traps focus.
export function initMoreSheet(): void {
  const sheet = document.querySelector<HTMLDetailsElement>('details[data-region="more-sheet"]')
  const tab = sheet?.querySelector<HTMLElement>("summary")
  if (!sheet || !tab) return
  const close = (refocus: boolean) => {
    if (!sheet.open) return
    sheet.open = false
    if (refocus) tab.focus()
  }
  sheet.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || !sheet.open) return
    event.preventDefault()
    event.stopPropagation()
    close(true)
  })
  document.addEventListener("click", (event) => {
    if (sheet.open && event.target instanceof Node && !sheet.contains(event.target)) close(false)
  })
  // Focus leaving for another element, or past the page's last one; a
  // press on the sheet's own padding moves focus nowhere and keeps it open.
  let pressed = false
  sheet.addEventListener("pointerdown", () => {
    pressed = true
    setTimeout(() => {
      pressed = false
    }, 0)
  })
  sheet.addEventListener("focusout", (event) => {
    const next = event.relatedTarget
    if (next instanceof Node) {
      if (!sheet.contains(next)) close(false)
      return
    }
    if (!pressed) setTimeout(() => {
      if (!sheet.contains(document.activeElement)) close(false)
    }, 0)
  })
}

// The home's Get started card: Hide keeps it hidden in this browser, for
// this workspace only (mehen.getStarted.<workspace id>); nothing is sent.
export const GET_STARTED_KEY = "mehen.getStarted."

export function initGetStarted(): void {
  const card = document.querySelector<HTMLElement>('[data-region="get-started"]')
  const id = card?.dataset.workspace
  if (!card || id === undefined || id === "") return
  const key = `${GET_STARTED_KEY}${id}`
  try {
    if (localStorage.getItem(key) === "hidden") card.hidden = true
  } catch {
    // Storage refused (a private window): the card stays.
  }
  card.querySelector('[data-action="hide-get-started"]')?.addEventListener("click", () => {
    card.hidden = true
    try {
      localStorage.setItem(key, "hidden")
    } catch {
      // Hidden for this page view only.
    }
  })
}
