// Connecting an OAuth account: one button that starts the provider flow.
// The page only ever navigates to an https address the vault returned.
// When the countdown runs out, everything that still invites a sign-in
// gives way to the expired card.

import { api } from "../api.ts"
import { type Boot, find, must, withBusy } from "../dom.ts"

const LIVE_REGIONS = ["connect-retry", "connect-awaiting", "connect-step-done", "connect-reconnect", "connect-account", "connect-scopes"]

function onExpired(): void {
  document.addEventListener("vault:expired", () => {
    const expired = find('[data-region="connect-expired"]')
    if (!expired) return
    for (const region of LIVE_REGIONS) {
      const el = find(`[data-region="${region}"]`)
      if (el) el.hidden = true
    }
    expired.hidden = false
    expired.scrollIntoView({ block: "start", behavior: "smooth" })
  })
}

// A connect still waiting on its client intake: no button yet, only the
// way to step 1, which stops being offered once the link runs out.
export function initConnectWaiting(): void {
  onExpired()
}

export function initConnect(boot: Boot): void {
  const id = String(boot.connect ?? "")
  const button = must<HTMLButtonElement>('[data-action="start-connect"]')
  button.disabled = false
  document.addEventListener("vault:expired", () => {
    button.disabled = true
  })
  onExpired()
  button.addEventListener("click", () => {
    void withBusy(button, "Opening the provider...", async () => {
      const { authorizeUrl } = await api<{ authorizeUrl: string }>(`/api/connect/${encodeURIComponent(id)}/start`, {})
      const target = new URL(authorizeUrl)
      if (target.protocol !== "https:") throw new Error("The vault returned a sign-in address that is not https, so this page will not open it.")
      location.assign(target.href)
    })
  })
}
