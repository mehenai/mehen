import { startAuthentication, type PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/browser"
import { VaultFailure, api } from "../api.ts"
import { find, showError, withBusy, type Boot } from "../dom.ts"

import { INVITE_KEY, clearOidcFragment, oidcFragment, oidcStartInvite } from "../oidc-logic.ts"
export function initOidc(boot: Boot): void {
  const fragment = clearOidcFragment({ location, history })
  if (boot.mode === "app-start") {
    const input = oidcFragment(fragment)
    if (!input) return
    void api<{ url: string }>("/api/auth/oidc/google/app/start", input).then(({ url }) => location.assign(url)).catch(showError)
    return
  }
  if (boot.mode === "app-callback") return
  const params = new URLSearchParams(location.search), purpose = typeof boot.purpose === "string" ? boot.purpose : "signin", workspace = typeof boot.workspace === "string" ? boot.workspace : undefined
  // An invitation's Google step lives on /signup, which shares the tab's
  // saved code; the callback returns there with the proof, so this page only
  // starts it.
  const invite = oidcStartInvite(purpose, fragment, sessionStorage), result = typeof boot.result === "string" ? boot.result : ""
  const next = typeof boot.next === "string" && /^\/(?![\/\\])/.test(boot.next) ? boot.next : "/workspaces"
  function click(action: string, work: () => Promise<void>) { const button = find<HTMLButtonElement>(`[data-action="${action}"]`); button?.addEventListener("click", () => { void withBusy(button, "Waiting...", work) }) }
  click("oidc-start", async () => {
    let stepUp: { nonce: string; assertion: unknown } | undefined
    if (purpose === "link") {
      const started = await api<{ nonce: string; options: PublicKeyCredentialRequestOptionsJSON }>("/api/account/stepup/start", { action: { type: "identity.link", provider: "google" } })
      stepUp = { nonce: started.nonce, assertion: await startAuthentication({ optionsJSON: started.options }) }
    }
    const { url } = await api<{ url: string }>("/api/auth/oidc/google/start", { purpose, ...(invite ? { invite } : {}), ...(workspace ? { workspace } : {}), next, ...(stepUp ? { stepUp } : {}), ...(params.has("action") ? { action: JSON.parse(params.get("action")!) as unknown } : {}), ...(params.has("rule") ? { rule: JSON.parse(params.get("rule")!) as unknown } : {}) }).catch((failure: unknown) => {
      // An invitation the vault no longer has active: its saved code goes, so no later step sends it.
      if (invite && failure instanceof VaultFailure && failure.body.reason === "invite_inactive") sessionStorage.removeItem(INVITE_KEY)
      throw failure
    })
    location.assign(url)
  })
  click("oidc-signin", async () => { const started = await api<{ flow: string; options: PublicKeyCredentialRequestOptionsJSON }>("/api/auth/signin/options", { oidcResult: result }); await api("/api/auth/signin/verify", { flow: started.flow, response: await startAuthentication({ optionsJSON: started.options }) }); location.assign(next) })
  click("oidc-link", async () => { const identity = boot.identity as { email: string; subject: string }; await api("/api/account/identities/link", { result, email: identity.email, subject: identity.subject }); location.assign("/account") })
  click("oidc-gate", async () => { await api("/api/auth/oidc/google/gate", { result }); location.assign(next) })
}
