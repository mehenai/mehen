export function oidcFragment(hash: string): { state: string; flow: string } | null { const params = new URLSearchParams(hash.replace(/^#/, "")), state = params.get("state"), flow = params.get("flow"); return state && flow ? { state, flow } : null }
export function clearOidcFragment(host: { location: { hash: string; pathname: string; search: string }; history: { replaceState(data: unknown, unused: string, url: string): void } }): string { const fragment = host.location.hash; if (fragment) host.history.replaceState(null, "", host.location.pathname + host.location.search); return fragment }
// The invitation code this tab keeps for /signup, where an invitation's
// Google step returns.
export const INVITE_KEY = "mehen.oidc.invite"
// The invitation code a Google start from /auth/oidc/verify carries: only an
// invitation's own, from its fragment or the code saved in this tab. A
// sign-in, link or check carries none, so a code an invitation followed
// earlier in this tab left behind never rides on it.
export function oidcStartInvite(purpose: string, fragment: string, tab: Pick<Storage, "getItem" | "setItem">): string | undefined {
  if (purpose !== "invite") return undefined
  if (fragment) tab.setItem(INVITE_KEY, new URLSearchParams(fragment.slice(1)).get("invite") ?? decodeURIComponent(fragment.slice(1)))
  return tab.getItem(INVITE_KEY) ?? undefined
}
