// A deep link's #fragment (/w/acme/people#confirm-mem_x) never reaches the
// server, so the sign-in redirect's ?next= cannot carry it. The browser keeps
// it across that redirect, so /signin finds it in its own address: the page
// keeps it in this tab's sessionStorage for the page `next` names, and once
// the passkey is accepted it goes to that page with the fragment put back.

export const SIGNIN_FRAGMENT_KEY = "mehen.signin.fragment"

type SavedFragment = { next: string; hash: string }

// A fragment worth carrying: one short line, nothing that is not printable.
export function carriedFragment(hash: string): string | null {
  return /^#[^\s\u0000-\u001f\u007f]{1,512}$/.test(hash) ? hash : null
}

// Where sign-in goes: `next`, with the fragment saved for exactly that page
// (or, failing that, the one in /signin's own address) when `next` has none.
export function signinDestination(next: string, saved: string | null, hash: string): string {
  if (next.includes("#")) return next
  let kept: string | null = null
  try {
    const value = JSON.parse(saved ?? "null") as Partial<SavedFragment> | null
    if (value !== null && value.next === next && typeof value.hash === "string") kept = carriedFragment(value.hash)
  } catch {
    kept = null
  }
  const fragment = kept ?? carriedFragment(hash)
  return fragment === null ? next : `${next}${fragment}`
}

export function rememberSigninFragment(next: string, hash: string): void {
  const fragment = carriedFragment(hash)
  if (fragment === null) return
  try {
    sessionStorage.setItem(SIGNIN_FRAGMENT_KEY, JSON.stringify({ next, hash: fragment } satisfies SavedFragment))
  } catch {
    // Without storage the fragment still in /signin's address is used.
  }
}

export function takeSigninFragment(next: string, hash: string): string {
  let saved: string | null = null
  try {
    saved = sessionStorage.getItem(SIGNIN_FRAGMENT_KEY)
    sessionStorage.removeItem(SIGNIN_FRAGMENT_KEY)
  } catch {
    saved = null
  }
  return signinDestination(next, saved, hash)
}
