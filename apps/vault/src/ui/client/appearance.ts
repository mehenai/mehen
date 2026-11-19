// The appearance choice: one localStorage key, applied as data-theme on the
// document element (theme.ts does the same at load, in the head, so the
// first frame is right). Light is the default and stores nothing; dark and
// following the system are kept. No DOM types here, so the server page and
// its tests can share the choices.

export const THEME_KEY = "mehen-theme"

export type Appearance = "light" | "dark" | "system"

export const DEFAULT_APPEARANCE: Appearance = "light"

export const APPEARANCES: { value: Appearance; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "Follow the system" },
]

// The browser bar's colour for a choice: the page ground of the scheme in
// force. theme.ts names the dark one too.
export const THEME_COLOURS = { light: "#f3ead8", dark: "#0f1626" } as const

export function themeColour(choice: Appearance, systemDark: boolean): string {
  const dark = choice === "dark" || (choice === "system" && systemDark)
  return dark ? THEME_COLOURS.dark : THEME_COLOURS.light
}

type Store = { getItem(key: string): string | null; setItem(key: string, value: string): void; removeItem(key: string): void }

type Themed = { dataset: Record<string, string | undefined> }

export function readAppearance(storage: Pick<Store, "getItem">): Appearance {
  try {
    const stored = storage.getItem(THEME_KEY)
    return stored === "dark" || stored === "system" ? stored : DEFAULT_APPEARANCE
  } catch {
    return DEFAULT_APPEARANCE
  }
}

export function applyAppearance(root: Themed, storage: Pick<Store, "setItem" | "removeItem">, choice: Appearance): void {
  try {
    if (choice === DEFAULT_APPEARANCE) storage.removeItem(THEME_KEY)
    else storage.setItem(THEME_KEY, choice)
  } catch {
    // Storage unavailable: the choice still applies to this page.
  }
  if (choice === DEFAULT_APPEARANCE) delete root.dataset.theme
  else root.dataset.theme = choice
}

// "expires in 6 days" from an invite's expiry, or the time itself when it
// cannot be read.
export function inviteExpiryWords(expiresAt: string, now: number): string {
  const ms = Date.parse(expiresAt) - now
  if (Number.isNaN(ms)) return `expires at ${expiresAt}`
  if (ms <= 0) return "has already expired"
  const hours = Math.max(1, Math.round(ms / 3_600_000))
  if (hours < 48) return `expires in ${hours} hour${hours === 1 ? "" : "s"}`
  const days = Math.round(hours / 24)
  return `expires in ${days} days`
}

// What an invite's role means, for the line under its link.
export function inviteRoleWords(role: "owner" | "member"): string {
  return role === "owner" ? "This link makes them an owner: they can approve machines, invite people and unfreeze the vault." : "This link makes them a member."
}
