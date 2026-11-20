// The keyboard shortcuts' tables and pure rules, with no DOM, so the
// server tests can check that every approval key only moves focus and
// that keys are ignored while typing. shortcuts.ts wires them.

export const GO_PLACES: Record<string, string> = { h: "/", m: "/devices", p: "/projects", a: "/audit", c: "/credentials" }

const WORKSPACE_GO: Record<string, { page: string; path: string }> = {
  h: { page: "home", path: "/" },
  m: { page: "machines", path: "/devices" },
  p: { page: "projects", path: "/projects" },
  a: { page: "audit", path: "/audit" },
  c: { page: "credentials", path: "/credentials" },
}

// On a workspace page, G then a letter goes to that workspace's page, and
// only to one its server serves.
export function workspaceGoPlaces(slug: string, pages: readonly string[]): Record<string, string> {
  const places: Record<string, string> = {}
  for (const [letter, place] of Object.entries(WORKSPACE_GO)) if (pages.includes(place.page)) places[letter] = `/w/${encodeURIComponent(slug)}${place.path}`
  return places
}

export const GO_WINDOW_MS = 1500

// The palette's key as the search box shows it: Command on an Apple
// device, Control everywhere else (both open it).
export function paletteKeyWords(platform: string): string {
  return /mac|iphone|ipad|ipod/i.test(platform) ? "⌘K" : "Ctrl K"
}

// Structural, so the server tests can check it without a DOM.
export function isTyping(target: EventTarget | { tagName?: unknown; isContentEditable?: unknown } | null): boolean {
  const node = target as { tagName?: unknown; isContentEditable?: unknown } | null
  if (node === null || typeof node.tagName !== "string") return false
  return node.tagName === "INPUT" || node.tagName === "TEXTAREA" || node.tagName === "SELECT" || node.isContentEditable === true
}

// What a single letter does on an approval page: every entry moves focus
// (or scrolls to the whole truth and focuses it). There is no kind that
// clicks, submits or decides, and the test holds that line.
export type KeyAction = { kind: "focus"; selector: string } | { kind: "jump"; selector: string }

export const APPROVAL_KEYS: Record<string, KeyAction> = {
  t: { kind: "focus", selector: '[data-input="code-matches"]' },
  w: { kind: "jump", selector: "#truth" },
  d: { kind: "focus", selector: '[data-action="deny"]' },
  // Only when enabled: a disabled or hidden Approve is left alone.
  y: { kind: "focus", selector: '[data-action="approve"]' },
}

// The row to move to from the one that has focus: the index of the row
// in `rows` plus or minus one, clamped; the first row when none has focus.
export function nextRowIndex(count: number, current: number, step: 1 | -1): number {
  if (count === 0) return -1
  if (current < 0) return step === 1 ? 0 : count - 1
  return Math.max(0, Math.min(count - 1, current + step))
}
