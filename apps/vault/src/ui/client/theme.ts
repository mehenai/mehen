// Loaded blocking in <head> as /assets/theme.js, before the stylesheet
// paints, so a chosen appearance applies on the first frame. Light is the
// default and needs nothing; it reads one localStorage key, accepts only
// "dark" or "system", sets data-theme on the document element and the
// browser bar's theme-color to match, and does nothing else. No imports: it
// is built on its own by build-ui.ts (the colours mirror appearance.ts).

const THEME_KEY = "mehen-theme"

try {
  const stored = localStorage.getItem(THEME_KEY)
  if (stored === "dark" || stored === "system") {
    document.documentElement.dataset.theme = stored
    const dark = stored === "dark" || matchMedia("(prefers-color-scheme: dark)").matches
    if (dark) document.querySelector('meta[name="theme-color"]')?.setAttribute("content", "#0f1626")
  }
} catch {
  // Storage can be unavailable (private mode, a blocked origin): light applies.
}
