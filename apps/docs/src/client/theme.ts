// Loaded blocking in <head> as /theme.js, before the stylesheet paints, so a
// chosen colour scheme applies on the first frame. The docs follow the
// system unless the reader picked light or dark with the toggle: it reads
// one localStorage key, accepts only "light" or "dark", sets data-theme on
// the document element and the browser bar's colour to match, and does
// nothing else. The app's theme.ts with the docs' own key. No imports.

const THEME_KEY = "mehen-docs-theme"

try {
  const stored = localStorage.getItem(THEME_KEY)
  if (stored === "light" || stored === "dark") {
    document.documentElement.dataset.theme = stored
    const colour = stored === "dark" ? "#0f1626" : "#f3ead8"
    for (const meta of document.querySelectorAll('meta[name="theme-color"]')) meta.setAttribute("content", colour)
  }
} catch {
  // Storage can be unavailable (private mode, a blocked origin): the system's scheme applies.
}
