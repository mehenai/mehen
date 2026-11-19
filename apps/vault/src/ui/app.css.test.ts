// The stylesheet invariants that keep overflow structurally impossible,
// checked on the source sheets in client/:
// nothing in the shared sheets is nowrap unless it is one short token or
// cut off with an ellipsis; every shared component lets its children
// shrink below their content; and every class the shared helpers and the
// touched markup emit has a rule. Page sheets may reuse and extend shared
// classes; this does not police them. It lives here, in the vault project,
// because import.meta.glob is typed by test/env.d.ts, which the browser
// project (client/tsconfig.json) does not include.

import { describe, expect, it } from "vitest"

const SOURCES = import.meta.glob<string>(["./client/app.css", "./client/shell.css", "./client/bar.css", "./client/intake.css", "./client/connect.css", "./client/brand-marks.css", "./client/pages/*.css", "./components.ts", "./pages/workspace-audit.ts", "./inbox-row.ts", "./layout.ts", "./pages/needs-you.ts", "./pages/workspace-pending.ts", "./pages/people.ts", "./pages/machines.ts", "./pages/workspaces.ts", "./pages/workspace-projects.ts", "./pages/oidc-verify.ts", "./pages/connect.ts", "./pages/workspace-settings.ts", "./pages/mandates.ts"], { query: "?raw", import: "default", eager: true })

function source(file: string): string {
  const text = SOURCES[file]
  if (text === undefined) throw new Error(`${file} was not loaded`)
  return text
}

type Rule = { selectors: string[]; body: string }

// The innermost { } blocks of a sheet, so a rule inside @media or
// @container counts as a rule. Comments are dropped first.
function rules(css: string): Rule[] {
  const bare = css.replace(/\/\*[\s\S]*?\*\//g, "")
  return [...bare.matchAll(/([^{}]+)\{([^{}]*)\}/g)]
    .map((m) => ({ selectors: (m[1] ?? "").split(",").map((s) => s.trim().replace(/\s+/g, " ")), body: m[2] ?? "" }))
    .filter((r) => !r.selectors.some((s) => s.startsWith("@") || /^(from|to|\d+%)$/.test(s)))
}

function declares(body: string, property: string, value: RegExp): boolean {
  return body.split(";").some((d) => {
    const [p, ...v] = d.split(":")
    return p?.trim() === property && value.test(v.join(":").trim())
  })
}

const SHARED = ["./client/app.css", "./client/shell.css", "./client/bar.css"]

// One short token each, in a box that wraps or ellipsises it.
const NOWRAP_TOKENS = [".pill", ".badge", ".chip", ".stat", "kbd", ".switcher-slug", ".request-line b", ".request-line .method", ".user-name", ".brand-sub", ".tabs a span"]

describe("the first overflow rule: nothing is nowrap unless it is one short token", () => {
  it("allows nowrap in the shared sheets only on a short token, a cut-off line, a scroller or a hidden label", () => {
    const offenders: string[] = []
    for (const file of SHARED) {
      for (const rule of rules(source(file))) {
        if (!declares(rule.body, "white-space", /^nowrap$/)) continue
        const cutOff = declares(rule.body, "text-overflow", /ellipsis/)
        const scrolls = declares(rule.body, "overflow-x", /^(auto|scroll)$/)
        const hidden = declares(rule.body, "clip-path", /inset\(50%\)/)
        if (cutOff || scrolls || hidden) continue
        for (const selector of rule.selectors) if (!NOWRAP_TOKENS.some((t) => selector === t || selector.endsWith(` ${t}`))) offenders.push(`${file}: ${selector}`)
      }
    }
    expect(offenders).toEqual([])
  })

  it("lets buttons wrap", () => {
    const buttons = rules(source("./client/app.css")).filter((r) => r.selectors.includes(".btn") || r.selectors.includes(".button"))
    expect(buttons.length).toBeGreaterThan(0)
    for (const rule of buttons) expect(declares(rule.body, "white-space", /nowrap/)).toBe(false)
  })
})

// The components section 4 names: each gives its children min-width: 0.
const SHRINKING = [".row", ".kv", ".summary", ".actions", ".card-head", ".page-head", ".member-actions", ".share-row", ".inline-form", ".manage-row", ".copybox", ".focus-top", ".notice", ".state"]

describe("the second overflow rule: a shared component's children may shrink", () => {
  const appRules = rules(source("./client/app.css"))

  it.each(SHRINKING)("%s > * has min-width: 0", (component) => {
    expect(appRules.some((r) => r.selectors.includes(`${component} > *`) && declares(r.body, "min-width", /^0$/))).toBe(true)
  })

  it("gives the grids that hold text tracks of minmax(0, ...)", () => {
    for (const grid of [".kv", ".state"]) {
      const columns = appRules.filter((r) => r.selectors.includes(grid) && /grid-template-columns/.test(r.body))
      expect(columns.length, grid).toBeGreaterThan(0)
      for (const r of columns) expect(r.body, grid).toMatch(/minmax\(0, 1fr\)/)
    }
  })

  it("wraps a button row and cards long tokens", () => {
    expect(appRules.some((r) => r.selectors.includes(".actions") && declares(r.body, "flex-wrap", /^wrap$/))).toBe(true)
    expect(appRules.some((r) => r.selectors.includes(".card") && declares(r.body, "overflow-wrap", /^anywhere$/))).toBe(true)
  })

  it("lets the switcher's name shorten instead of centring it to its text", () => {
    const summary = rules(source("./client/shell.css")).find((r) => r.selectors.includes(".switcher summary"))
    expect(summary && declares(summary.body, "align-items", /^stretch$/)).toBe(true)
  })

  it("lays the sign-up recovery codes in a grid whose columns hold a whole code and leave the next number room", () => {
    const codes = rules(source("./client/pages/people.css")).find((r) => r.selectors.includes("ol.codes"))
    expect(codes && declares(codes.body, "columns", /./)).toBe(false)
    expect(codes && declares(codes.body, "display", /^grid$/)).toBe(true)
    expect(codes && declares(codes.body, "grid-template-columns", /^repeat\(auto-fill, minmax\(19ch, 1fr\)\)$/)).toBe(true)
    expect(codes && declares(codes.body, "gap", /^\S+ 3em$/)).toBe(true)
  })

  it("keeps the eyebrow a block unless it leads with an icon", () => {
    const eyebrow = appRules.find((r) => r.selectors.includes(".eyebrow") && /display/.test(r.body))
    expect(eyebrow && declares(eyebrow.body, "display", /^block$/)).toBe(true)
    expect(appRules.some((r) => r.selectors.includes(".eyebrow:has(> .i)") && declares(r.body, "display", /^flex$/))).toBe(true)
  })

  it("keeps the card gap between a page's notice and the search below it, which otherwise sets its own top margin to nothing", () => {
    expect(appRules.some((r) => r.selectors.includes(".page > .notice + .toolbar") && declares(r.body, "margin-top", /^var\(--s4\)$/))).toBe(true)
  })
})

// Every class a sheet names, anywhere in a selector.
function definedClasses(): Set<string> {
  const names = new Set<string>()
  for (const [file, text] of Object.entries(SOURCES)) {
    if (!file.endsWith(".css")) continue
    for (const rule of rules(text)) for (const s of rule.selectors) for (const m of s.matchAll(/\.(-?[_a-zA-Z][\w-]*)/g)) names.add(m[1] as string)
  }
  return names
}

// The literal class names in a module's class="..." attributes; a name
// built from an interpolation (c-${colour}) is not literal and is skipped.
function usedClasses(file: string): string[] {
  const names = new Set<string>()
  for (const m of source(file).matchAll(/class="([^"]*)"/g)) {
    for (const c of (m[1] ?? "").replace(/\$\{[^}]*\}/g, "$").split(/\s+/)) if (/^[a-z][\w-]*$/.test(c)) names.add(c)
  }
  return [...names]
}

describe("classes the markup uses have a rule", () => {
  const defined = definedClasses()

  it.each(["./components.ts", "./pages/workspace-audit.ts", "./inbox-row.ts", "./layout.ts", "./pages/needs-you.ts", "./pages/workspace-pending.ts", "./pages/workspaces.ts", "./pages/workspace-settings.ts", "./pages/mandates.ts"])("every class in %s is styled", (file) => {
    expect(usedClasses(file).filter((c) => !defined.has(c))).toEqual([])
  })

  it("styles the classes the workspace pages used without a rule", () => {
    const named = ["plain", "warning", "card-inset", "activation", "member-id", "invite-terms", "membership", "own-override", "share-who", "workspace-identity", "focus-card", "reconnect-note"]
    const used = new Set(["./pages/people.ts", "./pages/machines.ts", "./pages/workspaces.ts", "./pages/workspace-projects.ts", "./pages/oidc-verify.ts", "./pages/connect.ts"].flatMap(usedClasses))
    for (const c of named) expect(used.has(c), c).toBe(true)
    expect(named.filter((c) => !defined.has(c))).toEqual([])
  })

  it("gives the workspace audit sentence its own class, not the legacy two-column grid", () => {
    expect(usedClasses("./pages/workspace-audit.ts")).toContain("audit-sentence")
    expect(usedClasses("./pages/workspace-audit.ts")).not.toContain("audit-line")
  })
})
