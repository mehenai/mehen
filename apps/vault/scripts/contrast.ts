// WCAG 2.x contrast for every text pairing app.css uses, in both schemes.
// The tokens here mirror the light-dark() pairs in the :root block of
// src/ui/client/app.css (light first, dark second), with the brand palette
// names resolved to their hex: translucent tints are composited on the
// surface they sit on, so each ratio is the one a browser paints.
// Prints a Markdown table and exits 1 if any body or small text pairing is
// under 4.5:1 or any large-text pairing under 3:1.
//
//   bun scripts/contrast.ts

type Rgb = [number, number, number]

// A colour as the stylesheet writes it: a hex, an rgb() with alpha, or an
// oklch() with an optional alpha. Alpha colours resolve over a backdrop.
type Token = string

// Midnight: the Papyrus page's vault band.
export const DARK: Record<string, Token> = {
  canvas: "#0f1626",
  sidebar: "#0b111e",
  surface: "#18223a",
  raised: "#1e2a45",
  overlay: "#1e2a45",
  "code-bg": "#0c1322",
  hover: "rgb(251 247 238 / 0.05)",
  active: "rgb(251 247 238 / 0.09)",
  "line-strong": "rgb(251 247 238 / 0.18)",
  ink: "#fbf7ee",
  "ink-muted": "#c9cedb",
  "ink-faint": "#9aa3b8",
  accent: "#6ccfc6",
  "accent-strong": "#8fdcd5",
  "accent-soft": "rgb(108 207 198 / 0.14)",
  "accent-ink": "#0f1626",
  primary: "#f2a65a",
  "primary-strong": "#f6b878",
  "primary-soft": "rgb(242 166 90 / 0.14)",
  "primary-ink": "#0f1626",
  ok: "#7fd29a",
  "ok-soft": "rgb(127 210 154 / 0.14)",
  warn: "#ecc45a",
  "warn-soft": "rgb(236 196 90 / 0.12)",
  danger: "#f08a6a",
  "danger-soft": "rgb(240 138 106 / 0.14)",
  "danger-ink": "#0f1626",
}

// Papyrus.
export const LIGHT: Record<string, Token> = {
  canvas: "#f3ead8",
  sidebar: "#e9dcc2",
  surface: "#fbf7ee",
  raised: "#fffdf7",
  overlay: "#fbf7ee",
  "code-bg": "#f3ead8",
  hover: "rgb(28 25 21 / 0.05)",
  active: "rgb(28 25 21 / 0.08)",
  "line-strong": "rgb(28 25 21 / 0.2)",
  ink: "#1c1915",
  "ink-muted": "#4b443b",
  "ink-faint": "#665d4f",
  accent: "#1f6f73",
  "accent-strong": "#164f54",
  "accent-soft": "rgb(31 111 115 / 0.12)",
  "accent-ink": "#fbf7ee",
  primary: "#c4461f",
  "primary-strong": "#b03d1a",
  "primary-soft": "rgb(212 80 43 / 0.12)",
  "primary-ink": "#fbf7ee",
  ok: "#266f44",
  "ok-soft": "rgb(38 111 68 / 0.12)",
  warn: "#8a5a12",
  "warn-soft": "rgb(138 90 18 / 0.12)",
  danger: "#ab2a22",
  "danger-soft": "rgb(171 42 34 / 0.1)",
  "danger-ink": "#fbf7ee",
}

// [text, background, backdrop for a translucent background, where it is used, large text?]
type Pair = { fg: string; bg: string; over?: string; where: string; large?: boolean }

const PAIRS: Pair[] = [
  { fg: "ink", bg: "canvas", where: "body on the page" },
  { fg: "ink", bg: "surface", where: "body on a card" },
  { fg: "ink", bg: "sidebar", where: "the rail" },
  { fg: "ink", bg: "raised", where: "row titles on a tile, tags" },
  { fg: "ink", bg: "overlay", where: "the palette, dialogs" },
  { fg: "ink", bg: "code-bg", where: "code, fingerprint boxes" },
  { fg: "ink", bg: "active", over: "surface", where: "tags, kbd, a pressed segment" },
  { fg: "ink", bg: "hover", over: "surface", where: "a hovered row" },
  { fg: "ink-muted", bg: "canvas", where: "secondary copy on the page" },
  { fg: "ink-muted", bg: "surface", where: "secondary copy, row subtitles, kv keys" },
  { fg: "ink-muted", bg: "sidebar", where: "rail links" },
  { fg: "ink-muted", bg: "raised", where: "letter tiles, hovered rows" },
  { fg: "ink-muted", bg: "code-bg", where: "muted text inside code blocks" },
  { fg: "ink-muted", bg: "active", over: "surface", where: "tag text, kbd hints" },
  { fg: "ink-faint", bg: "canvas", where: "page-level captions" },
  { fg: "ink-faint", bg: "surface", where: "activity timestamps, eyebrows, placeholders" },
  { fg: "ink-faint", bg: "sidebar", where: "the rail's role line, the search hint" },
  { fg: "ink-faint", bg: "raised", where: "chart labels on a tile" },
  { fg: "ink-faint", bg: "code-bg", where: "the hint inside a copy box" },
  { fg: "ink-faint", bg: "active", over: "surface", where: "the count in a chip" },
  { fg: "ink-muted", bg: "warn-soft", over: "surface", where: "a muted line in a warning sentence or warn notice" },
  { fg: "accent", bg: "surface", where: "links, the current nav item" },
  { fg: "accent", bg: "canvas", where: "links on the page" },
  { fg: "accent", bg: "code-bg", where: "links inside code and copy boxes" },
  { fg: "accent-strong", bg: "sidebar", where: "the current rail item" },
  { fg: "accent", bg: "accent-soft", over: "surface", where: "accent pill, the hidden group" },
  { fg: "accent-strong", bg: "accent-soft", over: "canvas", where: "the current settings section, the current doc" },
  { fg: "accent-strong", bg: "accent-soft", over: "sidebar", where: "the current rail item" },
  { fg: "ink", bg: "accent-soft", over: "surface", where: "body inside an accent tint" },
  { fg: "ink-muted", bg: "accent-soft", over: "surface", where: "muted copy inside an accent tint" },
  { fg: "accent-ink", bg: "accent", where: "the avatar, step numbers, the toggle" },
  { fg: "primary", bg: "surface", where: "the request line's method" },
  { fg: "primary-ink", bg: "primary", where: "primary button, count badge" },
  { fg: "primary-ink", bg: "primary-strong", where: "primary button, hover" },
  { fg: "ink", bg: "primary-soft", over: "surface", where: "body inside the decision card's ring" },
  { fg: "ok", bg: "surface", where: "ok text, rule notes" },
  { fg: "ok", bg: "ok-soft", over: "surface", where: "ok pill, verified card eyebrow, typed group" },
  { fg: "ink", bg: "ok-soft", over: "surface", where: "body on a verified card" },
  { fg: "ink-muted", bg: "ok-soft", over: "surface", where: "secondary copy on a verified card" },
  { fg: "warn", bg: "surface", where: "warn text, wider choices" },
  { fg: "warn", bg: "warn-soft", over: "surface", where: "warn pill, the callout's bold" },
  { fg: "ink", bg: "warn-soft", over: "surface", where: "body in a callout" },
  { fg: "danger", bg: "surface", where: "danger text, refused, the wrong group" },
  { fg: "danger", bg: "danger-soft", over: "surface", where: "danger pill, warning card heading, a hidden-character marker" },
  { fg: "ink", bg: "danger-soft", over: "surface", where: "body on a warning card" },
  { fg: "danger-ink", bg: "danger", where: "the filled danger button" },
  { fg: "canvas", bg: "ink", where: "a pressed chip" },
]

function hexToRgb(hex: string): Rgb {
  const v = hex.replace("#", "")
  return [0, 2, 4].map((i) => parseInt(v.slice(i, i + 2), 16) / 255) as Rgb
}

function clamp01(x: number): number {
  return Math.min(1, Math.max(0, x))
}

function linearToSrgb(c: number): number {
  const v = clamp01(c)
  return v <= 0.0031308 ? 12.92 * v : 1.055 * v ** (1 / 2.4) - 0.055
}

// OKLCH to sRGB, as CSS Color 4 specifies (Björn Ottosson's matrices).
function oklchToRgb(l: number, c: number, h: number): Rgb {
  const hr = (h * Math.PI) / 180
  const a = c * Math.cos(hr)
  const b = c * Math.sin(hr)
  const l_ = l + 0.3963377774 * a + 0.2158037573 * b
  const m_ = l - 0.1055613458 * a - 0.0638541728 * b
  const s_ = l - 0.0894841775 * a - 1.291485548 * b
  const l3 = l_ ** 3
  const m3 = m_ ** 3
  const s3 = s_ ** 3
  const r = 4.0767416621 * l3 - 3.3077115913 * m3 + 0.2309699292 * s3
  const g = -1.2684380046 * l3 + 2.6097574011 * m3 - 0.3413193965 * s3
  const bl = -0.0041960863 * l3 - 0.7034186147 * m3 + 1.707614701 * s3
  return [linearToSrgb(r), linearToSrgb(g), linearToSrgb(bl)]
}

type Parsed = { rgb: Rgb; alpha: number }

export function parseColour(token: Token): Parsed {
  if (token.startsWith("#")) return { rgb: hexToRgb(token), alpha: 1 }
  const rgb = /^rgb\(\s*(\d+)\s+(\d+)\s+(\d+)\s*(?:\/\s*([\d.]+))?\s*\)$/.exec(token)
  if (rgb) return { rgb: [Number(rgb[1]) / 255, Number(rgb[2]) / 255, Number(rgb[3]) / 255], alpha: rgb[4] === undefined ? 1 : Number(rgb[4]) }
  const oklch = /^oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*(?:\/\s*([\d.]+))?\s*\)$/.exec(token)
  if (oklch) return { rgb: oklchToRgb(Number(oklch[1]), Number(oklch[2]), Number(oklch[3])), alpha: oklch[4] === undefined ? 1 : Number(oklch[4]) }
  throw new Error(`cannot parse colour ${token}`)
}

function over(top: Parsed, backdrop: Rgb): Rgb {
  return top.rgb.map((c, i) => c * top.alpha + (backdrop[i] as number) * (1 - top.alpha)) as Rgb
}

function luminance([r, g, b]: Rgb): number {
  const lin = (c: number) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

export function ratio(fg: Rgb, bg: Rgb): number {
  const [l1, l2] = [luminance(fg), luminance(bg)].sort((x, y) => y - x) as [number, number]
  return (l1 + 0.05) / (l2 + 0.05)
}

export function toHex(rgb: Rgb): string {
  return `#${rgb.map((c) => Math.round(clamp01(c) * 255).toString(16).padStart(2, "0")).join("")}`
}

function resolve(scheme: Record<string, Token>, name: string, backdrop?: string): Rgb {
  const token = scheme[name]
  if (token === undefined) throw new Error(`no token ${name}`)
  const parsed = parseColour(token)
  if (parsed.alpha === 1) return parsed.rgb
  if (backdrop === undefined) throw new Error(`${name} is translucent and needs a backdrop`)
  return over(parsed, resolve(scheme, backdrop))
}

export type ContrastRow = { fg: string; bg: string; where: string; ratio: number; min: number; pass: boolean }

export function check(scheme: Record<string, Token>): ContrastRow[] {
  return PAIRS.map((p) => {
    const bg = resolve(scheme, p.bg, p.over)
    const fg = p.fg === p.bg ? bg : resolve(scheme, p.fg, p.over ?? p.bg)
    const r = ratio(fg, bg)
    const min = p.large ? 3 : 4.5
    return { fg: p.fg, bg: p.over ? `${p.bg} over ${p.over}` : p.bg, where: p.where, ratio: r, min, pass: r >= min }
  })
}

function table(name: string, scheme: Record<string, Token>): { md: string; ok: boolean } {
  const rows = check(scheme)
  const lines = rows.map((r) => {
    const fgHex = toHex(resolve(scheme, r.fg, r.bg.split(" over ")[1] ?? r.bg.split(" over ")[0]))
    return `| \`--${r.fg}\` ${fgHex} | \`--${r.bg}\` | ${r.where} | **${r.ratio.toFixed(2)}:1** ${r.pass ? "" : "FAIL"} |`
  })
  return { md: `**${name}**\n\n| Text | On | Used for | Ratio |\n|---|---|---|---|\n${lines.join("\n")}\n`, ok: rows.every((r) => r.pass) }
}

if (import.meta.main) {
  const d = table("Dark", DARK)
  const l = table("Light", LIGHT)
  console.log(`Accent hex: dark ${toHex(resolve(DARK, "accent"))}, light ${toHex(resolve(LIGHT, "accent"))}\n`)
  console.log(d.md)
  console.log(l.md)
  if (!d.ok || !l.ok) {
    console.error("a pairing is under the minimum")
    process.exit(1)
  }
}
