// HTML built only through the `html` tagged template: every interpolated
// value is escaped unless it is already an Html fragment made the same way.
// The vault's html.ts without its vault-path and app-link helpers.

export class Html {
  readonly value: string
  constructor(value: string) {
    this.value = value
  }
  toString(): string {
    return this.value
  }
}

export type HtmlValue = Html | string | number | boolean | null | undefined | readonly HtmlValue[]

const ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" }

export function escapeHtml(text: string): string {
  return text.replace(/[&<>"'`]/g, (c) => ESCAPES[c] as string)
}

function render(value: HtmlValue): string {
  if (value === null || value === undefined || typeof value === "boolean") return ""
  if (value instanceof Html) return value.value
  if (Array.isArray(value)) return value.map(render).join("")
  return escapeHtml(String(value))
}

export function html(strings: TemplateStringsArray, ...values: HtmlValue[]): Html {
  let out = strings[0] ?? ""
  for (let i = 0; i < values.length; i++) out += render(values[i] as HtmlValue) + (strings[i + 1] ?? "")
  return new Html(out)
}

// A link in a page: a same-origin path, an http(s) URL or a mailto: link;
// anything else becomes inert.
export function safeHref(url: string): string {
  if (url.startsWith("/") && !url.startsWith("//") && !url.startsWith("/\\")) return url
  try {
    const parsed = new URL(url)
    return parsed.protocol === "https:" || parsed.protocol === "http:" || parsed.protocol === "mailto:" ? parsed.href : "#"
  } catch {
    return "#"
  }
}
