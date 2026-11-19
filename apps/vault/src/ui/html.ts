// HTML built only through the `html` tagged template: every interpolated
// value is escaped unless it is already an Html fragment made the same way.
// There is no raw-string escape hatch, so a name, reason or host from an
// agent can never become markup.

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

// Links the vault prints come from its own data; anything that is not a
// same-origin path or an http(s) URL becomes inert.
export function safeHref(url: string): string {
  if (url.startsWith("/") && !url.startsWith("//") && !url.startsWith("/\\")) return url
  try {
    const parsed = new URL(url)
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : "#"
  } catch {
    return "#"
  }
}

// A path on this vault: starts with one slash, no scheme, no `//` or `/\`
// host trick, no control characters. Anything else is not a vault path.
export function isVaultPath(path: string): boolean {
  return path.startsWith("/") && !path.startsWith("//") && !path.startsWith("/\\") && !/[\u0000-\u001F\u007F]/.test(path)
}

// Links into a native app. Only the vault builds these, from a fixed set of
// targets; a string from data can never become one.
export type NativeAppLink = "ask-again" | "open-app"

const NATIVE_APP_LINKS: Record<NativeAppLink, string> = {
  "ask-again": "jeff://ask?text=Try%20the%20vault%20link%20again",
  "open-app": "jeff://",
}

export function nativeAppHref(link: NativeAppLink): string {
  return NATIVE_APP_LINKS[link]
}
