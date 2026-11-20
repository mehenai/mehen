// Placeholders stand in for secrets wherever a program insists on having
// "the key" in its environment or config but only ever sends it over HTTP.
// The program gets `sk-proj-jvphQ3r...`, the local relay swaps it for the
// real value on the way out to a bound host only, and the real value never
// reaches the machine.
//
// A placeholder keeps the real secret's well-known prefix (so SDKs that
// check the shape of a key are satisfied) followed by a fixed core:
// "jvph" and 24 base62 characters. Placeholders are random per run, so a
// leaked one is worthless outside that run and its proxy, and seeing one
// anywhere else (a gist, a log, an unbound host) is a tripwire.

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
export const PLACEHOLDER_CORE = /jvph[0-9A-Za-z]{24}/g
const CORE_LENGTH = 28

// Prefixes that SDKs and secret scanners use to recognise a key. Longest
// first so "sk-proj-" wins over "sk-".
const KNOWN_PREFIXES = [
  "sk-ant-api03-", "sk-ant-", "sk-proj-", "sk-svcacct-", "sk-or-v1-", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_",
  "github_pat_", "ghp_", "gho_", "ghs_", "ghu_", "glpat-", "xoxb-", "xoxp-", "xapp-", "lin_api_", "secret_", "ntn_",
  "sk-", "AKIA", "AIza", "hf_", "gsk_", "pplx-", "re_", "SG.", "key-", "dp.st.", "phc_", "phx_", "sntrys_", "sntryu_",
  "npm_", "pat-na1-", "pat-eu1-", "fc-", "r8_", "xai-", "sbp_", "dop_v1_", "rnd_", "pscale_tkn_",
].sort((a, b) => b.length - a.length)

export function secretPrefix(value: string): string {
  for (const prefix of KNOWN_PREFIXES) if (value.startsWith(prefix)) return prefix
  return ""
}

function randomBase62(length: number): string {
  const out: string[] = []
  const bytes = new Uint8Array(length * 2)
  while (out.length < length) {
    crypto.getRandomValues(bytes)
    for (const b of bytes) {
      // 248 = 4 * 62: reject the tail to keep the distribution uniform.
      if (b < 248 && out.length < length) out.push(BASE62[b % 62] as string)
    }
  }
  return out.join("")
}

export function newPlaceholder(realValueShapeHint = ""): string {
  return `${secretPrefix(realValueShapeHint)}jvph${randomBase62(CORE_LENGTH - 4)}`
}

export function placeholderCore(placeholder: string): string | null {
  const match = placeholder.match(/jvph[0-9A-Za-z]{24}$/)
  return match ? match[0] : null
}

export function findPlaceholders(text: string): string[] {
  return [...new Set(text.match(PLACEHOLDER_CORE) ?? [])]
}

export function containsPlaceholder(text: string): boolean {
  PLACEHOLDER_CORE.lastIndex = 0
  const found = PLACEHOLDER_CORE.test(text)
  PLACEHOLDER_CORE.lastIndex = 0
  return found
}

export type PlaceholderLookup = (core: string) => { placeholder: string; value: string } | null

// Swaps every known placeholder for its real value. The whole placeholder,
// preserved prefix included, becomes the real value (which carries its own
// prefix); a bare core whose prefix was stripped becomes the real value too.
// Unknown cores are left alone for the caller to refuse.
export function replacePlaceholders(text: string, lookup: PlaceholderLookup): { text: string; unknown: string[]; used: string[] } {
  const unknown = new Set<string>()
  const used = new Set<string>()
  let out = ""
  let last = 0
  for (const match of text.matchAll(PLACEHOLDER_CORE)) {
    const core = match[0]
    const at = match.index ?? 0
    const entry = lookup(core)
    if (entry === null) {
      unknown.add(core)
      continue
    }
    used.add(core)
    const prefix = entry.placeholder.slice(0, entry.placeholder.length - core.length)
    const start = prefix !== "" && text.slice(Math.max(last, at - prefix.length), at) === prefix ? at - prefix.length : at
    out += text.slice(last, start) + entry.value
    last = at + core.length
  }
  out += text.slice(last)
  return { text: out, unknown: [...unknown], used: [...used] }
}
