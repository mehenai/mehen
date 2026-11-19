// Whether a plain value looks like a secret. The vault refuses such a value
// as a plain project variable or override; `mehen adopt` uses the same rule
// to tell config from secrets on a machine.

import { type ItemKind, KINDS } from "./kinds.ts"
import { TEMPLATES } from "./templates.ts"

const TEMPLATE_PREFIXES = [...new Set(Object.values(TEMPLATES).flatMap((t) => t.prefixes ?? []))].sort((a, b) => b.length - a.length)

function shannonBitsPerChar(text: string): number {
  const counts = new Map<string, number>()
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let bits = 0
  for (const n of counts.values()) {
    const p = n / text.length
    bits -= p * Math.log2(p)
  }
  return bits
}

// A canonical UUID: an id (a project, client or tenant id) far more often
// than a secret, so on its own it is not random-looking enough to refuse.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

// Why a plain value looks like a secret, or null. Never echoes the value.
export function secretLikeness(value: string): string | null {
  if (/-----BEGIN [A-Z0-9 ]*-----/.test(value)) return "it contains a PEM block"
  if (/[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i.test(value)) return "it is a URL with a password in it"
  for (const token of value.split(/[\s"'`=:,;()[\]{}<>]+/)) {
    const prefix = TEMPLATE_PREFIXES.find((p) => token.startsWith(p) && token.length > p.length + 8)
    if (prefix) return `it starts like a provider key ("${prefix}")`
    for (const part of token.split(/[./?&#@]+/)) {
      if (part.length >= 24 && !UUID.test(part) && /[A-Za-z]/.test(part) && /[0-9]/.test(part) && shannonBitsPerChar(part) >= 3.5) return "it contains a long random-looking string"
    }
  }
  return null
}

// Why the vault refuses a public field sent with an item of this kind, or
// null: the vault keeps public fields in the clear. `mehen adopt plan
// --check` and submit apply the same rule. Never echoes the value.
export function publicFieldRefusal(kind: ItemKind, name: string, value: string): string | null {
  const spec = KINDS[kind]
  const field = spec.fields.find((f) => f.name === name)
  if (!field || field.secret) return `"${name}" is not a public field of a ${spec.label}.`
  // An SSH public key is public by definition, and long and random-looking.
  if (!(kind === "ssh-key" && name === "public_key") && secretLikeness(value) !== null) return `"${name}" looks like a secret; send it sealed, as a secret field.`
  return null
}
