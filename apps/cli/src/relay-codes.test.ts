// Pins which relay refusals from a vault that sends no Mehen-Forwarded the
// CLI treats as made before forwarding (http-client.ts): every code the
// vault's /v1/relay path can raise, read from its source, is classified as
// pre-forward or may-have-been-sent, never both, and what the relay route
// can raise after the upstream fetch is never pre-forward.

import { describe, expect, test } from "bun:test"
import { existsSync, readFileSync } from "node:fs"
import { dirname, join, relative, resolve } from "node:path"
import { ERROR_CODES, type ErrorCode } from "@mehen/protocol/api"
import { RELAY_MAY_HAVE_BEEN_SENT_CODES, RELAY_PRE_FORWARD_CODES } from "./http-client.ts"

const VAULT = resolve(import.meta.dir, "..", "..", "vault", "src")
// Where a relay can be refused: the Worker entry's own checks (rate limits,
// the version gate, the readiness check), the relay route and the device
// request it reads, and the workspace's authorisation of the request, with
// everything each imports. The entry point is read alone, as it imports
// every route.
const ENTRY = ["index.ts"]
const ROOTS = ["rate-limits.ts", "cli-version.ts", "directory/workspace-cutover.ts", "routes/relay.ts", "routes/context.ts", "vault/areas/relay-workspace.ts", "vault/areas/relay.ts"]
// After the upstream fetch: the forwarding and what it imports.
const AFTER_FORWARD = ["relay/forward.ts"]

const PATTERNS = [/VaultError\(\s*["'`]([a-z_]+)["'`]/g, /\berror:\s*["']([a-z_]+)["']/g, /\bno\(\s*["']([a-z_]+)["']/g, /\bcode:\s*["']([a-z_]+)["']/g]
const CODES = new Set<string>(ERROR_CODES)

function closure(roots: readonly string[], follow: boolean): Set<string> {
  const seen = new Set<string>()
  const queue = roots.map((root) => join(VAULT, root))
  while (queue.length > 0) {
    const file = queue.pop() as string
    if (seen.has(file) || !existsSync(file)) continue
    seen.add(file)
    if (!follow || file === join(VAULT, "index.ts")) continue
    for (const match of readFileSync(file, "utf8").matchAll(/(?:from|import)\s*\(?\s*["'](\.[^"']+)["']/g)) {
      const target = resolve(dirname(file), match[1] as string)
      if (target.startsWith(VAULT)) queue.push(target)
    }
  }
  return seen
}
function codesIn(files: Iterable<string>): Map<ErrorCode, string[]> {
  const found = new Map<ErrorCode, string[]>()
  for (const file of files) {
    const text = readFileSync(file, "utf8")
    for (const pattern of PATTERNS) for (const match of text.matchAll(pattern)) {
      const code = match[1] as ErrorCode
      if (CODES.has(code)) found.set(code, [...(found.get(code) ?? []), relative(VAULT, file)])
    }
  }
  return found
}

describe("relay refusals from a vault that does not say whether it forwarded", () => {
  const relayPath = new Set([...closure(ENTRY, false), ...closure(ROOTS, true)])
  const raised = codesIn(relayPath)

  test("reads the vault's relay path", () => {
    expect(relayPath.size).toBeGreaterThan(10)
    expect(raised.has("approval_required")).toBe(true)
    expect(raised.has("upstream_failed")).toBe(true)
  })

  test("classifies every code that path can raise", () => {
    const unclassified = [...raised.keys()].filter((code) => !RELAY_PRE_FORWARD_CODES.has(code) && !RELAY_MAY_HAVE_BEEN_SENT_CODES.has(code))
    expect(unclassified.map((code) => `${code} (${raised.get(code)?.slice(0, 3).join(", ")})`)).toEqual([])
  })

  test("never calls a code both, and never pre-forward one raised after the upstream fetch", () => {
    expect([...RELAY_PRE_FORWARD_CODES].filter((code) => RELAY_MAY_HAVE_BEEN_SENT_CODES.has(code))).toEqual([])
    const after = codesIn(closure(AFTER_FORWARD, true))
    expect(after.has("upstream_failed") && after.has("too_large")).toBe(true)
    // The route answers anything else that goes wrong while forwarding as internal.
    for (const code of [...after.keys(), "internal" as const]) expect([code, RELAY_MAY_HAVE_BEEN_SENT_CODES.has(code)]).toEqual([code, true])
  })

  test("names only real codes", () => {
    for (const code of [...RELAY_PRE_FORWARD_CODES, ...RELAY_MAY_HAVE_BEEN_SENT_CODES]) expect(CODES.has(code)).toBe(true)
  })
})
