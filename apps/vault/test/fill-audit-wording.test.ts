// item.fill rows (vault/areas/browser-workspace.ts fillAudit) as the audit
// page reads them: who typed which field of which credential into which
// page, a refusal in red with its reason in words, never a raw code, and a
// private credential's row with the origin and the field alone.

import { describe, expect, it } from "vitest"
import { type AuditLine, auditLine } from "../src/ui/wording.ts"

const ctx = { self: null, devices: new Map([["dev_mac", "mac-mini"]]) }
const words = (line: AuditLine) => `${line.actor}${line.pieces.map((p) => p.text).join("")}`
const shared = (detail: Record<string, unknown>) => auditLine({ actor: "device:dev_mac", action: "item.fill", target: "github-login", detail: JSON.stringify({ item: "itm_github01", origin: "https://github.com", field: "password", page: "/login", outcome: "typed", approval: "apr_1", ...detail }) }, ctx)
// The audit page passes a private row's own slug as its target.
const own = (outcome: string, field = "password", workload?: { id: string; label: string }) => auditLine({
  actor: "device:dev_mac",
  action: "item.fill",
  target: "own-login",
  detail: JSON.stringify({ actor: { kind: "device", device: "dev_mac", owner: { kind: "member", member: "mem_alex01" }, ...(workload ? { workload } : {}) }, session: null, item: "itm_own01", slug: "own-login", outcome, run: null, browser: { origin: "https://github.com", field } }),
}, ctx)

describe("item.fill in the audit", () => {
  it("says which field of which credential was typed into which page, and links the approval that allowed it", () => {
    const line = shared({})
    expect(words(line)).toBe("An agent on mac-mini typed the password of github-login into https://github.com/login")
    expect(line.pieces.filter((p) => p.as === "code").map((p) => p.text)).toEqual(["github-login", "https://github.com/login"])
    expect(line.link).toEqual({ href: "/a/apr_1", label: "Open the request" })
    expect(words(shared({ field: "totp" }))).toBe("An agent on mac-mini typed the one-time code of github-login into https://github.com/login")
    const free = shared({ field: "username", approval: null })
    expect(words(free)).toBe("An agent on mac-mini typed the username of github-login into https://github.com/login")
    expect(free.link).toEqual({ href: "/items/github-login", label: "Open the credential" })
  })

  it("shows a refusal in red with its reason in words, never the code", () => {
    for (const [code, reason] of [
      ["origin_mismatch", "that page is not one it may be typed into"],
      ["rate_limited", "too many in too short a time"],
      ["totp_unreadable", "its one-time code secret cannot be read"],
      ["something_new", null],
    ] as const) {
      const line = shared({ outcome: `refused:${code}`, approval: null })
      expect(words(line)).toBe(`An agent on mac-mini tried to type the password of github-login into https://github.com/login. Refused${reason !== null ? `: ${reason}` : ""}.`)
      expect(line.pieces.find((p) => p.as === "danger")?.text).toBe("Refused")
      expect(JSON.stringify(line)).not.toContain(code)
    }
  })

  it("names only the origin and the field on a private credential's row, with the task that asked", () => {
    const line = own("typed", "totp", { id: "wl_task01", label: "globex:grant-7f3k" })
    expect(words(line)).toBe("An agent on mac-mini typed the one-time code of own-login into https://github.com. Task: globex:grant-7f3k, as the machine named it")
    expect(line.link).toBeNull()
    expect(words(own("refused:origin_mismatch"))).toBe("An agent on mac-mini tried to type the password of own-login into https://github.com. Refused: that page is not one it may be typed into.")
  })
})
