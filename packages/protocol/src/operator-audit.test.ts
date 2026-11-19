import { describe, expect, it } from "bun:test"
import { operatorAuditQuery, operatorAuditSearch } from "./operator-audit.ts"

describe("the Audit view's query", () => {
  it("takes an empty field as no filter, and refuses a filter that is not one", () => {
    expect(operatorAuditQuery(new URLSearchParams("actor=&action=platform.&target=&from=2026-11-01&to="))).toEqual({ ok: true, query: { action: "platform.", from: "2026-11-01" } })
    for (const bad of ["from=1 Nov", "before=x", "who=alex", `actor=${"a".repeat(129)}`]) expect(operatorAuditQuery(new URLSearchParams(bad)).ok).toBe(false)
  })

  it("keeps the filters in the next page's address", () => {
    expect(operatorAuditSearch({ actor: "acc_tom", to: "2026-11-02" }, "1800000000000.dpe_1")).toBe("?actor=acc_tom&to=2026-11-02&before=1800000000000.dpe_1")
    expect(operatorAuditSearch({})).toBe("")
  })
})
