import { describe, expect, it } from "bun:test"
import { OperatorAccountListQuerySchema } from "./operator-accounts.ts"

describe("the Accounts view's list query", () => {
  it("takes a search, one of the filters and the next page's cursor, nothing else", () => {
    expect(OperatorAccountListQuerySchema.parse({})).toEqual({ filter: "all" })
    expect(OperatorAccountListQuerySchema.parse({ q: " kim ", filter: "suspended", before: "1800000000000~acc_kim" })).toEqual({ q: "kim", filter: "suspended", before: "1800000000000~acc_kim" })
    for (const input of [{ filter: "everyone" }, { before: "yesterday" }, { before: "1~kim" }, { q: "x".repeat(255) }, { page: "2" }]) expect(OperatorAccountListQuerySchema.safeParse(input).success, JSON.stringify(input)).toBe(false)
  })
})
