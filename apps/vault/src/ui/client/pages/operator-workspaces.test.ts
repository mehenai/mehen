// The restore form's moment: typed with its zone, sent as the vault keeps
// it (UTC with milliseconds), never read in the browser's local time.
import { describe, expect, it } from "vitest"
import { restorePoint } from "./operator-workspaces.ts"

describe("a restore's point in time", () => {
  it("takes a time with Z or an offset and sends it in UTC with milliseconds", () => {
    expect(restorePoint("2026-10-31T08:15:00Z")).toBe("2026-10-31T08:15:00.000Z")
    expect(restorePoint(" 2026-10-31T09:15+01:00 ")).toBe("2026-10-31T08:15:00.000Z")
    expect(restorePoint("2026-10-31T08:15:00.250Z")).toBe("2026-10-31T08:15:00.250Z")
  })

  it("refuses a time without its zone, a date alone and anything else", () => {
    for (const typed of ["2026-10-31T08:15:00", "2026-10-31", "yesterday", "", "2026-13-31T08:15:00Z"]) expect(restorePoint(typed), typed).toBeNull()
  })
})
