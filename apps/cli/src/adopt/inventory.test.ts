import { afterEach, describe, expect, it, spyOn } from "bun:test"
import { ADOPTION_LEFT_OUT, type AdoptionStatus } from "@mehen/protocol/adopt"
import { AdoptOutput, printInventory } from "../commands/adopt.ts"
import { type AdoptInventory, batchRows } from "./inventory.ts"
import { OutputGuard, WITHHELD } from "./output-guard.ts"

const status = (over: Partial<AdoptionStatus>): AdoptionStatus => ({ adoption: "adp_test01", status: "approved", expiresAt: "2026-11-05T10:00:00.000Z", machines: [], ...over })

describe("batchRows", () => {
  it("names each row this machine sent by its outcome, a row unticked at review or one an approved batch did not decide as left out", () => {
    const approved = status({ created: [{ ref: "a001", slug: "openai-api-2" }], mapped: [{ ref: "a002", slug: "openai-api" }], replaced: [{ ref: "a003", slug: "stripe-api" }], refused: [{ ref: "a005", reason: "name not available" }, { ref: "a006", reason: ADOPTION_LEFT_OUT }] })
    expect(batchRows(approved, ["a001", "a002", "a003", "a004", "a005", "a006"])).toEqual([
      { ref: "a001", outcome: "created", slug: "openai-api-2", reason: null },
      { ref: "a002", outcome: "mapped", slug: "openai-api", reason: null },
      { ref: "a003", outcome: "replaced", slug: "stripe-api", reason: null },
      { ref: "a004", outcome: "left-out", slug: null, reason: null },
      { ref: "a005", outcome: "refused", slug: null, reason: "name not available" },
      { ref: "a006", outcome: "left-out", slug: null, reason: null },
    ])
  })

  it("lists another machine's rows of the batch nowhere once this machine's are known", () => {
    expect(batchRows(status({ created: [{ ref: "a7kq001", slug: "openai" }, { ref: "a001", slug: "stripe" }] }), ["a001"])).toEqual([{ ref: "a001", outcome: "created", slug: "stripe", reason: null }])
  })

  it("an open batch's rows wait, a cancelled or expired batch has none, and a batch recorded without refs lists only what its status names", () => {
    expect(batchRows(status({ status: "open", refused: [{ ref: "a002", reason: "too big" }] }), ["a001", "a002"])).toEqual([
      { ref: "a001", outcome: "waiting", slug: null, reason: null },
      { ref: "a002", outcome: "refused", slug: null, reason: "too big" },
    ])
    expect(batchRows(status({ status: "expired" }), ["a001"])).toEqual([])
    expect(batchRows(status({ status: "cancelled" }), ["a001"])).toEqual([])
    expect(batchRows(status({ created: [{ ref: "a001", slug: "openai" }] }), null)).toEqual([{ ref: "a001", outcome: "created", slug: "openai", reason: null }])
  })
})

describe("printInventory", () => {
  const writes: string[] = []
  afterEach(() => {
    writes.length = 0
  })
  const inventory: AdoptInventory = {
    plan: "/Users/sam/.config/mehen/adopt/office/plan.json",
    workspace: "acme",
    machine: "office",
    items: [{ ref: "a001", slug: "openai-api", kind: "api-key", home: "project", project: "api", include: true, exists: false, stale: false, storeOnly: false, sources: [{ path: "/Users/sam/code/api/.env", variable: "OPENAI_API_KEY", pointer: null, mtime: "2026-11-01T09:00:00.000Z", stale: [] }], uses: [{ project: "api", env: "dev", variable: "OPENAI_API_KEY" }] }],
    batches: [
      { adoption: "adp_test01", status: "approved", expiresAt: "2026-11-05T10:00:00.000Z", url: "https://vault.test/w/acme/b/adp_test01", rows: [{ ref: "a001", outcome: "refused", slug: null, reason: "SENTINEL-guarded-0123456789" }] },
      { adoption: "adp_test02", status: null, expiresAt: null, url: null, rows: [] },
    ],
    url: "https://vault.test/w/acme/adopt",
  }

  it("prints the plan's rows, each batch's outcomes and the inventory page link", () => {
    const write = spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => writes.push(String(chunk)) > 0)
    try {
      printInventory({ ...inventory, batches: [{ ...inventory.batches[0]!, rows: [{ ref: "a001", outcome: "mapped", slug: "openai", reason: null }] }, inventory.batches[1]!] }, new AdoptOutput(new OutputGuard(), false))
    } finally {
      write.mockRestore()
    }
    expect(writes.join("")).toBe(
      [
        "/Users/sam/.config/mehen/adopt/office/plan.json: 1 item (1 included) for workspace acme on office",
        "a001 openai-api (api-key, project:api): included",
        "  from /Users/sam/code/api/.env OPENAI_API_KEY, changed 2026-11-01T09:00:00.000Z",
        "  used by api dev: OPENAI_API_KEY",
        "batch adp_test01: approved, expires 2026-11-05T10:00:00.000Z; https://vault.test/w/acme/b/adp_test01",
        "  a001: mapped to openai",
        "batch adp_test02: the vault no longer answers for it; outcomes unknown",
        "inventory page: https://vault.test/w/acme/adopt",
        "",
      ].join("\n"),
    )
  })

  it("goes through the output guard, as text and as JSON: a line holding a value read is never written", () => {
    for (const json of [false, true]) {
      const guard = new OutputGuard()
      guard.add("SENTINEL-guarded-0123456789", "secret")
      const write = spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => writes.push(String(chunk)) > 0)
      try {
        expect(() => printInventory(inventory, new AdoptOutput(guard, json))).toThrow(WITHHELD)
      } finally {
        write.mockRestore()
      }
      expect(writes.join("")).not.toContain("SENTINEL")
    }
  })
})
