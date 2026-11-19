import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { EXIT } from "@mehen/protocol/api"
import type { WorkloadView } from "@mehen/protocol/workload"
import { DEFAULT_NEXT } from "../errors.ts"
import { MockVault, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"
import { HARNESS_GUIDE_URL, LABEL_NOTE, workloadScopeWords } from "./workload.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>
let device: string

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_HOME: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.overrides.clear()
  device = await vault.enrolSoftware(dir.path)
  vault.seen.length = 0
})
afterEach(async () => dir.remove())

const ID = "wl_build42abc"

function view(extra: Partial<WorkloadView> = {}): WorkloadView {
  return {
    workload: ID,
    device,
    label: "build-42",
    thumbprint: "t".repeat(43),
    scope: { tags: ["ci"], modes: ["relay"] },
    state: "active",
    createdAt: "2026-10-29T12:00:00.000Z",
    expiresAt: "2026-10-29T13:00:00.000Z",
    hardExpiresAt: "2026-11-05T12:00:00.000Z",
    lastSeenAt: null,
    revokedAt: null,
    revokedBy: null,
    ...extra,
  }
}

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

describe("mehen workload ls", () => {
  test("is GET /v1/workloads signed by the device key, and --json prints the vault's list", async () => {
    const list = { workloads: [view(), view({ workload: "wl_review7xyz", label: "review:pr-7", scope: {}, lastSeenAt: "2026-10-29T12:30:00.000Z" })] }
    vault.overrides.set("GET /v1/workloads", () => Response.json(list))
    const result = await runJv(["workload", "ls", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toEqual(list)
    const call = vault.seen.find((s) => s.path === "/v1/workloads")
    expect(call?.method).toBe("GET")
    expect(call?.claims.dev).toBe(device)
    expect(call?.claims.wkl).toBeUndefined()
  })

  test("the human table names each workload, its label as the machine's words, its scope in words, expiry and last seen", async () => {
    vault.overrides.set("GET /v1/workloads", () => Response.json({ workloads: [view(), view({ workload: "wl_review7xyz", label: "review:pr-7", scope: {}, lastSeenAt: "2026-10-29T12:30:00.000Z" })] }))
    const result = await runJv(["workload", "ls"], env)
    expect(result.code).toBe(EXIT.ok)
    const lines = result.stdout.trimEnd().split("\n")
    expect(lines[0]).toMatch(/^WORKLOAD +LABEL +SCOPE +EXPIRES +LAST SEEN$/)
    expect(lines[1]).toMatch(/^wl_build42abc +build-42 +items tagged ci; modes relay +2026-10-29T13:00:00.000Z +never$/)
    expect(lines[2]).toMatch(/^wl_review7xyz +review:pr-7 +everything this machine may use +2026-10-29T13:00:00.000Z +2026-10-29T12:30:00.000Z$/)
    expect(lines.at(-1)).toBe(LABEL_NOTE)
  })

  // A 0.3.18 machine may be given fill (ladder F1): a workload limited to it
  // is listed, never refused as an unknown mode.
  test("a workload whose modes include fill is listed", async () => {
    const list = { workloads: [view({ scope: { modes: ["fill"] } }), view({ workload: "wl_review7xyz", scope: { modes: ["relay", "sign", "mint", "placeholder", "fill", "lease"] } })] }
    vault.overrides.set("GET /v1/workloads", () => Response.json(list))
    const result = await runJv(["workload", "ls", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toEqual(list)
    vault.overrides.set("DELETE /v1/workloads/wl_build42abc", () => Response.json(view({ scope: { modes: ["fill"] }, state: "revoked", revokedAt: "2026-10-29T12:40:00.000Z", revokedBy: "device" })))
    expect((await runJv(["workload", "revoke", ID, "--json"], env)).code).toBe(EXIT.ok)
  })

  test("no live workloads says so", async () => {
    vault.overrides.set("GET /v1/workloads", () => Response.json({ workloads: [] }))
    const result = await runJv(["workload", "ls"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).toBe("No live workloads on this machine.\n")
  })

  test("an answer that is not a workload list is internal, never printed as one", async () => {
    vault.overrides.set("GET /v1/workloads", () => Response.json({ workloads: [{ workload: ID }] }))
    const result = await runJv(["workload", "ls", "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "internal" })
  })
})

describe("mehen workload revoke", () => {
  test("is DELETE /v1/workloads/:id signed by the device key; --json prints the ended workload", async () => {
    const ended = view({ state: "revoked", revokedAt: "2026-10-29T12:40:00.000Z", revokedBy: "device" })
    vault.overrides.set(`DELETE /v1/workloads/${ID}`, () => Response.json(ended))
    const result = await runJv(["workload", "revoke", ID, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(json(result)).toEqual(ended)
    const call = vault.seen.find((s) => s.path === `/v1/workloads/${ID}`)
    expect(call?.method).toBe("DELETE")
    expect(call?.claims.dev).toBe(device)
    expect(call?.claims.wkl).toBeUndefined()
  })

  test("is idempotent: revoking an ended workload again answers how it ended, exit 0", async () => {
    vault.overrides.set(`DELETE /v1/workloads/${ID}`, () => Response.json(view({ state: "revoked", revokedAt: "2026-10-29T12:40:00.000Z", revokedBy: "member" })))
    const first = await runJv(["workload", "revoke", ID], env)
    const second = await runJv(["workload", "revoke", ID], env)
    expect(first.code).toBe(EXIT.ok)
    expect(second.stdout).toBe(first.stdout)
    expect(first.stdout).toBe(`Workload ${ID} (build-42, as this machine named it) is revoked by a person on the machine's page at 2026-10-29T12:40:00.000Z; it can do nothing.\n`)
    vault.overrides.set(`DELETE /v1/workloads/${ID}`, () => Response.json(view({ state: "expired" })))
    expect((await runJv(["workload", "revoke", ID], env)).stdout).toBe(`Workload ${ID} (build-42, as this machine named it) had already expired; it can do nothing.\n`)
  })

  test("says why a workload ended with its machine: the machine revoked, or its owner losing access", async () => {
    for (const [revokedBy, why] of [["device_revoked", "because its machine was revoked"], ["owner_inactive", "because its owner lost access"]] as const) {
      vault.overrides.set(`DELETE /v1/workloads/${ID}`, () => Response.json(view({ state: "revoked", revokedAt: "2026-10-29T12:40:00.000Z", revokedBy })))
      const result = await runJv(["workload", "revoke", ID], env)
      expect(result.code).toBe(EXIT.ok)
      expect(result.stdout).toBe(`Workload ${ID} (build-42, as this machine named it) is revoked ${why} at 2026-10-29T12:40:00.000Z; it can do nothing.\n`)
    }
  })

  test("a vault that answers still active is not reported as revoked", async () => {
    vault.overrides.set(`DELETE /v1/workloads/${ID}`, () => Response.json(view()))
    const result = await runJv(["workload", "revoke", ID, "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toMatchObject({ error: "internal" })
  })

  test("a bad id, a missing id, an extra argument, an unknown action and create are usage errors, before anything is signed", async () => {
    for (const args of [["revoke", "dev_abcdefgh"], ["revoke", "wl_short"], ["revoke"], ["ls", ID], ["rm", ID], ["create"]]) {
      const result = await runJv(["workload", ...args, "--json"], env)
      expect(result.code).toBe(EXIT.usage)
      expect(json(result)).toMatchObject({ error: "usage" })
    }
    expect(vault.seen).toHaveLength(0)
    const create = await runJv(["workload", "create", "--json"], env)
    expect((json(create) as { message: string }).message).toContain("@mehen/client")
    expect((json(create) as { message: string }).message).toContain(HARNESS_GUIDE_URL)
  })

  test("--help says there is no create and points at the harness guide", async () => {
    const help = await runJv(["workload", "--help"], env)
    expect(help.code).toBe(EXIT.ok)
    expect(help.stdout).toStartWith("usage: mehen workload ls | revoke <wl_id>\n")
    expect(help.stdout).toContain("mehen does not create workloads")
    expect(help.stdout).toContain(HARNESS_GUIDE_URL)
  })
})

describe("the workload refusals", () => {
  test("workload_required: exit 5 (refused) with its next step, as JSON and for a person", async () => {
    vault.overrides.set("GET /v1/items", () => vaultError("workload_required", "This machine acts only through workloads."))
    const result = await runJv(["ls", "--json"], env)
    expect(result.code).toBe(EXIT.refused)
    expect(json(result)).toMatchObject({ error: "workload_required", message: "This machine acts only through workloads.", next: DEFAULT_NEXT.workload_required })
    const human = await runJv(["ls"], env)
    expect(human.code).toBe(EXIT.refused)
    expect(human.stderr).toContain(`next: ${DEFAULT_NEXT.workload_required.say}`)
  })

  test("workload_ended: exit 6 (identity) with its next step, as JSON and for a person", async () => {
    vault.overrides.set("GET /v1/workloads", () => vaultError("workload_ended", "This workload has ended. Create a new one from its device."))
    const result = await runJv(["workload", "ls", "--json"], env)
    expect(result.code).toBe(EXIT.identity)
    expect(json(result)).toMatchObject({ error: "workload_ended", next: DEFAULT_NEXT.workload_ended })
    const human = await runJv(["workload", "ls"], env)
    expect(human.code).toBe(EXIT.identity)
    expect(human.stderr).toContain(`next: ${DEFAULT_NEXT.workload_ended.say}`)
  })
})

describe("workloadScopeWords", () => {
  test("names each narrowing, and the machine's whole scope when there is none", () => {
    expect(workloadScopeWords({})).toBe("everything this machine may use")
    expect(workloadScopeWords({ items: ["github-work"], tags: ["ci"], projects: ["prj_a"], modes: ["relay", "placeholder"] })).toBe("only github-work; items tagged ci; projects prj_a; modes relay, placeholder")
  })
})
