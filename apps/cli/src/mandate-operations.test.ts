import { expect, test } from "bun:test"
import type { Config } from "./config.ts"
import { type MandateSession, cappedText, parseMandateSchedule, parseSince, readMandateStatus, scheduleText } from "./mandate-operations.ts"
import { mandateView } from "./testing/mandate-fixtures.ts"
import { type VaultApi, type VaultRequestOptions, VaultNetworkError } from "./vault-api.ts"

const HELP = "mehen mandate --help"

test("a schedule reads as the protocol's windows and prints back the way it was written", () => {
  for (const [text, windows] of [
    ["Europe/Paris mon-fri 08:00-19:00", [{ days: [1, 2, 3, 4, 5], from: "08:00", to: "19:00" }]],
    ["UTC daily 22:00-06:00", [{ days: [0, 1, 2, 3, 4, 5, 6], from: "22:00", to: "06:00" }]],
    ["America/New_York mon,wed-fri 09:00-17:00; sat,sun 10:00-12:00", [{ days: [1, 3, 4, 5], from: "09:00", to: "17:00" }, { days: [0, 6], from: "10:00", to: "12:00" }]],
  ] as const) {
    const schedule = parseMandateSchedule(text, "--schedule", HELP)
    expect(schedule.windows).toEqual(windows as unknown as typeof schedule.windows)
    expect(scheduleText(schedule)).toBe(text)
  }
  expect(scheduleText(parseMandateSchedule("UTC MON,tue,wed 08:00-09:00", "--schedule", HELP))).toBe("UTC mon-wed 08:00-09:00")
})

test("refusal/a schedule without a time zone, with a backward day range, a bad hour or too many windows is a usage error", () => {
  for (const text of ["", "mon-fri 08:00-19:00", "Europe/Paris", "Europe/Paris mon-fri", "Europe/Paris fri-mon 08:00-19:00", "Europe/Paris mon-fri 8:00-19:00", "Europe/Paris mon-fri 08:00-08:00", "Europe/Paris weekdays 08:00-19:00", "Europe/Paris mon-fri 08:00-19:00;", `UTC ${Array(8).fill("mon 08:00-09:00").join("; ")}`]) {
    expect(() => parseMandateSchedule(text, "--schedule", HELP), text).toThrow()
  }
})

test("a cap said in words carries its number when the mandate was read, and the classes in the usual order", () => {
  expect(cappedText(["delete", "send"], { read: 5000, change: 0, send: 50, delete: 20 })).toBe("This machine's mandate has used today's 50 sends and 20 deletes.")
  expect(cappedText(["change"], null)).toBe("This machine's mandate has used today's changes.")
})

test("--since takes a time with its offset or a span back from now", () => {
  const now = Date.parse("2026-11-08T12:00:00Z")
  expect(parseSince("1h", "--since", HELP, now)).toBe(Date.parse("2026-11-08T11:00:00Z"))
  expect(parseSince("7d", "--since", HELP, now)).toBe(Date.parse("2026-11-01T12:00:00Z"))
  expect(parseSince("2026-11-08T09:00:00+01:00", "--since", HELP, now)).toBe(Date.parse("2026-11-08T08:00:00Z"))
  for (const text of ["0h", "1w", "yesterday", "2026-11-08"]) expect(() => parseSince(text, "--since", HELP, now), text).toThrow()
})

const statusSession = (answer: (options?: VaultRequestOptions) => Promise<unknown>): MandateSession => ({
  vaultUrl: "https://vault.example",
  config: { workspaceSlug: "mock-space" } as Config,
  api: { request: (_method: string, _path: string, _body?: unknown, options?: VaultRequestOptions) => answer(options) } as VaultApi,
})

test("the status read gives up after 2 seconds or on a network error, and status says nothing about mandates", async () => {
  expect(await readMandateStatus(statusSession(async () => ({ mandates: [mandateView()], proposals: [] })))).toMatchObject({ mandate: { id: "mdt_live" }, mandateProposals: 0 })
  expect(await readMandateStatus(statusSession(async () => { throw new VaultNetworkError("Could not reach the vault.") }))).toBeNull()
  const started = Date.now()
  const slow = statusSession((options) => new Promise((_resolve, reject) => {
    if (!options?.signal) return
    options.signal.addEventListener("abort", () => reject(options.signal?.reason))
  }))
  expect(await readMandateStatus(slow)).toBeNull()
  expect(Date.now() - started).toBeGreaterThanOrEqual(1900)
  expect(Date.now() - started).toBeLessThan(4000)
})
