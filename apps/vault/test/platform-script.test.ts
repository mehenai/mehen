// The operator's platform commands (scripts/platform.ts), run against a
// fresh D1 with the wrangler calls replaced.

import { describe, expect, it } from "vitest"
import { DEFAULT_PLATFORM_LIMITS, canonicalJson } from "@mehen/protocol"
import type { Env } from "../src/env.ts"
import { type PlatformArgs, type PlatformIo, parsePlatformArgs, runPlatform, sqlText } from "../scripts/platform.ts"
import { activityEventId } from "../src/platform/sweeps.ts"
import { addSubject, newPlatformKey, platformEnv } from "./platform-fixtures.ts"

const NOW = Date.UTC(2026, 9, 29, 12)
const IDS = { event: "pev_test", platform: "plt_testplatform", key: "pky_testkey" }

type TestIo = PlatformIo & { output: string[]; batches: string[][] }

function io(env: Env, options: { typed?: string | null; files?: Record<string, string> } = {}): TestIo {
  const output: string[] = []
  const batches: string[][] = []
  return {
    output,
    batches,
    async query<T>(_target: unknown, sql: string) {
      return (await env.DB.prepare(sql).all<T>()).results
    },
    async batch(_target, statements) {
      batches.push(statements)
      const results = await env.DB.batch(statements.map((statement) => env.DB.prepare(statement)))
      return results.map((result) => result.results)
    },
    async bookmark() {
      output.push("bookmark")
      return "fixture-bookmark"
    },
    async ask() {
      return options.typed === undefined ? "globex" : options.typed
    },
    async readFile(path) {
      const file = options.files?.[path]
      if (file === undefined) throw new Error("no such file")
      return file
    },
    print(line) {
      output.push(line)
    },
    now: () => NOW,
  }
}

async function keyFile(): Promise<string> {
  return JSON.stringify((await newPlatformKey()).jwk)
}

function args(argv: string[]): PlatformArgs {
  return parsePlatformArgs(["--local", ...argv])
}

async function registered(env: Env): Promise<void> {
  const file = await keyFile()
  expect(await runPlatform(args(["register", "globex", "--name", "Globex", "--key", "key.json", "--actor", "operator:alex"]), io(env, { files: { "key.json": file } }), IDS)).toBe(0)
}

async function platformRow(env: Env): Promise<Record<string, unknown> | null> {
  return env.DB.prepare("SELECT status,status_by,status_reason,retire_after,limits FROM platforms WHERE slug='globex'").first()
}

async function events(env: Env): Promise<string[]> {
  return (await env.DB.prepare("SELECT action FROM platform_events ORDER BY rowid").all<{ action: string }>()).results.map((r) => r.action)
}

describe("parsing", () => {
  it("needs the database, a known command, a valid slug and an operator actor, and refuses anything else", () => {
    for (const argv of [
      [],
      ["--local"],
      ["--local", "register", "globex"],
      ["--local", "register", "Globex!", "--name", "Globex", "--key", "k", "--actor", "operator:alex"],
      ["--local", "register", "globex", "--name", "Globex", "--key", "k", "--actor", "alex"],
      ["--local", "suspend", "globex", "--actor", "operator:alex"],
      ["--local", "revoke-key", "globex", "dev_x", "--actor", "operator:alex"],
      ["--local", "retire", "globex", "--after-days", "-1", "--actor", "operator:alex"],
      ["--local", "show", "globex", "--actor", "operator:alex"],
      ["--local", "subjects", "globex", "--status", "gone"],
      ["--local", "explode", "globex"],
      ["--local", "remove", "globex", "--actor", "operator:alex"],
      ["--local", "add-admin", "globex", "alex", "--actor", "operator:alex"],
      ["--local", "remove-admin", "globex", "--actor", "operator:alex"],
    ]) expect(() => parsePlatformArgs(argv), argv.join(" ")).toThrow("Usage:")
    expect(parsePlatformArgs(["--remote", "show", "globex"]).target).toEqual({ kind: "remote", database: "mehen", flags: ["--remote", "--env", ""] })
    expect(args(["rotate-key", "globex", "--key", "k.json", "--actor", "operator:alex"])).toMatchObject({ command: "rotate-key", overlapHours: 24 })
    expect(args(["remove", "globex", "--reason", "Set up again", "--actor", "operator:alex"])).toMatchObject({ command: "remove", reason: "Set up again" })
    expect(args(["add-admin", "globex", "acc_someone", "--actor", "operator:alex"])).toMatchObject({ command: "add-admin", account: "acc_someone" })
  })

  it("quotes every text value as a SQL literal", () => {
    expect(sqlText("it's")).toBe("'it''s'")
  })
})

describe("register", () => {
  it("prints the bookmark and plan, asks for the slug, then writes the platform, its key and one event", async () => {
    const { env } = await platformEnv()
    const file = await keyFile()
    const transport = io(env, { files: { "key.json": file, "limits.json": JSON.stringify({ subjects: 5 }) } })
    expect(await runPlatform(args(["register", "globex", "--name", "Globex", "--key", "key.json", "--limits", "limits.json", "--actor", "operator:alex"]), transport, IDS)).toBe(0)
    expect(transport.output[0]).toBe("bookmark")
    expect(transport.output[1]).toBe("D1 bookmark before change: fixture-bookmark")
    expect(transport.output.at(-1)).toBe("Registered globex. Platform id plt_testplatform, key id pky_testkey: give both to the platform for its configuration.")
    expect(transport.batches).toHaveLength(1)
    expect(await env.DB.prepare("SELECT id,slug,name,status,limits,created_by FROM platforms").first()).toEqual({ id: IDS.platform, slug: "globex", name: "Globex", status: "active", limits: canonicalJson({ ...DEFAULT_PLATFORM_LIMITS, subjects: 5 }), created_by: "operator:alex" })
    expect(await env.DB.prepare("SELECT id,platform,revoked_at,expires_at FROM platform_keys").first()).toEqual({ id: IDS.key, platform: IDS.platform, revoked_at: null, expires_at: null })
    expect(await events(env)).toEqual(["operator.register"])
  })

  it("refuses a private key, a bad limit, a wrong confirmation and a slug that exists, writing nothing", async () => {
    const { env } = await platformEnv()
    const { privateKey } = await newPlatformKey()
    const privateJwk = JSON.stringify(await crypto.subtle.exportKey("jwk", privateKey))
    const register = args(["register", "globex", "--name", "Globex", "--key", "key.json", "--actor", "operator:alex"])
    await expect(runPlatform(register, io(env, { files: { "key.json": privateJwk } }), IDS)).rejects.toThrow("The key holds a private part; send only the public half.")
    await expect(runPlatform({ ...register, command: "register", limitsFile: "limits.json" } as PlatformArgs, io(env, { files: { "key.json": await keyFile(), "limits.json": JSON.stringify({ decisionTtlSeconds: 3600 }) } }), IDS)).rejects.toThrow("The limits are refused")
    for (const typed of [null, "other"]) expect(await runPlatform(register, io(env, { typed, files: { "key.json": await keyFile() } }), IDS)).toBe(1)
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM platforms").first()).toEqual({ n: 0 })
    await registered(env)
    const again = io(env, { files: { "key.json": await keyFile() } })
    expect(await runPlatform(register, again, { ...IDS, platform: "plt_another1", key: "pky_another1" })).toBe(1)
    expect(again.output).toEqual(["Nothing changed: a platform with that slug exists."])
  })
})

describe("the platform's status", () => {
  it("suspends, resumes, retires and resumes a retirement before its date, each recorded once", async () => {
    const { env } = await platformEnv()
    await registered(env)
    expect(await runPlatform(args(["suspend", "globex", "--reason", "Odd traffic", "--actor", "operator:alex"]), io(env), { ...IDS, event: "pev_1" })).toBe(0)
    expect(await platformRow(env)).toMatchObject({ status: "suspended", status_by: "operator:alex", status_reason: "Odd traffic" })
    const twice = io(env)
    expect(await runPlatform(args(["suspend", "globex", "--reason", "Again", "--actor", "operator:alex"]), twice, { ...IDS, event: "pev_2" })).toBe(1)
    expect(twice.output).toEqual(["Nothing changed: the platform is suspended."])
    expect(await runPlatform(args(["resume", "globex", "--actor", "operator:alex"]), io(env), { ...IDS, event: "pev_3" })).toBe(0)
    expect(await platformRow(env)).toMatchObject({ status: "active", status_reason: null })
    expect(await runPlatform(args(["retire", "globex", "--after-days", "7", "--actor", "operator:alex"]), io(env), { ...IDS, event: "pev_4" })).toBe(0)
    expect(await platformRow(env)).toMatchObject({ status: "retiring", retire_after: NOW + 7 * 86_400_000 })
    expect(await runPlatform(args(["resume", "globex", "--actor", "operator:alex"]), io(env), { ...IDS, event: "pev_5" })).toBe(0)
    expect(await platformRow(env)).toMatchObject({ status: "active", retire_after: null })
    expect(await events(env)).toEqual(["operator.register", "operator.suspend", "operator.resume", "operator.retire", "operator.resume"])
  })

  it("refuses to retire a suspended platform later, which would lift its suspension, and retires it with --after-days 0", async () => {
    const { env } = await platformEnv()
    await registered(env)
    expect(await runPlatform(args(["suspend", "globex", "--reason", "Odd traffic", "--actor", "operator:alex"]), io(env), { ...IDS, event: "pev_1" })).toBe(0)
    const later = io(env)
    expect(await runPlatform(args(["retire", "globex", "--after-days", "7", "--actor", "operator:alex"]), later, { ...IDS, event: "pev_2" })).toBe(1)
    expect(later.output).toEqual(["Nothing changed: the platform is suspended; retire it after 0 days, or resume it first."])
    expect(await platformRow(env)).toMatchObject({ status: "suspended", retire_after: null })
    expect(await runPlatform(args(["retire", "globex", "--after-days", "0", "--actor", "operator:alex"]), io(env), { ...IDS, event: "pev_3" })).toBe(0)
    expect(await platformRow(env)).toMatchObject({ status: "retiring", retire_after: NOW })
    expect(await events(env)).toEqual(["operator.register", "operator.suspend", "operator.retire"])
  })

  it("the retire guard refuses a platform suspended after the plan was made with a later date", async () => {
    const { env } = await platformEnv()
    await registered(env)
    const racing = io(env)
    racing.ask = async () => {
      await env.DB.prepare("UPDATE platforms SET status='suspended',status_reason='raced' WHERE slug='globex'").run()
      return "globex"
    }
    expect(await runPlatform(args(["retire", "globex", "--after-days", "7", "--actor", "operator:alex"]), racing, { ...IDS, event: "pev_1" })).toBe(1)
    expect(racing.output.at(-1)).toBe("Nothing changed: the platform no longer matched.")
    expect(await platformRow(env)).toMatchObject({ status: "suspended", retire_after: null })
    expect(await events(env)).toEqual(["operator.register"])
  })

  it("records nothing when the guard no longer matches at the moment of the batch", async () => {
    const { env } = await platformEnv()
    await registered(env)
    const racing = io(env)
    racing.ask = async () => {
      await env.DB.prepare("UPDATE platforms SET status='suspended',status_reason='raced' WHERE slug='globex'").run()
      return "globex"
    }
    expect(await runPlatform(args(["suspend", "globex", "--reason", "Odd traffic", "--actor", "operator:alex"]), racing, { ...IDS, event: "pev_1" })).toBe(1)
    expect(racing.output.at(-1)).toBe("Nothing changed: the platform no longer matched.")
    expect(await events(env)).toEqual(["operator.register"])
  })
})

describe("keys and limits", () => {
  it("rotates a key with an overlap, revokes one at once, and lays a partial limits file over the current limits", async () => {
    const { env } = await platformEnv()
    await registered(env)
    expect(await runPlatform(args(["rotate-key", "globex", "--key", "new.json", "--overlap-hours", "2", "--actor", "operator:alex"]), io(env, { files: { "new.json": await keyFile() } }), { ...IDS, event: "pev_1", key: "pky_newkey" })).toBe(0)
    expect((await env.DB.prepare("SELECT id,expires_at,revoked_at FROM platform_keys ORDER BY id").all()).results).toEqual([
      { id: "pky_newkey", expires_at: null, revoked_at: null },
      { id: IDS.key, expires_at: NOW + 2 * 3_600_000, revoked_at: null },
    ])
    expect(await runPlatform(args(["revoke-key", "globex", IDS.key, "--actor", "operator:alex"]), io(env), { ...IDS, event: "pev_2" })).toBe(0)
    expect(await env.DB.prepare("SELECT revoked_at,revoked_by FROM platform_keys WHERE id=?").bind(IDS.key).first()).toEqual({ revoked_at: NOW, revoked_by: "operator:alex" })
    expect(await runPlatform(args(["revoke-key", "globex", IDS.key, "--actor", "operator:alex"]), io(env), { ...IDS, event: "pev_3" })).toBe(1)
    expect(await runPlatform(args(["limits", "globex", "--limits", "l.json", "--actor", "operator:alex"]), io(env, { files: { "l.json": JSON.stringify({ callsPerMinute: 1200 }) } }), { ...IDS, event: "pev_4" })).toBe(0)
    expect(JSON.parse(String((await platformRow(env))?.limits))).toEqual({ ...DEFAULT_PLATFORM_LIMITS, callsPerMinute: 1200 })
    expect(await events(env)).toEqual(["operator.register", "operator.rotate_key", "operator.revoke_key", "operator.limits"])
  })
})

describe("subjects", () => {
  it("show and subjects give one platform with its N workspaces, and delete-subjects marks every live one deleting", async () => {
    const { env } = await platformEnv()
    await registered(env)
    const other = await env.DB.prepare("INSERT INTO platforms (id,slug,name,status,limits,defaults,created_at,created_by,status_at,status_by) SELECT 'plt_otherplat','other','Other','active',limits,defaults,0,'operator:x',0,'operator:x' FROM platforms WHERE slug='globex'").run()
    expect(other.meta.changes).toBe(1)
    const live = await addSubject(env, IDS.platform, "subject-live")
    await addSubject(env, IDS.platform, "subject-new1", "creating")
    await addSubject(env, IDS.platform, "subject-gone", "deleted")
    await addSubject(env, IDS.platform, "subject-old1", "purged")
    await addSubject(env, "plt_otherplat", "subject-live")
    await env.DB.prepare("INSERT INTO platform_events (id,platform,at,actor,action,detail) VALUES (?,?,?,'system','platform.activity',?)")
      .bind(activityEventId(IDS.platform), IDS.platform, NOW, JSON.stringify({ "devices.create": { ok: 3, quota_exceeded: 1 }, "intakes.submit": { ok: 2 }, "connects.finish": { ok: 1 }, "items.remove": { ok: 1 }, "approvals.decide": { ok: 4, conflict: 2 } }))
      .run()
    const shown = io(env)
    expect(await runPlatform(args(["show", "globex"]), shown)).toBe(0)
    expect(shown.output).toContain("Workspaces: 4 (1 creating, 1 active, 0 deleting, 1 deleted, 1 purged)")
    expect(shown.output).toContain(`Last 24 hours, as of ${new Date(NOW).toISOString()}: 3 devices made, 3 items added, 1 items deleted, 4 decisions, 3 refusals`)
    expect(shown.output).toContain(`  ${IDS.key} added ${new Date(NOW).toISOString()}, live`)
    const listed = io(env)
    expect(await runPlatform(args(["subjects", "globex"]), listed)).toBe(0)
    expect(listed.output[0]).toBe(`globex (${IDS.platform}): 4 workspaces`)
    expect(listed.output.filter((line) => line.includes("subject-live"))).toHaveLength(1)
    expect(listed.output.some((line) => line.includes("(purged) purged"))).toBe(true)
    const deleting = io(env)
    expect(await runPlatform(args(["subjects", "globex", "--status", "active"]), deleting)).toBe(0)
    expect(deleting.output).toEqual([`globex (${IDS.platform}): 1 workspaces active`, expect.stringContaining(`${live} subject-live active`)])
    expect(await runPlatform(args(["delete-subjects", "globex", "--reason", "Platform asked", "--actor", "operator:alex"]), io(env), { ...IDS, event: "pev_1" })).toBe(0)
    expect((await env.DB.prepare("SELECT status FROM managed_workspaces WHERE platform=? ORDER BY status").bind(IDS.platform).all()).results).toEqual([{ status: "deleted" }, { status: "deleting" }, { status: "deleting" }, { status: "purged" }])
    expect(await env.DB.prepare("SELECT status FROM managed_workspaces WHERE platform='plt_otherplat'").first()).toEqual({ status: "active" })
    const nothing = io(env)
    expect(await runPlatform(args(["delete-subjects", "globex", "--reason", "Again", "--actor", "operator:alex"]), nothing, { ...IDS, event: "pev_2" })).toBe(1)
    expect(nothing.output).toEqual(["Nothing changed: the platform has no live subjects."])
    expect((await events(env)).filter((e) => e === "operator.delete_subjects")).toHaveLength(1)
  })
})

describe("an admin's name on the operator's terminal", () => {
  it("add-admin's plan and result and show spell its control characters, so no ESC or BEL from it reaches the terminal", async () => {
    const { env } = await platformEnv()
    await registered(env)
    await env.DB.prepare("UPDATE accounts SET name=? WHERE id='acc_owner'").bind("Mallory\u001b[31m red\u001b[0m\u0007\u009b2J").run()
    const spelled = "Mallory\\u001B[31m red\\u001B[0m\\u0007\\u009B2J"
    const added = io(env)
    expect(await runPlatform(args(["add-admin", "globex", "acc_owner", "--actor", "operator:alex"]), added, { ...IDS, event: "pev_admin" })).toBe(0)
    const shown = io(env)
    expect(await runPlatform(args(["show", "globex"]), shown)).toBe(0)
    for (const output of [added.output, shown.output]) expect(output.filter((line) => /[\u0000-\u001f\u007f-\u009f]/.test(line))).toEqual([])
    expect(added.output.find((line) => line.startsWith("On local database"))).toContain(`make ${spelled} (acc_owner) an admin of globex`)
    expect(added.output.at(-1)).toBe(`${spelled} is now an admin of globex.`)
    expect(shown.output.find((line) => line.startsWith(`  ${spelled} (acc_owner) added `))).toBeDefined()
  })
})

describe("every change", () => {
  it("prints the bookmark and every statement before asking, and writes nothing without the slug typed back", async () => {
    const { env } = await platformEnv()
    await registered(env)
    await addSubject(env, IDS.platform, "subject-live")
    const files = { "new.json": await keyFile(), "l.json": JSON.stringify({ callsPerMinute: 10 }) }
    const changes = [
      ["suspend", "globex", "--reason", "Odd traffic", "--actor", "operator:alex"],
      ["retire", "globex", "--after-days", "0", "--actor", "operator:alex"],
      ["rotate-key", "globex", "--key", "new.json", "--actor", "operator:alex"],
      ["revoke-key", "globex", IDS.key, "--actor", "operator:alex"],
      ["limits", "globex", "--limits", "l.json", "--actor", "operator:alex"],
      ["delete-subjects", "globex", "--reason", "Platform asked", "--actor", "operator:alex"],
      ["remove", "globex", "--reason", "Set up again", "--actor", "operator:alex"],
      ["add-admin", "globex", "acc_owner", "--actor", "operator:alex"],
    ]
    const before = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM platform_events) AS events, (SELECT group_concat(status) FROM platforms) AS platforms, (SELECT group_concat(status) FROM managed_workspaces) AS subjects, (SELECT COUNT(*) FROM platform_keys WHERE revoked_at IS NULL AND expires_at IS NULL) AS keys").first()
    for (const argv of changes) {
      const transport = io(env, { typed: "not-globex", files })
      expect(await runPlatform(args(argv), transport, { ...IDS, event: "pev_x", key: "pky_rotated" }), argv[0]).toBe(1)
      expect(transport.output[0]).toBe("bookmark")
      expect(transport.output[1]).toBe("D1 bookmark before change: fixture-bookmark")
      expect(transport.output.filter((line) => /^(INSERT|UPDATE) /.test(line)).length, argv[0]).toBeGreaterThan(0)
      expect(transport.output.at(-1)).toBe("Nothing changed: the slug confirmation did not match.")
      expect(transport.batches).toEqual([])
    }
    expect(await env.DB.prepare("SELECT (SELECT COUNT(*) FROM platform_events) AS events, (SELECT group_concat(status) FROM platforms) AS platforms, (SELECT group_concat(status) FROM managed_workspaces) AS subjects, (SELECT COUNT(*) FROM platform_keys WHERE revoked_at IS NULL AND expires_at IS NULL) AS keys").first()).toEqual(before)
  })
})
