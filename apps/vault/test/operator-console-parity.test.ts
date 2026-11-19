// The operator script (scripts/platform.ts) and the web console run the
// same plans, so each action leaves the same D1 state, actor aside: one
// platform changed by each, side by side, compared after every step.

import { expect, it } from "vitest"
import type { OperatorCommand } from "@mehen/protocol"
import { type PlatformIo, parsePlatformArgs, runPlatform } from "../scripts/platform.ts"
import { maintainPlatforms } from "../src/platform/sweeps.ts"
import { answer, consoleFixture } from "./console-support.ts"
import { addSubject, newPlatformKey } from "./platform-fixtures.ts"

type Fixture = Awaited<ReturnType<typeof consoleFixture>>

function scriptIo(f: Fixture, slug: string, files: Record<string, string>): PlatformIo {
  return {
    async query<T>(_target: unknown, sql: string) {
      return (await f.env.DB.prepare(sql).all<T>()).results
    },
    async batch(_target, statements) {
      return (await f.env.DB.batch(statements.map((statement) => f.env.DB.prepare(statement)))).map((result) => result.results)
    },
    bookmark: async () => "fixture-bookmark",
    ask: async () => slug,
    async readFile(path) {
      const file = files[path]
      if (file === undefined) throw new Error("no such file")
      return file
    },
    print: () => {},
    now: () => Date.now(),
  }
}

// Everything a change leaves in D1 about one platform, with ids, actors and
// times taken out or made relative.
async function state(f: Fixture, slug: string): Promise<unknown> {
  const platform = await f.env.DB.prepare("SELECT id,name,status,status_reason,limits,defaults,defaults_rev,status_at,retire_after,removing_at,removed_at,removed_slug FROM platforms WHERE slug=? OR removed_slug=?").bind(slug, slug).first<Record<string, unknown> & { id: string; status_at: number; retire_after: number | null; removing_at: number | null; removed_at: number | null }>()
  if (!platform) return null
  const keys = (await f.env.DB.prepare("SELECT created_at,expires_at,revoked_at FROM platform_keys WHERE platform=? ORDER BY created_at,rowid").bind(platform.id).all<{ created_at: number; expires_at: number | null; revoked_at: number | null }>()).results
  const newest = Math.max(...keys.map((k) => k.created_at))
  return {
    platform: { name: platform.name, status: platform.status, reason: platform.status_reason, limits: platform.limits, defaults: platform.defaults, revision: platform.defaults_rev, retiresAfterStatus: platform.retire_after === null ? null : platform.retire_after - platform.status_at, removing: platform.removing_at !== null, removed: platform.removed_at !== null, removedSlug: platform.removed_slug === null ? null : platform.removed_slug === slug },
    keys: keys.map((k) => ({ revoked: k.revoked_at !== null, expiresAfterNewest: k.expires_at === null ? null : Math.round((k.expires_at - newest) / 60_000) })),
    subjects: (await f.env.DB.prepare("SELECT status,subject IS NULL AS purged FROM managed_workspaces WHERE platform=? ORDER BY status,subject").bind(platform.id).all()).results,
    admins: (await f.env.DB.prepare("SELECT account,removed_at IS NULL AS live FROM platform_admins WHERE platform=? ORDER BY added_at,rowid").bind(platform.id).all()).results,
    events: (await f.env.DB.prepare("SELECT action,detail FROM platform_events WHERE platform=? ORDER BY at,rowid").bind(platform.id).all<{ action: string; detail: string }>()).results.map((e) => ({ action: e.action, detail: Object.keys(JSON.parse(e.detail)).sort() })),
  }
}

it("the script and the web console reach the same D1 state for each action", async () => {
  const f = await consoleFixture()
  await f.grantOperator("acc_owner")
  const alex = await f.person("acc_owner")
  const keys = { script: [await newPlatformKey(), await newPlatformKey()], web: [await newPlatformKey(), await newPlatformKey()] }
  const files = { "first.json": JSON.stringify(keys.script[0]!.jwk), "second.json": JSON.stringify(keys.script[1]!.jwk), "register-limits.json": JSON.stringify({ subjects: 5 }), "limits.json": JSON.stringify({ callsPerMinute: 100 }) }
  const firstKey = async (slug: string) => (await f.env.DB.prepare("SELECT k.id FROM platform_keys k JOIN platforms p ON p.id=k.platform WHERE p.slug=? ORDER BY k.created_at,k.rowid LIMIT 1").bind(slug).first<{ id: string }>())!.id
  async function both(argv: (slug: string) => Promise<string[]>, command: (slug: string) => Promise<OperatorCommand>): Promise<void> {
    const viaScript = await argv("by-script")
    expect(await runPlatform(parsePlatformArgs(["--local", viaScript[0]!, "by-script", ...viaScript.slice(1), "--actor", "operator:alex"]), scriptIo(f, "by-script", files)), viaScript[0]).toBe(0)
    const viaWeb = await command("by-web")
    const stepUp = await f.operatorProof(alex, "by-web", viaWeb)
    await answer(await f.request(viaWeb.command === "register" ? "/api/operator/platforms" : "/api/operator/platforms/by-web", alex, { command: viaWeb, stepUp }), viaWeb.command === "register" ? 201 : 200)
    expect(await state(f, "by-web"), viaWeb.command).toEqual(await state(f, "by-script"))
  }
  await both(async () => ["register", "--name", "Same", "--key", "first.json", "--limits", "register-limits.json"], async (slug) => ({ command: "register", slug, name: "Same", key: keys.web[0]!.jwk, limits: { subjects: 5 }, confirm: slug }))
  await both(async () => ["limits", "--limits", "limits.json"], async () => ({ command: "limits", limits: { callsPerMinute: 100 } }))
  await both(async () => ["suspend", "--reason", "Odd traffic"], async (slug) => ({ command: "suspend", reason: "Odd traffic", confirm: slug }))
  await both(async () => ["resume"], async () => ({ command: "resume" }))
  await both(async () => ["rotate-key", "--key", "second.json", "--overlap-hours", "2"], async (slug) => ({ command: "rotate-key", key: keys.web[1]!.jwk, overlapHours: 2, confirm: slug }))
  await both(async (slug) => ["revoke-key", await firstKey(slug)], async (slug) => ({ command: "revoke-key", key: await firstKey(slug), confirm: slug }))
  await both(async () => ["add-admin", "acc_admin"], async () => ({ command: "add-admin", account: "acc_admin" }))
  await both(async () => ["remove-admin", "acc_admin"], async () => ({ command: "remove-admin", account: "acc_admin" }))
  await both(async () => ["add-admin", "acc_kim"], async () => ({ command: "add-admin", account: "acc_kim" }))
  for (const slug of ["by-script", "by-web"]) {
    const { id } = (await f.env.DB.prepare("SELECT id FROM platforms WHERE slug=?").bind(slug).first<{ id: string }>())!
    await addSubject(f.env, id, "subject-one")
    await addSubject(f.env, id, "subject-two")
  }
  await both(async () => ["delete-subjects", "--reason", "Platform asked"], async (slug) => ({ command: "delete-subjects", reason: "Platform asked", confirm: slug }))
  for (const slug of ["by-script", "by-web"]) {
    const { id } = (await f.env.DB.prepare("SELECT id FROM platforms WHERE slug=?").bind(slug).first<{ id: string }>())!
    await addSubject(f.env, id, "subject-three")
  }
  await both(async () => ["retire", "--after-days", "7"], async (slug) => ({ command: "retire", afterDays: 7, confirm: slug }))
  await both(async () => ["remove", "--reason", "Set up again"], async (slug) => ({ command: "remove", reason: "Set up again", confirm: slug }))
  await maintainPlatforms(f.env, Date.now())
  await maintainPlatforms(f.env, Date.now())
  const removed = await state(f, "by-script")
  expect(removed).toMatchObject({ platform: { status: "retired", removed: true, removedSlug: true }, admins: [{ account: "acc_admin", live: 0 }, { account: "acc_kim", live: 0 }] })
  expect(await state(f, "by-web")).toEqual(removed)
})
