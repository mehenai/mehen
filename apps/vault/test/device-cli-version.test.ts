// A machine's CLI version (docs/OPERATIONS.md, Releasing the CLI step 7):
// recorded from its `mehen/<x.y.z>` User-Agent with last_seen_at, a change
// written at once even inside the minute's throttle, anything else leaving
// it as it was; copied to D1's device_cli_versions for the operator's fleet
// view only when it changes, and dropped there when the machine is revoked;
// shown in each machine's view and on the Machines page, marked against the
// vault's minimum and recommended versions; counted across workspaces by
// scripts/fleet-versions.ts.
import { createProof, webCryptoSigner } from "@mehen/protocol"
import { WorkspaceDeviceViewSchema, type WorkspaceDeviceView } from "@mehen/protocol/workspace"
import { env } from "cloudflare:workers"
import { describe, expect, it, vi } from "vitest"
import { FLEET_QUERY, type FleetRow, machinesBelow, parseArgs, runFleetVersions, versionCounts } from "../scripts/fleet-versions.ts"
import { renderDocument } from "../src/ui/layout.ts"
import { machinePage, machinesPage } from "../src/ui/pages/machines.ts"
import { PEOPLE_DEVICE, peopleShell } from "../src/ui/people-gallery.ts"
import { ORIGIN } from "./helpers.ts"
import { body, workJourney } from "./e2e/workspace-journey.ts"
import { registerPlatform } from "./platform-fixtures.ts"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"
import { VaultError } from "../src/http.ts"
import { workspaceApprovalOps } from "../src/vault/areas/approvals-workspace.ts"
import { authoriseWorkspaceRelay } from "../src/vault/areas/relay-workspace.ts"
import { registerWorkspacePendingProvider, workspacePendingOps } from "../src/vault/areas/pending-workspace.ts"
import type { PendingList } from "@mehen/protocol/api"
import { credentialsFixture, deviceInvocation, devicePrincipal, inAccess, seedCredential } from "./credentials-test-support.ts"
import { fixtureSql } from "./fixture-sql.ts"

async function setup() {
  const f = await workJourney()
  const machine = await f.machine(f.alex, f.work)
  async function call(agent: string | null, path = "/v1/me", method = "GET") {
    const proof = await createProof(webCryptoSigner(machine.device, machine.keys.privateKey), { method, url: `${ORIGIN}${path}`, body: method === "GET" ? null : "{}" }, { tenant: machine.workspace.id })
    return f.request(path, undefined, method === "GET" ? undefined : {}, { "Mehen-Proof": proof, ...(agent === null ? {} : { "user-agent": agent }) }, method)
  }
  async function recorded() {
    const [row] = await f.sql<{ last_cli_version: string | null; last_seen_at: number | null }>(f.work, "SELECT last_cli_version,last_seen_at FROM devices WHERE id=?", machine.device)
    return row!
  }
  async function fleet() {
    return (await env.DB.prepare("SELECT version,seen_at FROM device_cli_versions WHERE tenant=? AND device=?").bind(f.work.id, machine.device).all<{ version: string; seen_at: number }>()).results
  }
  return { f, machine, call, recorded, fleet }
}

describe("a machine's CLI version", () => {
  it("is recorded from mehen/x.y.z, a newer one at once inside the throttle window, and never cleared by another User-Agent", async () => {
    const { call, recorded } = await setup()
    expect((await call("mehen/0.3.1 (darwin-arm64; release)")).status).toBe(200)
    const first = await recorded()
    expect(first.last_cli_version).toBe("0.3.1")
    expect(first.last_seen_at).toEqual(expect.any(Number))
    expect((await call("mehen/0.3.2 (darwin-arm64; release)")).status).toBe(200)
    expect((await recorded()).last_cli_version).toBe("0.3.2")
    for (const agent of [null, "Bun/1.4.2", "Mozilla/5.0 (Macintosh) Version/18.0 Safari/605.1", "mehen/0.3"]) {
      expect((await call(agent)).status, String(agent)).toBe(200)
      expect((await recorded()).last_cli_version, String(agent)).toBe("0.3.2")
    }
  })

  it("is copied to D1 only when it changes, and a failed copy never fails the call", async () => {
    const { f, machine, call, recorded, fleet } = await setup()
    await call("mehen/0.3.1 (linux-x64; release)")
    expect(await fleet()).toEqual([{ version: "0.3.1", seen_at: expect.any(Number) }])
    // Removed by hand: the same version again writes nothing.
    await env.DB.prepare("DELETE FROM device_cli_versions WHERE tenant=? AND device=?").bind(f.work.id, machine.device).run()
    await call("mehen/0.3.1 (linux-x64; release)")
    await call("Bun/1.4.2")
    expect(await fleet()).toEqual([])
    await call("mehen/0.3.2 (linux-x64; release)")
    expect(await fleet()).toEqual([{ version: "0.3.2", seen_at: expect.any(Number) }])
    await env.DB.prepare("ALTER TABLE device_cli_versions RENAME TO device_cli_versions_away").run()
    try {
      expect((await call("mehen/0.3.3 (linux-x64; release)")).status).toBe(200)
      expect((await recorded()).last_cli_version).toBe("0.3.3")
    } finally {
      await env.DB.prepare("ALTER TABLE device_cli_versions_away RENAME TO device_cli_versions").run()
    }
    expect(await fleet()).toEqual([{ version: "0.3.2", seen_at: expect.any(Number) }])
  })

  it("is dropped from D1 when the machine is revoked", async () => {
    const { call, fleet } = await setup()
    await call("mehen/0.3.1 (linux-x64; release)")
    expect(await fleet()).toHaveLength(1)
    expect((await call("mehen/0.3.1 (linux-x64; release)", "/v1/devices/self/revoke", "POST")).status).toBe(200)
    await vi.waitFor(async () => expect(await fleet()).toEqual([]))
  })

  it("is in the machine's view for the people who may see it", async () => {
    const { f, machine, call } = await setup()
    const view = async () => WorkspaceDeviceViewSchema.parse(await body(await f.request(`/api/w/${f.work.slug}/devices/${machine.device}`, f.alex)))
    expect((await view()).lastCliVersion).toBeNull()
    await call("mehen/0.3.1 (darwin-arm64; release)")
    expect((await view()).lastCliVersion).toBe("0.3.1")
    const { devices } = await body<{ devices: WorkspaceDeviceView[] }>(await f.request(`/api/w/${f.work.slug}/devices`, f.alex))
    expect(devices.find((d) => d.device === machine.device)?.lastCliVersion).toBe("0.3.1")
  })
})

describe("the Machines page", () => {
  const cli = { minimum: "0.3.0", recommended: "0.3.1" }
  const data = { viewer: { member: "mem_alex01", role: "owner" as const, blocked: false }, projects: null, now: Date.parse(PEOPLE_DEVICE.lastSeenAt!) + 60_000, cli }
  const machine = (lastCliVersion: string | null, revoked = false): WorkspaceDeviceView => ({ ...PEOPLE_DEVICE, device: `dev_${lastCliVersion ?? "none"}${revoked ? "x" : ""}`, lastCliVersion, revoked })
  const region = (markup: string, device: string) => new RegExp(`/devices/${device}"[^]*?<span data-region="cli-version">([^<]*(?:<span class="pill [a-z]+">[^<]*</span>)?)</span>`).exec(markup)?.[1] ?? ""

  it("shows each machine's version beside last seen, marked below the recommended and the minimum version", () => {
    const team: WorkspaceDeviceView = { ...machine("0.3.0"), device: "dev_team", owner: { kind: "team", team: "tm_platform01", name: "Platform" } }
    const markup = renderDocument(machinesPage(peopleShell("owner"), [machine("0.3.1"), machine("0.3.0"), team, machine("0.2.9"), machine(null), machine("0.2.0", true)], data)).value
    expect(region(markup, "dev_0.3.1")).toBe("mehen 0.3.1")
    expect(region(markup, "dev_0.3.0")).toBe('mehen 0.3.0 <span class="pill warn">update available</span>')
    expect(region(markup, "dev_team")).toBe('mehen 0.3.0 <span class="pill warn">update available</span>')
    expect(region(markup, "dev_0.2.9")).toBe('mehen 0.2.9 <span class="pill warn">too old to connect</span>')
    expect(region(markup, "dev_0.2.0x")).toBe("mehen 0.2.0")
    expect(markup).toMatch(/\/devices\/dev_none"><span class="row-title">tom-laptop<\/span><span class="row-sub">Tom Barker · seen 1 min ago<\/span>/)
    // With no advice configured nothing is marked.
    expect(renderDocument(machinesPage(peopleShell("owner"), [machine("0.2.9")], { ...data, cli: { minimum: null, recommended: null } })).value).not.toContain("too old to connect")
  })

  it("shows it on the machine's own page, or that none was reported yet", () => {
    expect(renderDocument(machinePage(peopleShell("owner"), machine("0.3.0"), data)).value).toMatch(/<dt>CLI version<\/dt><dd><span data-region="cli-version">mehen 0.3.0 <span class="pill warn">update available<\/span><\/span><\/dd>/)
    expect(renderDocument(machinePage(peopleShell("owner"), machine(null), data)).value).toMatch(/<dt>CLI version<\/dt><dd><span class="muted">not reported yet<\/span><\/dd>/)
  })
})

describe("the operator's fleet view", () => {
  const row = (workspace: string, device: string, version: string): FleetRow => ({ workspace, device, version, seen_at: Date.UTC(2026, 9, 30) })

  it("counts machines per version, oldest first, and lists those below a version", () => {
    const rows = [row("northwind", "dev_a", "0.3.1"), row("alex", "dev_b", "0.10.0"), row("northwind", "dev_c", "0.3.0"), row("alex", "dev_d", "0.3.1"), row("alex", "dev_e", "0.2.0"), row("alex", "dev_f", "garbage")]
    expect(versionCounts(rows)).toEqual({ counts: [{ version: "0.2.0", machines: 1 }, { version: "0.3.0", machines: 1 }, { version: "0.3.1", machines: 2 }, { version: "0.10.0", machines: 1 }], unreadable: 1 })
    expect(machinesBelow(rows, "0.3.1").map((r) => r.device)).toEqual(["dev_c", "dev_e"])
    expect(machinesBelow(rows, "0.2.0")).toEqual([])
  })

  it("takes an explicit database and only an x.y.z for --below", () => {
    expect(parseArgs(["--remote"])).toEqual({ target: { kind: "remote", database: "mehen", d1: ["--remote", "--env", ""] }, below: null })
    expect(parseArgs(["--local", "--below", "0.3.1"]).below).toBe("0.3.1")
    for (const argv of [[], ["--below", "0.3.1"], ["--local", "--below"], ["--local", "--below", "0.3"], ["--local", "--below", "0.3.1'; DROP TABLE x"], ["--local", "extra"]]) expect(() => parseArgs(argv)).toThrow("Usage:")
  })

  it("reads only active workspaces' machines from D1, by slug, and prints the counts and the list", async () => {
    const f = await createWorkspaceFixture()
    const platform = await registerPlatform(f.env)
    const now = Date.UTC(2026, 9, 30)
    await f.env.DB.batch([
      f.env.DB.prepare("INSERT INTO workspaces(id,slug,name,status,created_by,created_at,delete_after) VALUES ('tn_Gone1234567','gone','Gone','deleting',?,?,?)").bind(f.account, now, now),
      f.env.DB.prepare("INSERT INTO managed_workspaces(tenant,platform,subject,subject_hash,status,created_at) VALUES ('tn_Managed12345',?,'subject-1','hash1','active',?),('tn_Deleted12345',?,'subject-2','hash2','deleted',?)").bind(platform.id, now, platform.id, now),
      f.env.DB.prepare("INSERT INTO device_cli_versions(tenant,device,version,seen_at) VALUES (?,?,?,?),(?,?,?,?),(?,?,?,?),(?,?,?,?),(?,?,?,?),(?,?,?,?)").bind(
        f.workspaces.work, "dev_work1", "0.3.1", now,
        f.workspaces.work, "dev_work2", "0.3.0", now,
        f.workspaces.personal, "dev_home1", "0.3.1", now,
        "tn_Gone1234567", "dev_gone1", "0.2.0", now,
        "tn_Managed12345", "dev_managed1", "0.2.9", now,
        "tn_Deleted12345", "dev_deleted1", "0.1.0", now,
      ),
    ])
    expect((await f.env.DB.prepare(FLEET_QUERY).all<FleetRow>()).results.map((r) => [r.workspace, r.device])).toEqual([["alex", "dev_home1"], [`managed:${platform.slug}/tn_Managed12345`, "dev_managed1"], ["northwind", "dev_work1"], ["northwind", "dev_work2"]])
    const output: string[] = []
    const io = { async query<T>(_target: unknown, sql: string) { return (await f.env.DB.prepare(sql).all<T>()).results }, print: (line: string) => output.push(line) }
    expect(await runFleetVersions(parseArgs(["--local", "--below", "0.3.1"]), io)).toBe(0)
    expect(output).toEqual([
      "Active machines by mehen version on local database mehen-local: 4 in all.",
      "  mehen 0.2.9: 1",
      "  mehen 0.3.0: 1",
      "  mehen 0.3.1: 2",
      "A machine that has not called the vault since versions were recorded is not listed.",
      "Below 0.3.1: 2.",
      `  managed:${platform.slug}/tn_Managed12345 dev_managed1 mehen 0.2.9, since 2026-10-30T00:00:00.000Z`,
      "  northwind dev_work2 mehen 0.3.0, since 2026-10-30T00:00:00.000Z",
    ])
  })
})

// A superseded approval (batch approvals) reads so only to a mehen that
// knows the status, with the newer ask beside it; any other caller reads
// stale, which every mehen since 0.3.0 already stops on.
describe("a superseded approval's status", () => {
  it("reads stale to 0.3.16 and to an unnamed client, and superseded with replacedBy to 0.3.17", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "cli-key")
      fixtureSql(ctx).exec("UPDATE items SET policy=? WHERE slug='cli-key'", JSON.stringify({ default: "approve", rules: [] }))
      const relay = async (body: string, replaces?: string): Promise<string> => {
        try { await authoriseWorkspaceRelay(ctx, devicePrincipal(), { item: "cli-key", method: "POST", url: "https://api.example.com/v1/databases", headers: [], body: Buffer.from(body).toString("base64url"), ...(replaces ? { replaces } : {}) }, await deviceInvocation(ctx)) } catch (error) { if (error instanceof VaultError && error.code === "approval_required") return error.extra.approval as string; throw error }
        throw new Error("Expected approval_required")
      }
      const first = await relay("one"), second = await relay("two", first)
      const read = async (cliVersion: string | null) => {
        const invocation = await deviceInvocation(ctx)
        if (invocation.auth.kind !== "device") throw new Error("Expected a device")
        return workspaceApprovalOps["approvals.status"]!.handler(ctx, devicePrincipal(), { id: first }, { ...invocation, auth: { ...invocation.auth, cliVersion } }) as Promise<Record<string, unknown>>
      }
      for (const version of ["0.3.16", "0.3.0", null]) {
        const old = await read(version)
        expect(old, String(version)).toMatchObject({ approval: first, status: "stale" })
        expect(old, String(version)).not.toHaveProperty("replacedBy")
      }
      for (const version of ["0.3.17", "0.4.0"]) expect(await read(version), version).toMatchObject({ approval: first, status: "superseded", replacedBy: second })
    })
  })
})

// An ask's review group rides on approval_required (batch approvals) only to
// a mehen that reads it, never for a bundled ask; next.url stays the ask's
// own page.
describe("an approval_required answer's review group", () => {
  it("names the group and how many of its asks are open to 0.3.17, and nothing to 0.3.16, an unnamed client or with the switch off", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      await seedCredential(ctx, "cli-key")
      fixtureSql(ctx).exec("UPDATE items SET policy=? WHERE slug='cli-key'", JSON.stringify({ default: "approve", rules: [] }))
      const refusal = async (body: string, cliVersion: string | null | undefined, on: typeof ctx = ctx): Promise<Record<string, unknown>> => {
        const invocation = await deviceInvocation(ctx)
        if (invocation.auth.kind !== "device") throw new Error("Expected a device")
        const auth = cliVersion === undefined ? invocation.auth : { ...invocation.auth, cliVersion }
        try { await authoriseWorkspaceRelay(on, devicePrincipal(), { item: "cli-key", method: "POST", url: "https://api.example.com/v1/databases", headers: [], body: Buffer.from(body).toString("base64url") }, { ...invocation, auth }) } catch (error) { if (error instanceof VaultError && error.code === "approval_required") return error.extra; throw error }
        throw new Error("Expected approval_required")
      }
      const slug = (await deviceInvocation(ctx)).workspace.slug
      const first = await refusal("one", "0.3.17")
      const group = ctx.sql.exec<{ review_group: string }>("SELECT review_group FROM approvals WHERE id=?", first.approval as string).toArray()[0]!.review_group
      const code = ctx.sql.exec<{ code: string }>("SELECT code FROM approval_group_codes WHERE review_group=?", group).toArray()[0]!.code
      expect(first.group).toEqual({ id: group, url: `https://vault.test/w/${slug}/g/${group}`, open: 1, code })
      expect((first.next as { url: string }).url).toBe(`https://vault.test/w/${slug}/a/${first.approval as string}`)
      expect((await refusal("two", "0.4.0")).group).toEqual({ id: group, url: `https://vault.test/w/${slug}/g/${group}`, open: 2, code })
      for (const version of ["0.3.16", "0.3.0", null, undefined]) expect(await refusal("three", version), String(version)).not.toHaveProperty("group")
      const off = Object.assign(Object.create(ctx) as typeof ctx, { env: { ...ctx.env, APPROVAL_BATCHES: "off" } })
      expect(await refusal("four", "0.3.17", off)).not.toHaveProperty("group")
      // A bundled ask names no group, and is not counted among the open.
      ctx.sql.exec("UPDATE approvals SET bundle='bnd_test' WHERE id=?", first.approval as string)
      expect(await refusal("one", "0.3.17")).not.toHaveProperty("group")
      expect((await refusal("two", "0.3.17")).group).toMatchObject({ open: 2 })
    })
  })

  it("counts as open only the group's asks the machine can list, as /v1/pending lists them: never one hidden from it or gone stale", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async (ctx) => {
      registerWorkspacePendingProvider("credentials", () => [])
      const item = await seedCredential(ctx, "cli-key")
      fixtureSql(ctx).exec("UPDATE items SET policy=? WHERE slug='cli-key'", JSON.stringify({ default: "approve", rules: [] }))
      const invocation = await deviceInvocation(ctx)
      if (invocation.auth.kind !== "device") throw new Error("Expected a device")
      const at = { ...invocation, auth: { ...invocation.auth, cliVersion: "0.3.17" } }
      const refusal = async (body: string): Promise<Record<string, unknown>> => {
        try { await authoriseWorkspaceRelay(ctx, devicePrincipal(), { item: "cli-key", method: "POST", url: "https://api.example.com/v1/databases", headers: [], body: Buffer.from(body).toString("base64url") }, at) } catch (error) { if (error instanceof VaultError && error.code === "approval_required") return error.extra; throw error }
        throw new Error("Expected approval_required")
      }
      const hidden = (await refusal("hidden")).approval as string, stale = (await refusal("stale")).approval as string
      ctx.sql.exec("UPDATE approvals SET ask=json_set(ask,'$.credentials',json('[\"itm_not_this_machines\"]')) WHERE id=?", hidden)
      ctx.sql.exec("UPDATE approvals SET snapshot=json_set(snapshot,'$.run',json(?)) WHERE id=?", JSON.stringify({ items: [{ id: item.id, configRevision: -1 }] }), stale)
      await refusal("listed")
      const last = await refusal("also-listed")
      expect(last.group).toMatchObject({ open: 2 })
      const listed = await workspacePendingOps["pending.list"]!.handler(ctx, devicePrincipal(), {}, at) as PendingList
      expect(listed.groups?.map((group) => group.approvals.length)).toEqual([2])
    })
  })
})
