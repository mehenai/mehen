// Adopt reconcile in the adoptions area: a compare row's value is compared
// with the staged or stored value already holding its name, for the review
// page alone; the reviewer maps, replaces or renames it; machines send a
// value-free index of their plans; a person keeps a batch open longer.
import { describe, expect, it } from "vitest"
import { ADOPTION_LIMITS, AdoptionStatusSchema, NAME_UNAVAILABLE, canonicalJson, getTemplate, secretPrefix, sha256B64, type AdoptionDecisionInput, type AdoptionStatus } from "@mehen/protocol"
import { ADOPTION_CHANGED, adoptionsArea } from "../src/vault/areas/adoptions.ts"
import { fingerprint, items, stepUpDigest } from "../src/vault/areas/items.ts"
import { applyMigrations } from "../src/vault/tenant-vault.ts"
import { setSetting } from "../src/vault/areas/workspace-runtime.ts"
import { SENTINEL, addReference, allowPrivate, approve, box, call, genericItem, inventory, item, matches, planItem, refused, sendIndex, secondMachine, seedGeneric, start, status, storedFingerprint, upload, view } from "./adoptions-test-support.ts"
import { credentialInput, credentialsFixture, deviceInvocation, inAccess, memberInvocation, memberPrincipal, seedCredential, seedOAuthConnection } from "./credentials-test-support.ts"
import { projectFixture } from "./projects-workspace-fixture.ts"
import { type AdoptionChoice, adoptionActions, adoptionDecisions, adoptionRefusals } from "../src/ui/client/pages/workspace-adopt-logic.ts"
import { ADOPTION_HOLDER_GONE } from "../src/adoption-words.ts"
import type { ApiError } from "@mehen/protocol/api"
import { assertCredentialNameFree, checkedCredential, prepareCredential, registerCredentialServices, storeCredential } from "../src/vault/areas/items-workspace.ts"
import { fixtureSql } from "./fixture-sql.ts"
import { withTrustedSchema } from "../src/vault/areas/management-guard.ts"

// seedCredential's value.
const STORED = "test-secret-never-returned"
const OTHER = "sk-proj-another-value-9876543210zyxwvutsrq"
const DAY_MS = 86_400_000

// A store-only row staged as the first schema's upload wrote it.
async function firstSchemaRow(ctx: import("../src/vault/core.ts").VaultContext, adoption: string, ref: string, slug: string, value: string): Promise<void> {
  const template = getTemplate("openai")!
  const itemId = `itm_${ref}`, field = "key"
  const sealed = await ctx.sealField({ type: "adoption-secret", id: `${adoption}/${ref}/${field}` }, new TextEncoder().encode(value) as Uint8Array<ArrayBuffer>)
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await ctx.fingerprintKey(ctx.rootVersion), new TextEncoder().encode(`adopt/${adoption}\n${value}`)))
  ctx.sql.exec("INSERT INTO adoption_items(adoption,ref,item_id,device,slug,kind,provider,binding,injection,home,tags,public_fields,sources,repo,status,refusal,uploaded_at) VALUES (?,?,?,'dev_owner',?,'api-key','openai',?,?,?,?,'{}',?,?,'staged',NULL,?)", adoption, ref, itemId, slug, canonicalJson(template.binding), template.injection === null ? null : canonicalJson(template.injection), canonicalJson(ws), canonicalJson(["adopted"]), canonicalJson([{ machine: "dev_owner", path: "/home/alex/app/.env", variable: "OPENAI_API_KEY", pointer: null, stale: [] }]), canonicalJson({ remote: "github.com/alex/app", env: "dev" }), ctx.now())
  ctx.sql.exec("INSERT INTO adoption_secrets(adoption,ref,field,root_version,wrapped_dek,ciphertext,length,prefix,fingerprint,fp_version,box_digest,dup_tag) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", adoption, ref, field, sealed.rootVersion, sealed.wrappedDek, sealed.ciphertext, value.length, secretPrefix(value), await fingerprint(ctx, itemId, value, ctx.rootVersion), ctx.rootVersion, await stepUpDigest(await box(ctx, adoption, ref, field, value)), btoa(String.fromCharCode(...mac)))
}

describe("adoptions migration 2", () => {
  it("a workspace built on the first adoptions schema migrates, keeps its rows, and approves a batch staged before with the digest a store-only page signs", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      for (const table of ["adoption_batches", "adoption_items", "adoption_secrets", "adoption_machines", "adoption_indexes", "adoption_compare_counts"]) withTrustedSchema(ctx, () => ctx.sql.exec(`DROP TABLE ${table}`))
      ctx.sql.exec("DELETE FROM _migrations WHERE area='adoptions'")
      withTrustedSchema(ctx, () => applyMigrations(ctx.sql, ctx.storage, [{ ...adoptionsArea, migrations: adoptionsArea.migrations.slice(0, 1) }]))
      const columns = (table: string) => ctx.sql.exec<{ name: string }>(`SELECT name FROM pragma_table_info('${table}')`).toArray().map(c => c.name)
      expect([columns("adoption_items"), columns("adoption_secrets"), columns("adoption_indexes")]).toEqual([expect.not.arrayContaining(["compare"]), expect.not.arrayContaining(["match"]), []])
      const { adoption } = await start(ctx)
      await firstSchemaRow(ctx, adoption, "a001", "kept-row", SENTINEL)
      const before = { items: ctx.sql.exec("SELECT adoption,ref,item_id,slug,status FROM adoption_items").toArray(), secrets: ctx.sql.exec("SELECT adoption,ref,field,fingerprint,dup_tag FROM adoption_secrets").toArray() }
      withTrustedSchema(ctx, () => applyMigrations(ctx.sql, ctx.storage, [adoptionsArea]))
      expect(ctx.sql.exec<{ applied: number }>("SELECT applied FROM _migrations WHERE area='adoptions'").toArray()[0]!.applied).toBe(2)
      expect({ items: ctx.sql.exec("SELECT adoption,ref,item_id,slug,status FROM adoption_items").toArray(), secrets: ctx.sql.exec("SELECT adoption,ref,field,fingerprint,dup_tag FROM adoption_secrets").toArray() }).toEqual(before)
      expect(ctx.sql.exec("SELECT compare,holder,holder_version,action,decided_slug,repoint FROM adoption_items").toArray()).toEqual([{ compare: 0, holder: null, holder_version: null, action: null, decided_slug: null, repoint: null }])
      expect(ctx.sql.exec("SELECT match,target_fingerprint FROM adoption_secrets").toArray()).toEqual([{ match: null, target_fingerprint: null }])
      expect(ctx.sql.exec("SELECT * FROM adoption_indexes").toArray()).toEqual([])
      expect(ctx.sql.exec("SELECT * FROM adoption_compare_counts").toArray()).toEqual([])
      const v = await view(ctx, adoption)
      expect(v.items.map(i => [i.ref, i.slug, i.compare, i.problem])).toEqual([["a001", "kept-row", null, null]])
      const signed = { adoption, items: v.items.map(i => ({ ref: i.ref, include: true, slug: i.slug, kind: i.kind, provider: i.provider, binding: i.binding.value, injection: i.injection.value, home: ws, tags: i.tags, publicFields: i.publicFields, secrets: i.secrets.map(s => ({ name: s.name, length: s.length, prefix: s.prefix, fingerprint: s.fingerprint, box: s.box })) })) }
      const done = strict(await approve(ctx, v, [decide("a001")], "owner", await sha256B64(canonicalJson(signed))))
      expect(done).toMatchObject({ status: "approved", created: [{ ref: "a001", slug: "kept-row" }] })
      expect((await items.openSecrets(ctx, items.getItem(ctx, "kept-row")!)).key).toBe(SENTINEL)
    })
  })
})

describe("compare at upload", () => {
  it("a compare row against a stored holder records same or differs per field, answers as an ordinary row and tells the machine nothing", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const same = await seedCredential(ctx, "held-alike"), differs = await seedCredential(ctx, "held-unlike")
      const { adoption } = await start(ctx)
      const answer = await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-alike", STORED, { compare: true }), await item(ctx, adoption, "a002", "held-unlike", SENTINEL, { compare: true }), await item(ctx, adoption, "a003", "not-held", SENTINEL)])
      expect(answer).toEqual({ adoption, accepted: ["a001", "a002", "a003"], refused: [] })
      expect(matches(ctx, adoption)).toEqual({ a001: { holder: same.id, version: 1, match: ["same"] }, a002: { holder: differs.id, version: 1, match: ["differs"] }, a003: { holder: null, version: null, match: [null] } })
      // The value keyed under the holder's id is what the holder carries when equal.
      expect(ctx.sql.exec<{ target_fingerprint: string }>("SELECT target_fingerprint FROM adoption_secrets WHERE ref='a001'").toArray()[0]!.target_fingerprint).toBe(storedFingerprint(ctx, same.id))
      const machine = await status(ctx, adoption)
      expect(AdoptionStatusSchema.parse(machine)).toEqual(machine)
      expect(machine.staged).toEqual([{ ref: "a001", slug: "held-alike", machine: "office" }, { ref: "a002", slug: "held-unlike", machine: "office" }, { ref: "a003", slug: "not-held", machine: "office" }])
      expect(JSON.stringify([answer, machine])).not.toMatch(/same|differs|unknown/)
      const audit = ctx.sql.exec<{ target: string; detail: string }>("SELECT target,detail FROM audit WHERE action='adoption.compare' ORDER BY seq").toArray()
      expect(audit.map(a => [a.target, JSON.parse(a.detail)])).toEqual([["held-alike", { adoption, ref: "a001", item: same.id, outcome: "allowed", run: null }], ["held-unlike", { adoption, ref: "a002", item: differs.id, outcome: "allowed", run: null }]])
      // Names it holds are not taken from it by the compare rows.
      expect(ctx.sql.exec("SELECT match FROM adoption_secrets WHERE ref='a003'").toArray()).toEqual([{ match: null }])
    })
  })

  it("a compare row against a staged row of a batch this machine may use compares values, one compare per holder per batch", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const laptop = secondMachine(ctx)
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "staged-alike", SENTINEL), await item(ctx, adoption, "a002", "staged-unlike", SENTINEL)])
      const joined = await upload(ctx, adoption, [await item(ctx, adoption, "a003", "staged-alike", SENTINEL, { compare: true }), await item(ctx, adoption, "a004", "staged-unlike", OTHER, { compare: true })], laptop)
      expect(joined).toEqual({ adoption, accepted: ["a003", "a004"], refused: [] })
      expect(matches(ctx, adoption)).toMatchObject({ a003: { holder: `${adoption}/a001`, version: null, match: ["same"] }, a004: { holder: `${adoption}/a002`, version: null, match: ["differs"] } })
      expect(await upload(ctx, adoption, [await item(ctx, adoption, "a005", "staged-alike", OTHER, { compare: true })], laptop)).toEqual({ adoption, accepted: [], refused: [{ ref: "a005", reason: "Another row in this batch is already compared with this name." }] })
      // The staged name stays held by its row, not by the rows compared with it.
      expect(await upload(ctx, adoption, [await item(ctx, adoption, "a006", "staged-alike", OTHER)], laptop)).toEqual({ adoption, accepted: [], refused: [{ ref: "a006", reason: NAME_UNAVAILABLE.message }] })
      expect(ctx.sql.exec<{ target: string }>("SELECT target FROM audit WHERE action='adoption.compare' ORDER BY seq").toArray().map(a => a.target)).toEqual([`${adoption}/a001`, `${adoption}/a002`])
    })
  })

  it("a holder the machine cannot see is refused exactly as a taken name; a free name makes an ordinary row", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      await seedCredential(ctx, "admin-private", { kind: "member", member: "mem_admin" })
      const other = await start(ctx, "dev_admin")
      expect(await upload(ctx, other.adoption, [await item(ctx, other.adoption, "a001", "admin-staged", SENTINEL)], "dev_admin")).toMatchObject({ accepted: ["a001"] })
      const { adoption } = await start(ctx)
      const before = ctx.sql.exec<{ count: number }>("SELECT count FROM name_miss_buckets WHERE subject='device:dev_owner'").toArray()[0]?.count ?? 0
      const answer = await upload(ctx, adoption, [await item(ctx, adoption, "a001", "admin-private", STORED, { compare: true }), await item(ctx, adoption, "a002", "admin-staged", SENTINEL, { compare: true }), await item(ctx, adoption, "a003", "nobody-holds", SENTINEL, { compare: true })])
      expect(answer).toEqual({ adoption, accepted: ["a003"], refused: [{ ref: "a001", reason: NAME_UNAVAILABLE.message }, { ref: "a002", reason: NAME_UNAVAILABLE.message }] })
      expect(ctx.sql.exec<{ count: number }>("SELECT count FROM name_miss_buckets WHERE subject='device:dev_owner'").toArray()[0]!.count).toBe(before + 2)
      expect(ctx.sql.exec("SELECT compare,holder FROM adoption_items WHERE adoption=? AND ref='a003'", adoption).toArray()).toEqual([{ compare: 1, holder: null }])
      expect(ctx.sql.exec("SELECT 1 FROM audit WHERE action='adoption.compare'").toArray()).toEqual([])
    })
  })

  it(`past ${ADOPTION_LIMITS.maxComparesPerTargetPerDay} compares with one holder in a day the result is unknown, and compare rows count towards the batch's limits`, async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const held = await seedCredential(ctx, "often-compared")
      const day = Math.floor(ctx.now() / DAY_MS)
      ctx.sql.exec("INSERT INTO adoption_compare_counts(target,day,count) VALUES (?,?,?),('itm_old',?,3)", held.id, day, ADOPTION_LIMITS.maxComparesPerTargetPerDay - 1, day - 2)
      const first = await start(ctx)
      await upload(ctx, first.adoption, [await item(ctx, first.adoption, "a001", "often-compared", STORED, { compare: true })])
      const second = await start(ctx)
      await upload(ctx, second.adoption, [await item(ctx, second.adoption, "a001", "often-compared", STORED, { compare: true })])
      expect([matches(ctx, first.adoption).a001!.match, matches(ctx, second.adoption).a001!.match]).toEqual([["same"], ["unknown"]])
      expect(ctx.sql.exec("SELECT target,count FROM adoption_compare_counts").toArray()).toEqual([{ target: held.id, count: ADOPTION_LIMITS.maxComparesPerTargetPerDay + 1 }])
      const third = await start(ctx)
      for (let i = 0; i < ADOPTION_LIMITS.maxItems; i++) ctx.sql.exec("INSERT INTO adoption_items(adoption,ref,item_id,device,slug,kind,provider,binding,injection,home,tags,public_fields,sources,repo,status,refusal,uploaded_at) VALUES (?,?,?,?,?,'api-key','openai','{}',NULL,'{\"kind\":\"workspace\"}','[]','{}','[]',NULL,'staged',NULL,0)", third.adoption, `z${i.toString(36).padStart(4, "0")}`, `itm_z${i}`, "dev_owner", `filler-${i}`)
      expect((await upload(ctx, third.adoption, [await item(ctx, third.adoption, "a001", "often-compared", STORED, { compare: true })])).refused).toEqual([{ ref: "a001", reason: `This batch is full: at most ${ADOPTION_LIMITS.maxItems} credentials.` }])
    })
  })
})

describe("the view of a compare row", () => {
  it("shows a stored holder, the result and the fingerprint a replace stores, what a replace would reach, and how long the batch can be kept open", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const held = await seedCredential(ctx, "held-alike")
      addReference(ctx, held, "prj_a", "dev", "OPENAI_API_KEY")
      ctx.sql.exec("INSERT INTO exposures(event,item,version,member,device,source,at) VALUES ('lease-1',?,?,'mem_member','dev_member','leased',1),('lease-2',?,?,'mem_member','dev_member','leased',2),('lease-old',?,0,'mem_admin','dev_admin','leased',3)", held.id, held.version, held.id, held.version, held.id)
      const earlier = await start(ctx)
      ctx.sql.exec("UPDATE adoption_machines SET name='old-laptop' WHERE adoption=?", earlier.adoption)
      ctx.sql.exec("INSERT INTO adoption_items(adoption,ref,item_id,device,slug,kind,provider,binding,injection,home,tags,public_fields,sources,repo,status,refusal,uploaded_at) VALUES (?,'a001',?,'dev_owner','held-alike','api-key','openai','{}',NULL,'{\"kind\":\"workspace\"}','[]','{}','[]',NULL,'created',NULL,0)", earlier.adoption, held.id)
      const client = await seedOAuthConnection(ctx)
      const clientItem = ctx.sql.exec<{ id: string }>("SELECT id FROM items WHERE slug='google-client'").one()
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-alike", STORED, { compare: true }), await item(ctx, adoption, "a002", "google-client", SENTINEL, { compare: true }), await item(ctx, adoption, "a003", "ordinary", SENTINEL)])
      // A root key rotated since upload: the value under the holder's id is recomputed.
      ctx.sql.exec("UPDATE adoption_secrets SET fp_version=fp_version-1,target_fingerprint='stale' WHERE adoption=? AND ref='a001'", adoption)
      const v = await view(ctx, adoption)
      const created = ctx.sql.exec<{ created_at: number }>("SELECT created_at FROM adoption_batches WHERE id=?", adoption).one().created_at
      expect(v.maxExpiresAt).toBe(new Date(created + ADOPTION_LIMITS.maxLifeMs).toISOString())
      const [alike, oauth, ordinary] = v.items
      expect(alike!.compare).toEqual({
        holder: { type: "stored", id: held.id, slug: "held-alike", kind: "api-key", version: 1, secrets: [{ name: "key", length: STORED.length, prefix: expect.any(String) }], rotatedAt: null, lastUsedAt: null },
        fields: [{ name: "key", result: "same", fingerprint: storedFingerprint(ctx, held.id) }],
        affected: { references: [{ project: "project-a", env: "dev", variable: "OPENAI_API_KEY" }], machines: ["old-laptop"], leasingDevices: 1, connections: [] },
      })
      expect(alike!.problem).toBeNull()
      expect(oauth!.compare).toMatchObject({ holder: { type: "stored", id: clientItem.id, kind: "oauth-client" }, fields: [{ name: "key", result: "differs" }], affected: { connections: [client.slug] } })
      expect(ordinary!.compare).toBeNull()
      expect(JSON.stringify(v)).not.toContain(STORED)
      expect(JSON.stringify(v)).not.toContain(SENTINEL)
    })
  })

  it("a low-entropy kind's result and fingerprint are shown only to a reviewer who may rotate the stored holder, never against a staged one", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const pin = await seedGeneric(ctx, "shared-pin", "4711")
      const mine = { kind: "member" as const, member: "mem_member" }
      const owners = await start(ctx)
      await upload(ctx, owners.adoption, [await genericItem(ctx, owners.adoption, "a001", "shared-pin", "4711", { compare: true }), await genericItem(ctx, owners.adoption, "a002", "staged-pin", "4711")])
      await upload(ctx, owners.adoption, [await genericItem(ctx, owners.adoption, "a003", "staged-pin", "4711", { compare: true })], secondMachine(ctx))
      allowPrivate(ctx, "dev_member")
      const members = await start(ctx, "dev_member")
      await upload(ctx, members.adoption, [await genericItem(ctx, members.adoption, "a001", "shared-pin", "4711", { compare: true, home: mine })], "dev_member")
      // One compare row per holder per batch, whatever its kind.
      await upload(ctx, members.adoption, [await item(ctx, members.adoption, "a002", "shared-pin", "4711", { compare: true, home: mine })], "dev_member").then(r => expect(r.refused).toEqual([{ ref: "a002", reason: "Another row in this batch is already compared with this name." }]))
      const fields = (v: Awaited<ReturnType<typeof view>>) => v.items.filter(i => i.compare).map(i => [i.ref, i.compare!.fields])
      expect(fields(await view(ctx, owners.adoption))).toEqual([["a001", [{ name: "value", result: "same", fingerprint: storedFingerprint(ctx, pin.id, "value") }]], ["a003", [{ name: "value", result: "unknown", fingerprint: null }]]])
      expect(matches(ctx, owners.adoption).a003!.match).toEqual(["same"])
      expect(fields(await view(ctx, members.adoption, "member"))).toEqual([["a001", [{ name: "value", result: "unknown", fingerprint: null }]]])
      expect(matches(ctx, members.adoption).a001!.match).toEqual(["same"])
    })
  })

  it("a compare row is left out of sameValueAs, so equality with a low-entropy staged holder shows nowhere", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await genericItem(ctx, adoption, "a001", "pin-one", "4711"), await genericItem(ctx, adoption, "a002", "pin-two", "4711")])
      await upload(ctx, adoption, [await genericItem(ctx, adoption, "a003", "pin-one", "4711", { compare: true })], secondMachine(ctx))
      const v = await view(ctx, adoption)
      expect(v.items.map(i => [i.ref, i.sameValueAs, i.compare?.fields.map(x => x.result) ?? null])).toEqual([["a001", ["a002"], null], ["a002", ["a001"], null], ["a003", [], ["unknown"]]])
    })
  })

  it("a reviewer who may rotate the holder but not change a protected environment using it sees the result without a fingerprint to replace with", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const held = await seedCredential(ctx, "project-held", { kind: "project", project: "prj_a" })
      addReference(ctx, held, "prj_b", "staging")
      allowPrivate(ctx, "dev_kim")
      const { adoption } = await start(ctx, "dev_kim")
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "project-held", STORED, { compare: true, home: { kind: "member", member: "mem_kim" } })], "dev_kim")
      const v = await view(ctx, adoption, "kim")
      expect(v.items[0]!.compare).toMatchObject({ fields: [{ name: "key", result: "same", fingerprint: null }], affected: { references: [] } })
      expect(JSON.stringify(v)).not.toContain("project-b")
    })
  })

  it("what a replace would reach names only the machines of batches this reviewer may see", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const held = await seedCredential(ctx, "held-alike")
      allowPrivate(ctx, "dev_member")
      const owners = await start(ctx), earlier = await start(ctx, "dev_member")
      ctx.sql.exec("UPDATE adoption_machines SET name='owners-office' WHERE adoption=?", owners.adoption)
      ctx.sql.exec("UPDATE adoption_machines SET name='members-laptop' WHERE adoption=?", earlier.adoption)
      ctx.sql.exec("INSERT INTO adoption_items(adoption,ref,item_id,device,slug,kind,provider,binding,injection,home,tags,public_fields,sources,repo,status,refusal,uploaded_at) VALUES (?,'a001',?,'dev_owner','held-alike','api-key','openai','{}',NULL,'{\"kind\":\"workspace\"}','[]','{}','[]',NULL,'created',NULL,0)", owners.adoption, held.id)
      ctx.sql.exec("INSERT INTO adoption_items(adoption,ref,item_id,device,slug,kind,provider,binding,injection,home,tags,public_fields,sources,repo,status,refusal,uploaded_at,holder,holder_version) VALUES (?,'a001','itm_unused','dev_member','held-alike','api-key','openai','{}',NULL,'{\"kind\":\"workspace\"}','[]','{}','[]',NULL,'mapped',NULL,0,?,1)", earlier.adoption, held.id)
      const { adoption } = await start(ctx, "dev_member")
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-alike", STORED, { compare: true, home: { kind: "member", member: "mem_member" } })], "dev_member")
      const v = await view(ctx, adoption, "member")
      expect(v.items[0]!.compare!.affected!.machines).toEqual(["members-laptop"])
      expect(JSON.stringify(v)).not.toContain("owners-office")
    })
  })

  it("a stored holder gone since upload leaves the row with a problem and no compare", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const held = await seedCredential(ctx, "soon-gone")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "soon-gone", STORED, { compare: true })])
      fixtureSql(ctx).exec("DELETE FROM items WHERE id=?", held.id)
      const [row] = (await view(ctx, adoption)).items
      expect([row!.compare, row!.problem]).toEqual([null, "What this row was compared with is gone or hidden from you; send it again or leave it out."])
    })
  })
})

// Every status answer parses under the strict schema, so no result reaches a machine.
function strict(answer: AdoptionStatus): AdoptionStatus { expect(AdoptionStatusSchema.parse(answer)).toEqual(answer); return answer }
const ws = { kind: "workspace" as const }
const decide = (ref: string, extra: Partial<AdoptionDecisionInput> = {}): AdoptionDecisionInput => ({ ref, include: true, home: ws, ...extra })
const itemCount = (ctx: import("../src/vault/core.ts").VaultContext) => ctx.sql.exec<{ n: number }>("SELECT count(*) AS n FROM items").one().n

describe("approve with actions", () => {
  it("a store-only batch approves with the digest it signed before actions existed", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "plain-one", SENTINEL), await item(ctx, adoption, "a002", "plain-two", OTHER)])
      const v = await view(ctx, adoption)
      const before = { adoption, items: v.items.map(i => i.ref === "a002" ? { ref: i.ref, include: false } : { ref: i.ref, include: true, slug: i.slug, kind: i.kind, provider: i.provider, binding: i.binding.value, injection: i.injection.value, home: ws, tags: i.tags, publicFields: i.publicFields, secrets: i.secrets.map(s => ({ name: s.name, length: s.length, prefix: s.prefix, fingerprint: s.fingerprint, box: s.box })) }) }
      const done = strict(await approve(ctx, v, [decide("a001"), decide("a002", { include: false })], "owner", await sha256B64(canonicalJson(before))))
      expect(done).toMatchObject({ status: "approved", created: [{ ref: "a001", slug: "plain-one" }], refused: [{ ref: "a002" }] })
    })
  })

  it("the review page's decisions store a store-only row and a free-name compare row explicitly, under the digest a store-only page signed, and a retry answers what was stored", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "plain-one", SENTINEL), await item(ctx, adoption, "a002", "free-compared", OTHER, { compare: true })])
      const v = await view(ctx, adoption)
      expect(v.items.map(i => [i.ref, i.compare, i.problem])).toEqual([["a001", null, null], ["a002", null, null]])
      const built = adoptionDecisions(adoption, v.items, new Map(v.items.map(i => [i.ref, { include: true, home: "workspace" }])))
      if (!built.ok) throw new Error(built.error.message)
      expect(built.decisions).toEqual([decide("a001", { action: "store" }), decide("a002", { action: "store" })])
      const before = { adoption, items: v.items.map(i => ({ ref: i.ref, include: true, slug: i.slug, kind: i.kind, provider: i.provider, binding: i.binding.value, injection: i.injection.value, home: ws, tags: i.tags, publicFields: i.publicFields, secrets: i.secrets.map(s => ({ name: s.name, length: s.length, prefix: s.prefix, fingerprint: s.fingerprint, box: s.box })) })) }
      const done = strict(await approve(ctx, v, built.decisions, "owner", await sha256B64(canonicalJson(before))))
      expect(done).toMatchObject({ status: "approved", created: [{ ref: "a001", slug: "plain-one" }, { ref: "a002", slug: "free-compared" }] })
      expect(strict(await approve(ctx, v, built.decisions))).toEqual(done)
    })
  })

  it("map keeps the vault's value and stores nothing; a compare row with no action, same, differing or free, or a held one with store, refuses the approval", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const alike = await seedCredential(ctx, "held-alike"), unlike = await seedCredential(ctx, "held-unlike")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-alike", STORED, { compare: true }), await item(ctx, adoption, "a002", "held-unlike", SENTINEL, { compare: true }), await item(ctx, adoption, "a003", "fresh-one", SENTINEL), await item(ctx, adoption, "a004", "free-compared", OTHER, { compare: true })])
      const v = await view(ctx, adoption)
      const noAction = "This row was sent to be compared, so it needs a decision: store it, keep the vault's value, replace it or keep both under another name."
      const undecided = await refused(approve(ctx, v, [decide("a001"), decide("a002"), decide("a003"), decide("a004")]))
      expect(undecided.refused).toEqual([{ ref: "a001", reason: noAction }, { ref: "a002", reason: noAction }, { ref: "a004", reason: noAction }])
      expect((await refused(approve(ctx, v, [decide("a001", { action: "map" }), decide("a002", { action: "store" }), decide("a003", { action: "map" }), decide("a004", { action: "store" })]))).refused).toEqual([
        { ref: "a002", reason: "This name is already held: keep the vault's value, replace it or keep both under another name." },
        { ref: "a003", reason: "Nothing else holds this name, so this row can only be stored." },
      ])
      const before = itemCount(ctx)
      const decisions = [decide("a001", { action: "map" }), decide("a002", { action: "map" }), decide("a003"), decide("a004", { action: "store" })]
      const done = strict(await approve(ctx, v, decisions))
      expect(done).toMatchObject({ status: "approved", created: [{ ref: "a003", slug: "fresh-one" }, { ref: "a004", slug: "free-compared" }], mapped: [{ ref: "a001", slug: "held-alike" }, { ref: "a002", slug: "held-unlike" }] })
      expect(done.replaced).toBeUndefined()
      expect(itemCount(ctx)).toBe(before + 2)
      expect([items.getItem(ctx, "held-alike")!.version, items.getItem(ctx, "held-unlike")!.version, storedFingerprint(ctx, unlike.id)]).toEqual([alike.version, unlike.version, storedFingerprint(ctx, unlike.id)])
      expect(ctx.sql.exec("SELECT ref,status,action FROM adoption_items WHERE adoption=? ORDER BY ref", adoption).toArray()).toEqual([{ ref: "a001", status: "mapped", action: "map" }, { ref: "a002", status: "mapped", action: "map" }, { ref: "a003", status: "created", action: null }, { ref: "a004", status: "created", action: "store" }])
      // The same decisions again answer what was stored; another action does not.
      expect(strict(await approve(ctx, v, decisions))).toEqual(done)
      expect((await refused(approve(ctx, v, [decide("a001", { action: "map" }), decide("a002", { action: "rename", slug: "held-unlike-2" }), decide("a003"), decide("a004", { action: "store" })]))).error).toBe("conflict")
      expect(strict(await status(ctx, adoption))).toEqual(done)
    })
  })

  it("replace changes only the row's fields: the holder keeps its config and its other secret values", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const login = { ...credentialInput("held-login"), kind: "password-login" as const, injection: null, ceiling: "relay" as const, publicFields: { url: "https://app.example.com", username: "alex" }, secretFields: { password: "old-password-value", totp_seed: "JBSWY3DPEHPK3PXP" } }
      const prepared = await prepareCredential(ctx, login, null)
      const held = ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-login", SENTINEL, { kind: "password-login", provider: null, binding: { hosts: ["api.example.com"] }, publicFields: { url: "https://app.example.com", username: "alex" }, sealed: { password: await box(ctx, adoption, "a001", "password", SENTINEL) }, compare: true })])
      const v = await view(ctx, adoption)
      strict(await approve(ctx, v, [decide("a001", { action: "replace" })]))
      const after = checkedCredential(ctx, "held-login")!
      const { version: _v, updatedAt: _u, ...kept } = after
      const { version: _hv, updatedAt: _hu, ...was } = held
      expect([after.version, kept]).toEqual([held.version + 1, was])
      expect(await items.openSecrets(ctx, after)).toEqual({ password: SENTINEL, totp_seed: "JBSWY3DPEHPK3PXP" })
    })
  })

  it("replace keeps the holder's previous values for 30 days, and a passkey restore puts them back", async () => {
    const { WorkspaceStepUpActionSchema } = await import("@mehen/protocol")
    const { workspaceItemOps } = await import("../src/vault/areas/items-workspace.ts")
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const login = { ...credentialInput("held-login"), kind: "password-login" as const, injection: null, ceiling: "relay" as const, publicFields: { url: "https://app.example.com", username: "alex" }, secretFields: { password: "old-password-value", totp_seed: "JBSWY3DPEHPK3PXP" } }
      const prepared = await prepareCredential(ctx, login, null)
      const held = ctx.storage.transactionSync(() => storeCredential(ctx, prepared, memberPrincipal(ctx), "item.create"))
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-login", SENTINEL, { kind: "password-login", provider: null, binding: { hosts: ["api.example.com"] }, publicFields: { url: "https://app.example.com", username: "alex" }, sealed: { password: await box(ctx, adoption, "a001", "password", SENTINEL) }, compare: true })])
      strict(await approve(ctx, await view(ctx, adoption), [decide("a001", { action: "replace" })]))
      const owner = memberPrincipal(ctx), by = owner.kind === "member" ? `member:${owner.memberId}` : ""
      const kept = ctx.sql.exec<{ name: string; version: number; replaced_by: string; replaced_at: number; expires_at: number }>("SELECT name,version,replaced_by,replaced_at,expires_at FROM item_secret_history WHERE item=? ORDER BY name", held.id).toArray()
      expect(kept.map(k => [k.name, k.version, k.replaced_by, k.expires_at - k.replaced_at])).toEqual([["password", held.version, by, ADOPTION_LIMITS.replacedKeptMs], ["totp_seed", held.version, by, ADOPTION_LIMITS.replacedKeptMs]])
      const terms = { version: held.version + 1, previous: held.version }
      const p = memberPrincipal(ctx, "owner")
      const signed = WorkspaceStepUpActionSchema.parse(await workspaceItemOps["items.action"].handler(ctx, p, { slug: "held-login", action: "restore", ...terms }, memberInvocation(ctx, "owner")))
      await workspaceItemOps["items.restore"].handler(ctx, p, { slug: "held-login", ...terms }, memberInvocation(ctx, "owner", signed))
      const restored = checkedCredential(ctx, "held-login")!
      expect(restored.version).toBe(held.version + 2)
      expect(await items.openSecrets(ctx, restored)).toEqual({ password: "old-password-value", totp_seed: "JBSWY3DPEHPK3PXP" })
    })
  })

  it("replace rotates the stored holder to this row's value under the signed fingerprint, and fails ADOPTION_CHANGED once the holder has moved", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const held = await seedCredential(ctx, "held-unlike")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-unlike", SENTINEL, { compare: true })])
      const v = await view(ctx, adoption)
      const signed = v.items[0]!.compare!.fields[0]!.fingerprint
      const done = strict(await approve(ctx, v, [decide("a001", { action: "replace" })]))
      expect(done).toMatchObject({ status: "approved", replaced: [{ ref: "a001", slug: "held-unlike" }] })
      expect([done.created, done.mapped]).toEqual([undefined, undefined])
      const after = items.getItem(ctx, "held-unlike")!
      expect([after.id, after.version, storedFingerprint(ctx, held.id)]).toEqual([held.id, held.version + 1, signed])
      expect((await items.openSecrets(ctx, after)).key).toBe(SENTINEL)
      expect(ctx.sql.exec<{ action: string }>("SELECT action FROM audit WHERE target='held-unlike' AND action IN ('item.rotate','adoption.item') ORDER BY seq").toArray().map(a => a.action)).toEqual(["item.rotate", "adoption.item"])

      const again = await start(ctx)
      await upload(ctx, again.adoption, [await item(ctx, again.adoption, "a001", "held-unlike", OTHER, { compare: true })])
      const stale = await view(ctx, again.adoption)
      await items.replaceSecrets(ctx, "held-unlike", { key: "rotated-meanwhile-0123456789" }, { kind: "system", reason: "test" })
      expect(await refused(approve(ctx, stale, [decide("a001", { action: "replace" })]))).toMatchObject({ error: "conflict", message: ADOPTION_CHANGED })
      expect(storedFingerprint(ctx, held.id)).not.toBe(stale.items[0]!.compare!.fields[0]!.fingerprint)
    })
  })

  it("replace needs credential.rotate on the holder, and the right to change every protected environment using it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      await seedCredential(ctx, "workspace-held")
      const projectHeld = await seedCredential(ctx, "project-held", { kind: "project", project: "prj_a" })
      addReference(ctx, projectHeld, "prj_b", "staging")
      allowPrivate(ctx, "dev_member")
      allowPrivate(ctx, "dev_kim")
      const members = await start(ctx, "dev_member"), kims = await start(ctx, "dev_kim")
      await upload(ctx, members.adoption, [await item(ctx, members.adoption, "a001", "workspace-held", SENTINEL, { compare: true, home: { kind: "member", member: "mem_member" } })], "dev_member")
      await upload(ctx, kims.adoption, [await item(ctx, kims.adoption, "a001", "project-held", SENTINEL, { compare: true, home: { kind: "member", member: "mem_kim" } })], "dev_kim")
      const member = await view(ctx, members.adoption, "member"), kim = await view(ctx, kims.adoption, "kim")
      expect((await refused(approve(ctx, member, [{ ref: "a001", include: true, home: { kind: "member", member: "mem_member" }, action: "replace" }], "member"))).refused).toEqual([{ ref: "a001", reason: "You cannot change this credential's value." }])
      expect((await refused(approve(ctx, kim, [{ ref: "a001", include: true, home: { kind: "member", member: "mem_kim" }, action: "replace" }], "kim"))).refused).toEqual([{ ref: "a001", reason: "A protected environment uses this credential; only someone who may change protected environments there can replace its value." }])
      expect(items.getItem(ctx, "project-held")!.version).toBe(projectHeld.version)
      // Keeping both needs no right over the holder.
      expect(strict(await approve(ctx, kim, [{ ref: "a001", include: true, home: { kind: "member", member: "mem_kim" }, action: "rename", slug: "project-held-kim" }], "kim"))).toMatchObject({ created: [{ ref: "a001", slug: "project-held-kim" }] })
    })
  })

  it("against a staged holder of the same batch, replace stores this row and maps the holder; map needs the holder stored too", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const laptop = secondMachine(ctx)
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "shared-key", SENTINEL), await item(ctx, adoption, "a002", "kept-key", SENTINEL)])
      await upload(ctx, adoption, [await item(ctx, adoption, "a003", "shared-key", OTHER, { compare: true }), await item(ctx, adoption, "a004", "kept-key", SENTINEL, { compare: true })], laptop)
      const v = await view(ctx, adoption)
      expect((await refused(approve(ctx, v, [decide("a001"), decide("a002", { include: false }), decide("a003", { action: "replace" }), decide("a004", { action: "map" })]))).refused).toEqual([{ ref: "a004", reason: "The row this one was compared with is left out; store that row too, or keep both under another name." }])
      const done = strict(await approve(ctx, v, [decide("a001"), decide("a002"), decide("a003", { action: "replace" }), decide("a004", { action: "map" })]))
      expect(done).toMatchObject({ created: [{ ref: "a002", slug: "kept-key" }, { ref: "a003", slug: "shared-key" }], mapped: [{ ref: "a001", slug: "shared-key" }, { ref: "a004", slug: "kept-key" }] })
      const winner = ctx.sql.exec<{ item_id: string }>("SELECT item_id FROM adoption_items WHERE adoption=? AND ref='a003'", adoption).one().item_id
      expect(items.getItem(ctx, "shared-key")!.id).toBe(winner)
      expect((await items.openSecrets(ctx, items.getItem(ctx, "shared-key")!)).key).toBe(OTHER)
      expect(done.machines).toEqual([{ device: "dev_owner", name: "office", items: 2 }, { device: laptop, name: "laptop", items: 2 }])
    })
  })

  it("a holder hidden from the reviewer since upload cannot be mapped or replaced, as the view says, and nothing is written; keeping both still can", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const held = await seedCredential(ctx, "soon-hidden")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "soon-hidden", SENTINEL, { compare: true })])
      fixtureSql(ctx).exec("UPDATE items SET home_kind='member',home_id='mem_admin' WHERE id=?", held.id)
      const v = await view(ctx, adoption)
      const hidden = "What this row was compared with is gone or hidden from you; send it again or leave it out."
      expect([v.items[0]!.compare, v.items[0]!.problem]).toEqual([null, hidden])
      const before = { items: itemCount(ctx), version: items.getItem(ctx, "soon-hidden")!.version, key: storedFingerprint(ctx, held.id), audit: ctx.sql.exec<{ n: number }>("SELECT count(*) AS n FROM audit WHERE action IN ('adoption.item','item.rotate')").one().n }
      for (const action of ["map", "replace"] as const) expect((await refused(approve(ctx, v, [decide("a001", { action })]))).refused).toEqual([{ ref: "a001", reason: hidden }])
      expect({ items: itemCount(ctx), version: items.getItem(ctx, "soon-hidden")!.version, key: storedFingerprint(ctx, held.id), audit: ctx.sql.exec<{ n: number }>("SELECT count(*) AS n FROM audit WHERE action IN ('adoption.item','item.rotate')").one().n }).toEqual(before)
      expect(strict(await approve(ctx, v, [decide("a001", { action: "rename", slug: "soon-hidden-2" })]))).toMatchObject({ created: [{ ref: "a001", slug: "soon-hidden-2" }] })
    })
  })

  it("the review page offers a row whose holder is gone or hidden only a copy under another name, which the vault refuses, before any write, once the holder is gone", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const hidden = await seedCredential(ctx, "page-hidden"), gone = await seedCredential(ctx, "page-gone")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "page-hidden", SENTINEL, { compare: true }), await item(ctx, adoption, "a002", "page-gone", SENTINEL, { compare: true })])
      fixtureSql(ctx).exec("UPDATE items SET home_kind='member',home_id='mem_admin' WHERE id=?", hidden.id)
      fixtureSql(ctx).exec("DELETE FROM items WHERE id=?", gone.id)
      const v = await view(ctx, adoption)
      expect(v.items.map(i => [i.ref, i.compare, i.problem, adoptionActions(i, adoption)])).toEqual([["a001", null, ADOPTION_HOLDER_GONE, ["rename"]], ["a002", null, ADOPTION_HOLDER_GONE, ["rename"]]])
      const page = (choices: [string, AdoptionChoice][]) => { const built = adoptionDecisions(adoption, v.items, new Map(choices)); if (!built.ok) throw new Error(built.error.message); return built.decisions }
      const keepHidden: [string, AdoptionChoice] = ["a001", { include: true, home: "workspace", action: "rename", slug: "page-hidden-copy" }]
      const keepGone: [string, AdoptionChoice] = ["a002", { include: true, home: "workspace", action: "rename", slug: "page-gone-copy" }]
      const before = itemCount(ctx)
      const answer = await refused(approve(ctx, v, page([keepHidden, keepGone])))
      expect(answer.refused).toEqual([{ ref: "a002", reason: ADOPTION_HOLDER_GONE }])
      expect(adoptionRefusals(answer as ApiError)).toEqual(new Map([["a002", ADOPTION_HOLDER_GONE]]))
      expect(itemCount(ctx)).toBe(before)
      expect(strict(await approve(ctx, v, page([keepHidden])))).toMatchObject({ created: [{ ref: "a001", slug: "page-hidden-copy" }] })
    })
  })

  it("a staged holder, as a stored one, is replaced only by a row of the same kind", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "shared-key", SENTINEL)])
      await upload(ctx, adoption, [await genericItem(ctx, adoption, "a002", "shared-key", "4711", { compare: true })], secondMachine(ctx))
      const v = await view(ctx, adoption)
      const before = itemCount(ctx)
      expect((await refused(approve(ctx, v, [decide("a001"), decide("a002", { action: "replace" })]))).refused).toEqual([{ ref: "a002", reason: "Only a credential of the same kind can replace this one." }])
      expect([itemCount(ctx), items.getItem(ctx, "shared-key")]).toEqual([before, null])
    })
  })

  it("a compare row against a staged row of another open batch cannot map or replace until that batch is decided, but can keep both", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const first = await start(ctx)
      await upload(ctx, first.adoption, [await item(ctx, first.adoption, "a001", "elsewhere", SENTINEL)])
      const second = await start(ctx)
      await upload(ctx, second.adoption, [await item(ctx, second.adoption, "a001", "elsewhere", SENTINEL, { compare: true })])
      const v = await view(ctx, second.adoption)
      for (const action of ["map", "replace"] as const) expect((await refused(approve(ctx, v, [decide("a001", { action })]))).refused).toEqual([{ ref: "a001", reason: "The row this one was compared with waits in another batch; approve that batch first, or keep both under another name." }])
      expect(strict(await approve(ctx, v, [decide("a001", { action: "rename", slug: "elsewhere-2" })]))).toMatchObject({ created: [{ ref: "a001", slug: "elsewhere-2" }] })
    })
  })

  it("once the staged holder's batch is approved, the row is compared again with the item now stored, and maps or replaces it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const first = await start(ctx)
      await upload(ctx, first.adoption, [await item(ctx, first.adoption, "a001", "shared-key", SENTINEL), await item(ctx, first.adoption, "a002", "other-key", SENTINEL)])
      const second = await start(ctx)
      await upload(ctx, second.adoption, [await item(ctx, second.adoption, "a001", "shared-key", SENTINEL, { compare: true }), await item(ctx, second.adoption, "a002", "other-key", OTHER, { compare: true })])
      strict(await approve(ctx, await view(ctx, first.adoption), [decide("a001"), decide("a002")]))
      const shared = items.getItem(ctx, "shared-key")!, other = items.getItem(ctx, "other-key")!
      const v = await view(ctx, second.adoption)
      expect(v.items.map(i => [i.compare?.holder.type, i.compare?.holder.id, i.compare?.holder.version, i.compare?.fields.map(x => x.result), i.problem])).toEqual([["stored", shared.id, 1, ["same"], null], ["stored", other.id, 1, ["differs"], null]])
      expect(v.items[1]!.compare!.fields[0]!.fingerprint).toEqual(expect.any(String))
      expect(ctx.sql.exec<{ target: string }>("SELECT target FROM audit WHERE action='adoption.compare' ORDER BY seq").toArray().map(a => a.target)).toEqual([`${first.adoption}/a001`, `${first.adoption}/a002`, "shared-key", "other-key"])
      const done = strict(await approve(ctx, v, [decide("a001", { action: "map" }), decide("a002", { action: "replace" })]))
      expect(done).toMatchObject({ mapped: [{ ref: "a001", slug: "shared-key" }], replaced: [{ ref: "a002", slug: "other-key" }] })
      expect([items.getItem(ctx, "shared-key")!.version, (await items.openSecrets(ctx, items.getItem(ctx, "other-key")!)).key]).toEqual([shared.version, OTHER])
    })
  })

  it("once the staged holder's batch is cancelled or expired, the name is free and the row is stored", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const cancelled = await start(ctx), expired = await start(ctx)
      await upload(ctx, cancelled.adoption, [await item(ctx, cancelled.adoption, "a001", "freed-key", SENTINEL)])
      await upload(ctx, expired.adoption, [await item(ctx, expired.adoption, "a001", "lapsed-key", SENTINEL)])
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "freed-key", OTHER, { compare: true }), await item(ctx, adoption, "a002", "lapsed-key", OTHER, { compare: true })])
      await call(ctx, "adoption.cancel", { adoption: cancelled.adoption }, await deviceInvocation(ctx, "dev_owner"))
      ctx.sql.exec("UPDATE adoption_batches SET expires_at=? WHERE id=?", ctx.now(), expired.adoption)
      const v = await view(ctx, adoption)
      expect(v.items.map(i => [i.compare, i.problem])).toEqual([[null, null], [null, null]])
      const done = strict(await approve(ctx, v, [decide("a001", { action: "store" }), decide("a002", { action: "store" })]))
      expect(done).toMatchObject({ created: [{ ref: "a001", slug: "freed-key" }, { ref: "a002", slug: "lapsed-key" }] })
      expect((await items.openSecrets(ctx, items.getItem(ctx, "freed-key")!)).key).toBe(OTHER)
    })
  })

  it("rename stores under the new name and refuses a taken one, leaving the holder as it was", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const held = await seedCredential(ctx, "held-unlike")
      await seedCredential(ctx, "already-here")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-unlike", SENTINEL, { compare: true }), await item(ctx, adoption, "a002", "staged-name", SENTINEL)])
      const v = await view(ctx, adoption)
      for (const slug of ["already-here", "staged-name"]) expect(await refused(approve(ctx, v, [decide("a001", { action: "rename", slug }), decide("a002")]))).toEqual(NAME_UNAVAILABLE)
      const done = strict(await approve(ctx, v, [decide("a001", { action: "rename", slug: "held-unlike-laptop" }), decide("a002")]))
      expect(done).toMatchObject({ created: [{ ref: "a001", slug: "held-unlike-laptop" }, { ref: "a002", slug: "staged-name" }] })
      expect(items.getItem(ctx, "held-unlike")!.version).toBe(held.version)
      expect(ctx.sql.exec("SELECT decided_slug,repoint FROM adoption_items WHERE adoption=? AND ref='a001'", adoption).one()).toEqual({ decided_slug: "held-unlike-laptop", repoint: null })
    })
  })
})

describe("a compare row whose staged holder's batch has closed", () => {
  it("is bound to nothing once another row of its batch compares with the item its holder became, refused every action but being left out, and the rest of the batch approves", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const holders = await start(ctx)
      await upload(ctx, holders.adoption, [await item(ctx, holders.adoption, "a001", "shared-key", SENTINEL)])
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "shared-key", SENTINEL, { compare: true })])
      strict(await approve(ctx, await view(ctx, holders.adoption), [decide("a001")]))
      const stored = items.getItem(ctx, "shared-key")!
      expect(await upload(ctx, adoption, [await item(ctx, adoption, "a002", "shared-key", OTHER, { compare: true })])).toEqual({ adoption, accepted: ["a002"], refused: [] })
      const v = await view(ctx, adoption)
      expect(matches(ctx, adoption)).toEqual({ a001: { holder: null, version: null, match: [null] }, a002: { holder: stored.id, version: 1, match: ["differs"] } })
      expect(v.items.map(i => [i.ref, i.compare?.holder.id ?? null, i.problem])).toEqual([["a001", null, "This name is no longer available."], ["a002", stored.id, null]])
      const before = { items: itemCount(ctx), version: items.getItem(ctx, "shared-key")!.version, key: storedFingerprint(ctx, stored.id) }
      for (const extra of [{ action: "store" }, { action: "map" }, { action: "replace" }, { action: "rename", slug: "shared-key-2" }] as const) expect((await refused(approve(ctx, v, [decide("a001", extra), decide("a002", { action: "map" })]))).refused).toEqual([{ ref: "a001", reason: "This name is no longer available." }])
      expect({ items: itemCount(ctx), version: items.getItem(ctx, "shared-key")!.version, key: storedFingerprint(ctx, stored.id) }).toEqual(before)
      expect(strict(await approve(ctx, v, [decide("a001", { include: false }), decide("a002", { action: "map" })]))).toMatchObject({ status: "approved", mapped: [{ ref: "a002", slug: "shared-key" }], refused: [{ ref: "a001", reason: "Left out at review." }] })
    })
  })

  it("is not bound to an unrelated item created under the name after its holder was left out", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const holders = await start(ctx)
      await upload(ctx, holders.adoption, [await item(ctx, holders.adoption, "a001", "shared-key", SENTINEL), await item(ctx, holders.adoption, "a002", "other-key", SENTINEL)])
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "shared-key", STORED, { compare: true })])
      strict(await approve(ctx, await view(ctx, holders.adoption), [decide("a001", { include: false }), decide("a002")]))
      await seedCredential(ctx, "shared-key")
      const v = await view(ctx, adoption)
      expect(matches(ctx, adoption)).toEqual({ a001: { holder: null, version: null, match: [null] } })
      expect([v.items[0]!.compare, v.items[0]!.problem]).toEqual([null, "This name is no longer available."])
      expect(ctx.sql.exec("SELECT 1 FROM audit WHERE action='adoption.compare' AND target='shared-key'").toArray()).toEqual([])
    })
  })

  it("is not bound to the item its holder became when the row's machine cannot read it", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const holders = await start(ctx)
      await upload(ctx, holders.adoption, [await item(ctx, holders.adoption, "a001", "shared-key", SENTINEL)])
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "shared-key", SENTINEL, { compare: true })])
      strict(await approve(ctx, await view(ctx, holders.adoption), [decide("a001")]))
      // The machine is narrowed to other tags; the reviewer still reads the item.
      ctx.sql.exec("UPDATE devices SET scope=json_set(scope,'$.tags',json('[\"elsewhere\"]')) WHERE id='dev_owner'")
      const v = await view(ctx, adoption)
      expect(matches(ctx, adoption)).toEqual({ a001: { holder: null, version: null, match: [null] } })
      expect([v.items[0]!.compare, v.items[0]!.problem]).toEqual([null, "This name is no longer available."])
      expect((await inventory(ctx)).rows.find(r => r.slug === "shared-key")!.stored).toMatchObject({ id: items.getItem(ctx, "shared-key")!.id })
    })
  })

  it("is bound to the item of the row that replaced its holder in the holder's batch", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const holders = await start(ctx)
      await upload(ctx, holders.adoption, [await item(ctx, holders.adoption, "a001", "shared-key", SENTINEL)])
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "shared-key", OTHER, { compare: true })])
      await upload(ctx, holders.adoption, [await item(ctx, holders.adoption, "a002", "shared-key", OTHER, { compare: true })], secondMachine(ctx))
      expect(strict(await approve(ctx, await view(ctx, holders.adoption), [decide("a001"), decide("a002", { action: "replace" })]))).toMatchObject({ mapped: [{ ref: "a001" }], created: [{ ref: "a002" }] })
      const stored = items.getItem(ctx, "shared-key")!
      expect(stored.id).toBe(ctx.sql.exec<{ item_id: string }>("SELECT item_id FROM adoption_items WHERE adoption=? AND ref='a002'", holders.adoption).one().item_id)
      await view(ctx, adoption)
      expect(matches(ctx, adoption)).toEqual({ a001: { holder: stored.id, version: 1, match: ["same"] } })
    })
  })
})

describe("a rename's name", () => {
  it("a rename to a taken name, a colleague's private one included, answers as an ordinary create does, and the same name budget runs out after the same misses", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      await seedCredential(ctx, "held-unlike")
      await seedCredential(ctx, "admin-private", { kind: "member", member: "mem_admin" })
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-unlike", SENTINEL, { compare: true })])
      const v = await view(ctx, adoption)
      const rename = (slug: string) => refused(approve(ctx, v, [decide("a001", { action: "rename", slug })]))
      const create = (slug: string) => refused(() => assertCredentialNameFree(ctx, memberPrincipal(ctx), slug))
      const misses = () => ctx.sql.exec<{ count: number }>("SELECT count FROM name_miss_buckets WHERE subject LIKE 'account:%'").toArray()[0]?.count ?? 0
      expect(await rename("admin-private")).toEqual(NAME_UNAVAILABLE)
      expect(await create("admin-private")).toEqual(NAME_UNAVAILABLE)
      expect(misses()).toBe(2)
      for (let n = 2; n < 20; n++) expect(await rename("admin-private")).toEqual(NAME_UNAVAILABLE)
      expect(misses()).toBe(20)
      const limited = await rename("free-name")
      expect(limited).toEqual({ error: "rate_limited", message: "Too many unavailable names; try again later.", retryAfter: expect.any(Number) })
      expect(await create("free-name")).toEqual(limited)
      expect(await rename("admin-private")).toEqual(limited)
      expect([misses(), items.getItem(ctx, "free-name"), ctx.sql.exec("SELECT status FROM adoption_batches WHERE id=?", adoption).one()]).toEqual([20, null, { status: "open" }])
    })
  })
})

// The projects area's own state, so a repoint binds real variables.
async function repointFixture() {
  const f = await projectFixture()
  await inAccess(f.tenant, () => registerCredentialServices())
  return f
}
// Binds a project variable to an item, as a repoint finds it on the holder.
const bindVar = (ctx: import("../src/vault/core.ts").VaultContext, project: string, env: string, name: string, slug: string) => ctx.sql.exec("INSERT INTO vars(project,env,name,item,field,updated_by,updated_at) VALUES (?,?,?,?,'key','member:mem_owner',?) ON CONFLICT(project,env,name) DO UPDATE SET item=excluded.item,field=excluded.field", project, env, name, slug, ctx.now())
const varOf = (ctx: import("../src/vault/core.ts").VaultContext, project: string, env: string, name: string) => ctx.sql.exec<{ item: string | null; field: string | null; updated_by: string }>("SELECT item,field,updated_by FROM vars WHERE project=? AND env=? AND name=?", project, env, name).toArray()[0] ?? null

describe("a rename's repoint", () => {
  it("as the review page builds it from the affected references, ticked in any order, binds them and a retry answers what was stored", async () => {
    const f = await repointFixture()
    await inAccess(f.tenant, async ctx => {
      await seedCredential(ctx, "held-unlike")
      bindVar(ctx, "prj_a", "dev", "TOKEN", "held-unlike")
      bindVar(ctx, "prj_b", "dev", "OPENAI_API_KEY", "held-unlike")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-unlike", SENTINEL, { compare: true })])
      const v = await view(ctx, adoption)
      const references = v.items[0]!.compare!.affected!.references
      expect(references.length).toBe(2)
      const built = adoptionDecisions(adoption, v.items, new Map([["a001", { include: true, home: "workspace", action: "rename" as const, slug: "held-unlike-office", repoint: [...references].reverse() }]]))
      if (!built.ok) throw new Error(built.error.message)
      const done = strict(await approve(ctx, v, built.decisions))
      expect(done).toMatchObject({ status: "approved", created: [{ ref: "a001", slug: "held-unlike-office" }] })
      expect([varOf(ctx, "prj_a", "dev", "TOKEN")?.item, varOf(ctx, "prj_b", "dev", "OPENAI_API_KEY")?.item]).toEqual(["held-unlike-office", "held-unlike-office"])
      expect(strict(await approve(ctx, v, built.decisions))).toEqual(done)
    })
  })

  it("binds each variable to the renamed item in the approval, audited as a variable set, and tells no machine", async () => {
    const f = await repointFixture()
    await inAccess(f.tenant, async ctx => {
      await seedCredential(ctx, "held-unlike")
      bindVar(ctx, "prj_a", "dev", "TOKEN", "held-unlike")
      bindVar(ctx, "prj_b", "dev", "OPENAI_API_KEY", "held-unlike")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-unlike", SENTINEL, { compare: true })])
      const v = await view(ctx, adoption)
      const was = varOf(ctx, "prj_a", "dev", "TOKEN")!
      const repoint = [{ project: "prj_a", env: "dev", variable: "TOKEN" }, { project: "project-b", env: "dev", variable: "OPENAI_API_KEY" }]
      const done = strict(await approve(ctx, v, [decide("a001", { action: "rename", slug: "held-unlike-office", repoint })]))
      expect(JSON.stringify(done)).not.toMatch(/TOKEN|OPENAI_API_KEY|repoint/)
      expect(strict(await status(ctx, adoption))).toEqual(done)
      expect([varOf(ctx, "prj_a", "dev", "TOKEN"), varOf(ctx, "prj_b", "dev", "OPENAI_API_KEY")]).toEqual([{ item: "held-unlike-office", field: "key", updated_by: "member:mem_owner" }, { item: "held-unlike-office", field: "key", updated_by: "member:mem_owner" }])
      expect(was.item).toBe("held-unlike")
      expect(ctx.sql.exec<{ target: string; detail: string }>("SELECT target,detail FROM audit WHERE action='project.var.set' ORDER BY seq").toArray().map(a => [a.target, JSON.parse(a.detail).name, JSON.parse(a.detail).item])).toEqual([["prj_a", "TOKEN", "held-unlike-office"], ["prj_b", "OPENAI_API_KEY", "held-unlike-office"]])
    })
  })

  it("is refused ADOPTION_CHANGED, with nothing written, once a variable it moves is no longer on the holder", async () => {
    const f = await repointFixture()
    await inAccess(f.tenant, async ctx => {
      await seedCredential(ctx, "held-unlike")
      await seedCredential(ctx, "set-meanwhile")
      bindVar(ctx, "prj_a", "dev", "TOKEN", "held-unlike")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-unlike", SENTINEL, { compare: true })])
      const v = await view(ctx, adoption)
      bindVar(ctx, "prj_a", "dev", "TOKEN", "set-meanwhile")
      const before = { items: itemCount(ctx), vars: ctx.sql.exec("SELECT * FROM vars ORDER BY project,env,name").toArray() }
      expect(await refused(approve(ctx, v, [decide("a001", { action: "rename", slug: "held-unlike-office", repoint: [{ project: "prj_a", env: "dev", variable: "TOKEN" }] })]))).toEqual({ error: "conflict", message: ADOPTION_CHANGED })
      expect({ items: itemCount(ctx), vars: ctx.sql.exec("SELECT * FROM vars ORDER BY project,env,name").toArray() }).toEqual(before)
      expect(ctx.sql.exec("SELECT status FROM adoption_batches WHERE id=?", adoption).one()).toEqual({ status: "open" })
    })
  })

  it("is refused ADOPTION_CHANGED, with nothing written, when two rows of one approval move the same variable", async () => {
    const f = await repointFixture()
    await inAccess(f.tenant, async ctx => {
      const held = await seedCredential(ctx, "held-unlike")
      await seedCredential(ctx, "held-elsewhere")
      bindVar(ctx, "prj_a", "dev", "TOKEN", "held-unlike")
      const { adoption } = await start(ctx)
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-unlike", SENTINEL, { compare: true }), await item(ctx, adoption, "a002", "held-elsewhere", OTHER, { compare: true })])
      // Two rows sharing one holder, which the limits are there to prevent.
      ctx.sql.exec("UPDATE adoption_items SET holder=?,holder_version=? WHERE adoption=? AND ref='a002'", held.id, held.version, adoption)
      const v = await view(ctx, adoption)
      const before = { items: itemCount(ctx), vars: ctx.sql.exec("SELECT * FROM vars ORDER BY project,env,name").toArray() }
      const decisions = [decide("a001", { action: "rename", slug: "held-unlike-one", repoint: [{ project: "prj_a", env: "dev", variable: "TOKEN" }] }), decide("a002", { action: "rename", slug: "held-unlike-two", repoint: [{ project: "project-a", env: "dev", variable: "TOKEN" }] })]
      expect(await refused(approve(ctx, v, decisions))).toEqual({ error: "conflict", message: ADOPTION_CHANGED })
      expect({ items: itemCount(ctx), vars: ctx.sql.exec("SELECT * FROM vars ORDER BY project,env,name").toArray() }).toEqual(before)
      expect(ctx.sql.exec("SELECT status FROM adoption_batches WHERE id=?", adoption).one()).toEqual({ status: "open" })
    })
  })

  it("is refused, with nothing written, without var.set's rights on the variable, or in a protected environment without editProtected", async () => {
    const f = await repointFixture()
    await inAccess(f.tenant, async ctx => {
      await seedCredential(ctx, "held-unlike")
      bindVar(ctx, "prj_a", "dev", "NEW_KEY", "held-unlike")
      allowPrivate(ctx, "dev_member")
      const { adoption } = await start(ctx, "dev_member")
      await upload(ctx, adoption, [await item(ctx, adoption, "a001", "held-unlike", SENTINEL, { compare: true, home: { kind: "member", member: "mem_member" } })], "dev_member")
      const v = await view(ctx, adoption, "member")
      const inA = { kind: "project" as const, project: "prj_a" }
      const rename = (repoint: { project: string; env: string; variable: string }[]) => approve(ctx, v, [{ ref: "a001", include: true, home: inA, action: "rename", slug: "held-unlike-member", repoint }], "member")
      const before = { items: itemCount(ctx), vars: ctx.sql.exec("SELECT * FROM vars ORDER BY project,env,name").toArray(), audit: ctx.sql.exec<{ n: number }>("SELECT count(*) AS n FROM audit WHERE action='project.var.set'").one().n }
      expect((await refused(rename([{ project: "prj_a", env: "dev", variable: "NEW_KEY" }, { project: "prj_b", env: "dev", variable: "NEW_KEY" }]))).refused).toEqual([{ ref: "a001", reason: "You cannot point one of these variables at the new credential." }])
      expect((await refused(rename([{ project: "prj_a", env: "prod", variable: "NEW_KEY" }]))).refused).toEqual([{ ref: "a001", reason: "One of these variables is in a protected environment; only someone who may change protected environments there can point it at the new credential." }])
      expect((await refused(rename([{ project: "prj_nowhere", env: "dev", variable: "NEW_KEY" }]))).refused).toEqual([{ ref: "a001", reason: "You cannot point one of these variables at the new credential." }])
      expect({ items: itemCount(ctx), vars: ctx.sql.exec("SELECT * FROM vars ORDER BY project,env,name").toArray(), audit: ctx.sql.exec<{ n: number }>("SELECT count(*) AS n FROM audit WHERE action='project.var.set'").one().n }).toEqual(before)
      // With the rights in an unprotected environment of a project it edits, it binds.
      expect(strict(await rename([{ project: "prj_a", env: "dev", variable: "NEW_KEY" }]))).toMatchObject({ created: [{ ref: "a001", slug: "held-unlike-member" }] })
      expect(varOf(ctx, "prj_a", "dev", "NEW_KEY")).toEqual({ item: "held-unlike-member", field: "key", updated_by: "member:mem_member" })
    })
  })
})

describe("a machine's plan index and the inventory", () => {
  it("an index replaces the machine's last one, answers value-free, refuses a secret-looking string or a workload, and is dropped once kept 30 days", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const first = await sendIndex(ctx, [planItem("a001", "openai-key"), planItem("a002", "stripe-key", { include: false })])
      const uploaded = ctx.sql.exec<{ uploaded_at: number }>("SELECT uploaded_at FROM adoption_indexes").one().uploaded_at
      expect(first).toEqual({ machine: "office", items: 2, expiresAt: new Date(uploaded + ADOPTION_LIMITS.indexKeptMs).toISOString() })
      await sendIndex(ctx, [planItem("a001", "openai-key")])
      const kept = () => ctx.sql.exec<{ device: string; member: string | null; items: string }>("SELECT device,member,items FROM adoption_indexes").toArray().map(r => ({ ...r, items: (JSON.parse(r.items) as { slug: string }[]).map(i => i.slug) }))
      expect(kept()).toEqual([{ device: "dev_owner", member: "mem_owner", items: ["openai-key"] }])
      const leaky = planItem("a003", "leaky", { sources: [{ path: `/home/alex/${SENTINEL}/.env`, stale: [] }] })
      expect(await refused(sendIndex(ctx, [planItem("a001", "openai-key"), leaky]))).toMatchObject({ error: "bad_request", message: expect.stringContaining("A string in a003 looks like a secret") })
      expect(JSON.stringify(await refused(sendIndex(ctx, [leaky])))).not.toContain(SENTINEL)
      expect(kept()).toEqual([{ device: "dev_owner", member: "mem_owner", items: ["openai-key"] }])
      expect(await refused(call(ctx, "adoption.index", { machine: "office", items: [] }, await deviceInvocation(ctx, "dev_owner"), { kind: "device", deviceId: "dev_owner", workload: "wl_ci" }))).toMatchObject({ error: "forbidden" })
      ctx.sql.exec("UPDATE adoption_indexes SET expires_at=?", ctx.now())
      await adoptionsArea.alarm!(ctx, "index:dev_owner")
      expect(kept()).toEqual([])
    })
  })

  it("an index refuses a secret-looking slug, and a managed workspace takes no index, as it takes no adoption", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const randomSlug = "x9f3k2m8q7w4z1v6b5n0p3r7t2y8"
      const leaky = await refused(sendIndex(ctx, [planItem("a001", randomSlug)]))
      expect(leaky).toEqual({ error: "bad_request", message: "A string in a001 looks like a secret (it contains a long random-looking string), so the index was not kept." })
      setSetting(ctx, "managed", { platform: "plt_x", subject: "s", member: "mem_owner" })
      expect(await refused(sendIndex(ctx, [planItem("a001", "openai-key")]))).toEqual({ error: "forbidden", message: "A managed workspace does not take adoptions; its platform adds credentials." })
      expect(ctx.sql.exec("SELECT * FROM adoption_indexes").toArray()).toEqual([])
    })
  })

  it("the inventory lists every name from open batches, approved batches and the member's own indexes, with a result only where the view shows one", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const held = await seedCredential(ctx, "held-alike")
      const done = await start(ctx)
      await upload(ctx, done.adoption, [await item(ctx, done.adoption, "a001", "stored-earlier", SENTINEL)])
      await approve(ctx, await view(ctx, done.adoption), [decide("a001")])
      const open = await start(ctx)
      await upload(ctx, open.adoption, [await item(ctx, open.adoption, "a001", "held-alike", STORED, { compare: true }), await item(ctx, open.adoption, "a002", "staged-now", SENTINEL, { sources: [{ path: "/srv/app/.env", variable: "KEY", stale: [], mtime: "2026-11-02T09:00:00.000Z" }] })])
      await sendIndex(ctx, [planItem("a001", "held-alike", { exists: true }), planItem("a009", "left-unticked", { include: false })])
      allowPrivate(ctx, "dev_member")
      await sendIndex(ctx, [planItem("a001", "members-plan", { home: "private" })], "dev_member", "members-laptop")
      const inv = await inventory(ctx)
      expect(inv.rows.map(r => r.slug)).toEqual(["held-alike", "left-unticked", "staged-now", "stored-earlier"])
      const [alike, unticked, staged, earlier] = inv.rows
      expect(alike).toEqual({ slug: "held-alike", stored: { id: held.id, kind: "api-key", home: ws, version: 1 }, entries: [
        { from: "staged", machine: "office", adoption: open.adoption, ref: "a001", kind: "api-key", home: ws, sources: [{ machine: "office", path: "/home/alex/app/.env", variable: "OPENAI_API_KEY", pointer: null, stale: [] }], compare: "same" },
        { from: "plan", machine: "office", ref: "a001", kind: "api-key", home: "workspace", project: null, include: true, exists: true, storeOnly: false, sources: [{ machine: "office", path: "/home/alex/app/.env", variable: "OPENAI_API_KEY", pointer: null, stale: [], mtime: "2026-11-01T10:00:00.000Z" }], uses: [{ project: "prj_a", env: "dev", variable: "OPENAI_API_KEY", field: "key" }] },
      ] })
      expect(unticked!.entries).toMatchObject([{ from: "plan", include: false }])
      expect(staged!.entries).toMatchObject([{ from: "staged", compare: null, sources: [{ mtime: "2026-11-02T09:00:00.000Z" }] }])
      expect(earlier).toMatchObject({ stored: { kind: "api-key" }, entries: [{ from: "approved", adoption: done.adoption, ref: "a001", outcome: "created" }] })
      expect(inv.indexes).toEqual([{ device: "dev_owner", machine: "office", indexedAt: expect.any(String), expiresAt: expect.any(String) }])
      expect(JSON.stringify(inv)).not.toMatch(new RegExp(`${SENTINEL}|${STORED}|members-plan|fingerprint`))
      expect((await inventory(ctx, "member")).rows.map(r => r.slug)).toEqual(["members-plan"])
    })
  })

  it("a low-entropy compare shows no result in the inventory to a member who cannot rotate the holder", async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      await seedGeneric(ctx, "shared-pin", "4711")
      allowPrivate(ctx, "dev_member")
      const { adoption } = await start(ctx, "dev_member")
      await upload(ctx, adoption, [await genericItem(ctx, adoption, "a001", "shared-pin", "4711", { compare: true, home: { kind: "member", member: "mem_member" } })], "dev_member")
      expect((await inventory(ctx, "member")).rows).toMatchObject([{ slug: "shared-pin", entries: [{ from: "staged", compare: "unknown" }] }])
    })
  })
})

describe("keep open", () => {
  it(`extends an open batch by ${ADOPTION_LIMITS.keepOpenMs / 86_400_000} days once per expiry shown, and stops ${ADOPTION_LIMITS.maxLifeMs / 86_400_000} days after it was started`, async () => {
    const f = await credentialsFixture()
    await inAccess(f.tenant, async ctx => {
      const { adoption } = await start(ctx)
      const created = ctx.sql.exec<{ created_at: number; expires_at: number }>("SELECT created_at,expires_at FROM adoption_batches WHERE id=?", adoption).one()
      const keep = (expiresAt: string, role = "owner") => call<{ adoption: string; expiresAt: string; maxExpiresAt: string }>(ctx, "adoption.keepOpen", { adoption, expiresAt }, memberInvocation(ctx, role))
      const shown = (await view(ctx, adoption)).expiresAt
      const iso = (ms: number) => new Date(ms).toISOString()
      const longest = iso(created.created_at + ADOPTION_LIMITS.maxLifeMs)
      expect(await keep(shown)).toEqual({ adoption, expiresAt: iso(created.expires_at + ADOPTION_LIMITS.keepOpenMs), maxExpiresAt: longest })
      // The same click again names the old expiry and extends nothing.
      expect(await refused(keep(shown))).toEqual({ error: "conflict", message: "This batch's expiry has changed; reload it." })
      expect(await keep(iso(created.expires_at + ADOPTION_LIMITS.keepOpenMs))).toMatchObject({ expiresAt: longest })
      expect(await refused(keep(longest))).toEqual({ error: "conflict", message: "This batch is already kept open as long as it can be." })
      expect((await view(ctx, adoption)).expiresAt).toBe(longest)
      expect(ctx.sql.exec("SELECT due_at FROM schedule WHERE area='adoptions' AND key=?", adoption).one()).toEqual({ due_at: created.created_at + ADOPTION_LIMITS.maxLifeMs })
      expect(await refused(keep(longest, "member"))).toMatchObject({ error: "not_found" })
      expect(strict(await status(ctx, adoption)).expiresAt).toBe(longest)
    })
  })
})
