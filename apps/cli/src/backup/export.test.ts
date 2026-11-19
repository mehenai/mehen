import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { lstat, mkdir, readFile, readdir } from "node:fs/promises"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { type BackupRecipientView, type BackupStatus, BackupBundleSchema, BackupSidecarSchema, backupCiphertextBase64, backupPlaintext } from "@mehen/protocol/backup"
import { fromUtf8, utf8 } from "@mehen/protocol/bytes"
import { ageDecrypt, ageEncrypt } from "./age.ts"
import { statusLines } from "./export.ts"
import { type BackupFixture, SECRET_VALUE, backupFixture, exportMeta, sampleBundle } from "../testing/backup-fixtures.ts"
import { MockVault, vaultError } from "../testing/mock-vault.ts"
import { runJv } from "../testing/run-mehen.ts"

let vault: MockVault
let f: BackupFixture
let env: Record<string, string>
beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  f = await backupFixture()
  env = { ...f.env, MEHEN_CONFIG_DIR: f.home, MEHEN_VAULT_URL: vault.url }
  await vault.enrolSoftware(f.home)
  vault.overrides.clear()
  vault.seen.length = 0
})
afterEach(() => f.remove())

function recipient(over: Partial<BackupRecipientView> = {}): BackupRecipientView {
  return { id: "bkr_key00001", recipient: f.recipient, fingerprint: "age1fp...", label: "1Password and paper", status: "active", registrant: { member: "mem_alex", name: "Alex" }, mine: true, registeredAt: "2026-10-01T09:00:00.000Z", activeAt: "2026-10-02T09:00:00.000Z", lastExport: null, changedSince: 3, rights: { export: true, remove: true }, ...over }
}

function serveStatus(recipients: BackupRecipientView[]): void {
  const status: BackupStatus = { recipients, rights: { add: true }, now: "2026-11-01T10:00:00.000Z" }
  vault.overrides.set("GET /v1/backup/status", () => Response.json(status))
  vault.overrides.set("GET /v1/backup/recipients", () => Response.json({ recipients }))
}

// The vault's answer to POST /v1/backup/exports: the sample bundle
// encrypted to the fixture's key, as the DO encrypts it; `tamper` changes
// the bytes after the meta is taken.
function serveExport(tamper?: (bytes: Uint8Array) => void): void {
  vault.overrides.set("POST /v1/backup/exports", async () => {
    const ciphertext = new Uint8Array(await ageEncrypt(utf8(backupPlaintext(sampleBundle(f.recipient))), [f.recipient]))
    const meta = await exportMeta(sampleBundle(f.recipient), ciphertext)
    tamper?.(ciphertext)
    return Response.json({ export: meta, ciphertext: backupCiphertextBase64(ciphertext) })
  })
}

const exportCalls = () => vault.seen.filter((s) => s.path === "/v1/backup/exports")

describe("mehen backup export", () => {
  test("asks for an export to each key it may export to, checks it and writes the .age and a sidecar with no slug or value, 0600", async () => {
    serveStatus([recipient(), recipient({ id: "bkr_someone1", mine: false, rights: { export: false, remove: false } })])
    serveExport()
    const result = await runJv(["backup", "export", "--to", f.out, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(exportCalls().map((s) => JSON.parse(s.body))).toEqual([{ recipient: "bkr_key00001" }])
    const archive = join(f.out, "mehen-acme-2026-11-01-bkx_test0001.age")
    const sidecarPath = join(f.out, "mehen-acme-2026-11-01-bkx_test0001.json")
    expect((await readdir(f.out)).sort()).toEqual(["mehen-acme-2026-11-01-bkx_test0001.age", "mehen-acme-2026-11-01-bkx_test0001.json"])
    for (const path of [archive, sidecarPath]) expect((await lstat(path)).mode & 0o777).toBe(0o600)
    const sidecarText = await readFile(sidecarPath, "utf8")
    expect(BackupSidecarSchema.parse(JSON.parse(sidecarText))).toMatchObject({ id: "bkx_test0001", items: 3, projects: 1, excluded: 2 })
    for (const needle of [SECRET_VALUE, "openai-dev", "billing-api", "gmail-alex"]) expect(sidecarText + result.stdout).not.toContain(needle)
    const opened = BackupBundleSchema.parse(JSON.parse(fromUtf8(new Uint8Array(await ageDecrypt(new Uint8Array(await readFile(archive)), [f.identity])))))
    expect(opened.items.map((i) => i.slug)).toEqual(["openai-dev", "db-main", "gmail-alex"])
    expect(JSON.parse(result.stdout)).toMatchObject({ exports: [{ id: "bkx_test0001", archive, sidecar: sidecarPath }] })
    const again = await runJv(["backup", "export", "--to", f.out], env)
    expect(again.code).toBe(EXIT.error)
    expect(again.stderr).toContain("something is already there")
  })

  test("a file whose SHA-256 is not what the vault reported is refused and nothing is written", async () => {
    serveStatus([recipient()])
    serveExport((bytes) => {
      bytes[bytes.length - 3] = (bytes[bytes.length - 3] as number) ^ 1
    })
    const result = await runJv(["backup", "export", "--to", f.out], env)
    expect(result.code).toBe(EXIT.error)
    expect(result.stderr).toContain("its SHA-256 differs from the one the vault reported")
    expect(await readdir(f.out)).toEqual([])
  })

  test("with no key it may export to, says when its own key starts working, or how to add one", async () => {
    serveStatus([recipient({ status: "pending", activeAt: "2026-11-02T09:00:00.000Z", rights: { export: false, remove: true } })])
    const waiting = await runJv(["backup", "export", "--to", f.out], env)
    expect(waiting.code).toBe(EXIT.error)
    expect(waiting.stderr).toContain("can receive exports from 2026-11-02T09:00:00.000Z")
    serveStatus([recipient({ mine: false, rights: { export: false, remove: false } })])
    const none = await runJv(["backup", "export", "--to", f.out], env)
    expect(none.stderr).toContain("only an owner exports, to a key they added themselves")
    expect(exportCalls().length).toBe(0)
  })

  test("--recipient names a registered key by id and never takes a key; the vault's refusal comes through", async () => {
    const key = await runJv(["backup", "export", "--to", f.out, "--recipient", f.recipient], env)
    expect(key.code).toBe(EXIT.usage)
    expect(key.stderr).toContain("takes a backup key's id (bkr_...)")
    vault.overrides.set("POST /v1/backup/exports", () => vaultError("rate_limited", "One export per backup recipient every ten minutes.", { retryAfter: 120 }))
    const limited = await runJv(["backup", "export", "--to", f.out, "--recipient", "bkr_key00001"], env)
    expect(limited.code).toBe(EXIT.transient)
    expect(limited.stderr).toContain("One export per backup recipient every ten minutes.")
    expect(vault.seen.some((s) => s.path === "/v1/backup/status")).toBe(false)
  })

  test("refuses a directory inside a git work tree", async () => {
    await mkdir(join(f.repo, ".git"))
    serveStatus([recipient()])
    serveExport()
    const result = await runJv(["backup", "export", "--to", join(f.repo, "backups")], env)
    expect(result.code).toBe(EXIT.error)
    expect(result.stderr).toContain("inside the git work tree")
    expect(exportCalls().length).toBe(0)
  })
})

describe("mehen backup status", () => {
  test("lists each key and, for your own, the last export and what changed since", async () => {
    const ago = () => "2 days ago"
    const status: BackupStatus = { recipients: [recipient({ lastExport: { id: "bkx_x", at: "2026-10-30T10:00:00.000Z", items: 41 }, changedSince: 14 }), recipient({ id: "bkr_other001", label: "Sam's key", mine: false, registrant: { member: "mem_sam", name: "Sam" }, lastExport: null, changedSince: null })], rights: { add: true }, now: "2026-11-01T10:00:00.000Z" }
    expect(statusLines(status, ago)).toEqual([
      "bkr_key00001  1Password and paper  age1fp...  active  added by you",
      "  stale: 14 items changed since bkx_x (2 days ago); run mehen backup export --to <dir>",
      "bkr_other001  Sam's key  age1fp...  active  added by Sam",
    ])
    expect(statusLines({ ...status, recipients: [recipient({ lastExport: { id: "bkx_x", at: "2026-10-30T10:00:00.000Z", items: 41 }, changedSince: 0 })] }, ago)[1]).toBe("  up to date: bkx_x (2 days ago), 41 credentials")
    serveStatus(status.recipients)
    const cli = await runJv(["backup", "status"], env)
    expect(cli.code).toBe(EXIT.ok)
    expect(cli.stdout).toContain("stale: 14 items changed since bkx_x")
  })

  // Threat model, one terminal boundary: a co-owner's name or key label is
  // a field of its row, so a line break in it is spelled out, never a
  // forged next: line of its own.
  test("a line break in another owner's name or key label stays inside its row", async () => {
    serveStatus([recipient({ id: "bkr_other001", label: "Sam's key\rnext: trust-this", mine: false, registrant: { member: "mem_sam", name: "Sam\r\nnext: mehen backup restore bkx_x --to /tmp/x" }, lastExport: null, changedSince: null })])
    const cli = await runJv(["backup", "status"], env)
    expect(cli.code).toBe(EXIT.ok)
    expect(cli.stdout).toBe("bkr_other001  Sam's key\\u000Dnext: trust-this  age1fp...  active  added by Sam\\u000D\\u000Anext: mehen backup restore bkx_x --to /tmp/x\n")
  })
})

describe("mehen backup snapshot with no --recipient", () => {
  test("encrypts to the caller's own active backup keys, never one still in its day of cooling-off", async () => {
    const { recipient: pendingKey } = await (await import("./age.ts")).newAgeIdentity()
    serveStatus([recipient(), recipient({ id: "bkr_pending1", recipient: pendingKey, status: "pending", rights: { export: false, remove: true } })])
    const result = await runJv(["backup", "snapshot", "--plan", f.planPath, "--to", f.out, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect((JSON.parse(result.stdout) as { recipients: { recipient: string }[] }).recipients.map((r) => r.recipient)).toEqual([f.recipient])
  })

  test("uses only the caller's own active keys: another owner's active key is never used, and with none of its own it is refused", async () => {
    const { recipient: othersKey } = await (await import("./age.ts")).newAgeIdentity()
    const others = recipient({ id: "bkr_other001", recipient: othersKey, mine: false, registrant: { member: "mem_sam", name: "Sam" }, rights: { export: false, remove: false } })
    serveStatus([recipient(), others])
    const own = await runJv(["backup", "snapshot", "--plan", f.planPath, "--to", f.out, "--json"], env)
    expect(own.code).toBe(EXIT.ok)
    expect((JSON.parse(own.stdout) as { recipients: { recipient: string }[] }).recipients.map((r) => r.recipient)).toEqual([f.recipient])
    serveStatus([others])
    const member = await runJv(["backup", "snapshot", "--plan", f.planPath, "--to", join(f.root, "member-out")], env)
    expect(member.code).toBe(EXIT.usage)
    expect(member.stderr).toContain("Name the backup recipient with --recipient age1...")
    expect(await lstat(join(f.root, "member-out")).catch(() => null)).toBeNull()
  })

  test("with no key named, none registered and no vault to ask, says how to name one", async () => {
    const result = await runJv(["backup", "snapshot", "--plan", f.planPath, "--to", f.out], f.env)
    expect(result.code).toBe(EXIT.usage)
    expect(result.stderr).toContain("Name the backup recipient with --recipient age1...")
    expect(result.stderr).toContain("the vault could not be asked for one")
  })
})
