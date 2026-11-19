import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { chmod, lstat, mkdir, readFile, readdir, rm, symlink, truncate, utimes, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { SNAPSHOT_FORMAT, SnapshotSchema, sha256Hex } from "@mehen/protocol/backup"
import { ageDecrypt } from "./age.ts"
import { checkSnapshot } from "./check.ts"
import { writeNewFile } from "./files.ts"
import { restoreSnapshot } from "./restore.ts"
import { backupRecipients, takeSnapshot } from "./snapshot.ts"
import { backupStatePath, readSnapshotRecords } from "./state.ts"
import { type BackupFixture, DB_PASSWORD, SECRET_VALUE, backupFixture, planFor, writePlan } from "../testing/backup-fixtures.ts"
import { CliError } from "../errors.ts"

let f: BackupFixture
beforeEach(async () => {
  f = await backupFixture()
})
afterEach(() => f.remove())

const snapshot = (overrides: Partial<Parameters<typeof takeSnapshot>[0]> = {}) => takeSnapshot({ planPath: f.planPath, to: f.out, recipients: [f.recipient], env: f.env, ...overrides })

async function failure(promise: Promise<unknown>): Promise<CliError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof CliError) return error
    throw error
  }
  throw new Error("expected a refusal")
}

async function outputs(): Promise<string[]> {
  return (await readdir(f.out).catch(() => [])).sort()
}

describe("mehen backup snapshot", () => {
  test("the archive opens with the backup identity to every file the plan names, byte for byte with mode, owner and mtime", async () => {
    await utimes(f.secretsFile, new Date(1_700_000_000_000), new Date(1_700_000_123_456))
    const result = await snapshot({ now: () => new Date("2026-11-01T09:30:00.000Z") })
    expect(result.paths).toEqual([f.manifest, f.envFile, f.secretsFile, f.serviceEnv, f.unit, f.planPath].sort())
    expect(result.selfCheck).toBe("passed")
    expect(await outputs()).toEqual([`${result.id}.age`, `${result.id}.json`])
    for (const path of [result.archive, result.sidecar]) expect((await lstat(path)).mode & 0o777).toBe(0o600)

    const opened = SnapshotSchema.parse(JSON.parse(new TextDecoder().decode(await ageDecrypt(new Uint8Array(await readFile(result.archive)), [f.identity]))))
    expect(opened).toMatchObject({ format: SNAPSHOT_FORMAT, id: result.id, machine: "testbox", createdAt: "2026-11-01T09:30:00.000Z", planDigest: await sha256Hex(new Uint8Array(await readFile(f.planPath))) })
    expect(opened.files.map((file) => file.path)).toEqual(result.paths)
    for (const file of opened.files) {
      const bytes = new Uint8Array(await readFile(file.path))
      const info = await lstat(file.path)
      expect(new Uint8Array(Buffer.from(file.content, "base64"))).toEqual(bytes)
      expect(file).toMatchObject({ mode: info.mode & 0o7777, uid: info.uid, gid: info.gid, mtimeMs: info.mtimeMs, size: bytes.length, sha256: await sha256Hex(bytes) })
    }
    expect(opened.files.find((file) => file.path === f.secretsFile)).toMatchObject({ mode: 0o640, mtimeMs: 1_700_000_123_456 })
  })

  test("records the passed snapshot under MEHEN_HOME with ids, paths and digests only", async () => {
    const result = await snapshot()
    const records = await readSnapshotRecords(f.env)
    expect(records).toEqual([{ id: result.id, archive: result.archive, planPath: f.planPath, planDigest: expect.stringMatching(/^[0-9a-f]{64}$/), paths: result.paths.filter((p) => p !== f.planPath), createdAt: result.createdAt, selfCheck: "passed", ciphertext: result.ciphertext }])
    expect((await lstat(backupStatePath(f.env))).mode & 0o777).toBe(0o600)
  })

  test("the sidecar, the state and the result hold no value, no substring of one, no length and no content hash", async () => {
    const result = await snapshot()
    const opened = SnapshotSchema.parse(JSON.parse(new TextDecoder().decode(await ageDecrypt(new Uint8Array(await readFile(result.archive)), [f.identity]))))
    const sidecarText = await readFile(result.sidecar, "utf8")
    const stateText = await readFile(backupStatePath(f.env), "utf8")
    const resultText = JSON.stringify(result)
    // The plan holds no value, and its digest is in the sidecar by design.
    const sources = opened.files.filter((file) => file.path !== f.planPath)
    const needles = [SECRET_VALUE, DB_PASSWORD, ...sources.flatMap((file) => [file.sha256, file.content])]
    for (const value of [SECRET_VALUE, DB_PASSWORD]) for (let i = 0; i + 6 <= value.length; i++) needles.push(value.slice(i, i + 6))
    for (const text of [sidecarText, stateText, resultText]) for (const needle of needles) expect(text.includes(needle), needle).toBe(false)
    expect(Object.keys(JSON.parse(sidecarText)).sort()).toEqual(["ciphertext", "createdAt", "files", "format", "id", "machine", "paths", "planDigest", "recipients", "selfCheck"])
    expect(sidecarText).not.toMatch(/"(size|sizes|bytes?Of|length|sha256s|hashes|content)"\s*:/)
  })

  test("a source that is a symbolic link is refused and nothing is written", async () => {
    const target = join(f.root, "elsewhere.env")
    await writeFile(target, "A=1\n", { mode: 0o600 })
    await symlink(target, join(f.repo, ".env.link"))
    await writePlan(f.planPath, { ...planFor(f), sources: { s1: { path: join(f.repo, ".env.link") } } })
    const error = await failure(snapshot())
    expect(error.code).toBe("failed")
    expect(error.message).toContain("symbolic link")
    expect(await outputs()).toEqual([])
  })

  test.skipIf(process.getuid?.() === 0)("another user's file is refused", async () => {
    await writePlan(f.planPath, { ...planFor(f), sources: { s1: { path: "/etc/hosts" } } })
    const error = await failure(snapshot())
    expect(error.message).toContain("owned by another user")
    expect(await outputs()).toEqual([])
  })

  test("a file over 1 MiB, a missing source and a relative path are refused", async () => {
    await truncate(f.secretsFile, 1_048_577)
    expect((await failure(snapshot())).message).toContain("larger than 1048576 bytes")
    await writePlan(f.planPath, { ...planFor(f), sources: { s1: { path: join(f.repo, "gone.env") } } })
    expect((await failure(snapshot())).message).toContain("nothing is there")
    await writePlan(f.planPath, { ...planFor(f), sources: { s1: { path: "code/.env" } } })
    expect((await failure(snapshot())).message).toContain("not an absolute path")
    expect(await outputs()).toEqual([])
  })

  // Seen on a real machine: a 1.1 MB plan was refused with the 1 MiB cap of
  // one source, and told to take the plan out of the plan.
  test("a 1.5 MB plan is snapshotted, checked and restored; a 1.5 MB source is still refused, and a plan over 16 MiB says to scan less", async () => {
    await writePlan(f.planPath, { ...planFor(f), padding: "x".repeat(1_500_000) })
    const result = await snapshot()
    expect(result.paths).toContain(f.planPath)
    expect(await checkSnapshot(result.archive)).toMatchObject({ id: result.id, files: result.files })
    const staging = join(f.root, "staging")
    expect((await restoreSnapshot({ archivePath: result.archive, identities: [f.identity], mode: { kind: "to", dir: staging }, env: f.env })).written).toBe(result.files)
    expect(await readFile(join(staging, f.planPath))).toEqual(await readFile(f.planPath))

    await truncate(f.secretsFile, 1_500_000)
    const source = await failure(snapshot())
    expect(source.message).toBe(`Refusing ${f.secretsFile}: it is larger than 1048576 bytes.`)

    await writePlan(f.planPath, planFor(f))
    await truncate(f.planPath, 16 * 1_048_576 + 1)
    const plan = await failure(snapshot())
    expect(plan.message).toBe(`Refusing ${f.planPath}: it is larger than 16777216 bytes.`)
    expect(plan.next?.say).toBe("Scan fewer folders with `mehen adopt scan --root <folder>` and plan again; mehen reads a plan up to 16777216 bytes.")
  })

  test("a repo root that is not absolute is refused, so the snapshot and the guard never resolve it against different directories", async () => {
    await writePlan(f.planPath, { ...planFor(f), repos: [{ root: "code/billing-api" }] })
    const error = await failure(snapshot())
    expect(error.message).toBe(`The plan ${f.planPath} names "code/billing-api", which is not an absolute path.`)
    expect(await outputs()).toEqual([])
  })

  test("--to inside a repo the plan adopts, or inside any git work tree, is refused", async () => {
    expect((await failure(snapshot({ to: join(f.repo, "backups") }))).message).toContain("a repo the plan adopts")
    const other = join(f.root, "code", "other")
    await mkdir(join(other, ".git"), { recursive: true })
    expect((await failure(snapshot({ to: join(other, "deep", "backups") }))).message).toContain(`inside the git work tree ${other}`)
  })

  test("an output is never written over: an existing file or a planted link refuses", async () => {
    const existing = join(f.root, "existing.age")
    await writeFile(existing, "keep me")
    expect((await failure(writeNewFile(existing, new Uint8Array([1])))).message).toContain("already there")
    expect(await readFile(existing, "utf8")).toBe("keep me")
    const link = join(f.root, "planted.age")
    await symlink(join(f.root, "victim"), link)
    await failure(writeNewFile(link, new Uint8Array([1])))
    expect(await lstat(join(f.root, "victim")).catch(() => null)).toBeNull()
  })

  test("a source changed after it was read fails the self-check and deletes what was written", async () => {
    const error = await failure(snapshot({ beforeSelfCheck: () => writeFile(f.envFile, "OPENAI_API_KEY=rotated-in-between\n") }))
    expect(error.message).toBe(`The self-check failed: ${f.envFile} changed while the snapshot was taken, so nothing was kept.`)
    expect(await outputs()).toEqual([])
    expect(await readSnapshotRecords(f.env)).toEqual([])
  })

  test("a mode changed after it was read fails the self-check too", async () => {
    const error = await failure(snapshot({ beforeSelfCheck: () => chmod(f.secretsFile, 0o600) }))
    expect(error.message).toContain(f.secretsFile)
    expect(await outputs()).toEqual([])
  })

  test("recipients come from --recipient, else MEHEN_BACKUP_RECIPIENTS; anything but X25519 is refused", () => {
    expect(backupRecipients([f.recipient, f.recipient], {})).toEqual([f.recipient])
    expect(backupRecipients([], { MEHEN_BACKUP_RECIPIENTS: ` ${f.recipient} ,` })).toEqual([f.recipient])
    expect(() => backupRecipients([], {})).toThrow("--recipient")
    expect(() => backupRecipients([`age1pq1${"q".repeat(80)}`], {})).toThrow("post-quantum")
    expect(() => backupRecipients(["ssh-ed25519 AAAA"], {})).toThrow("SSH")
  })
})

describe("mehen backup check", () => {
  test("a fresh archive matches its sidecar: length, hash and one X25519 stanza per recipient plus the self-check's", async () => {
    const result = await snapshot()
    expect(await checkSnapshot(result.archive)).toMatchObject({ id: result.id, machine: "testbox", files: result.files, stanzas: 2, ciphertext: result.ciphertext })
  })

  test("detects truncation, a flipped byte, a wrong stanza count and a missing sidecar", async () => {
    const result = await snapshot()
    const good = new Uint8Array(await readFile(result.archive))
    const sidecar = JSON.parse(await readFile(result.sidecar, "utf8")) as { recipients: unknown[]; ciphertext: { bytes: number; sha256: string } }

    await writeFile(result.archive, good.subarray(0, good.length - 10))
    expect((await failure(checkSnapshot(result.archive))).message).toContain(`is ${good.length - 10} bytes, not ${good.length}`)

    const flipped = new Uint8Array(good)
    flipped[good.length - 5] = (flipped[good.length - 5] as number) ^ 1
    await writeFile(result.archive, flipped)
    expect((await failure(checkSnapshot(result.archive))).message).toContain("SHA-256 differs")

    await writeFile(result.archive, good)
    await writeFile(result.sidecar, JSON.stringify({ ...sidecar, recipients: [...sidecar.recipients, sidecar.recipients[0]] }))
    expect((await failure(checkSnapshot(result.archive))).message).toContain("header has 2 stanzas, not 3")

    await rm(result.sidecar)
    expect((await failure(checkSnapshot(result.archive))).message).toContain("no sidecar")
  })
})
