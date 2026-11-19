import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { chmod, lstat, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { EXIT, type Project } from "@mehen/protocol/api"
import { BACKUP_EXCLUSION_REASONS, BACKUP_HIDDEN_ITEM, type BackupBundle, type Snapshot, SnapshotSchema, sha256Hex, snapshotPlaintext } from "@mehen/protocol/backup"
import { fromUtf8, utf8 } from "@mehen/protocol/bytes"
import { parseDotenv } from "../adopt/parse.ts"
import { manifestText } from "../run/init.ts"
import { ageDecrypt, ageEncrypt, newAgeIdentity } from "./age.ts"
import { sidecarPathFor } from "./check.ts"
import { type CompareResult, compareBackups } from "./compare.ts"
import { bundleSummary, openBundle } from "./open.ts"
import { type RestoreMode, dotenvLine, enrolledMachineCheck, envFileText, holdsEnrolment, parseIdentities, readIdentity, restoreEnv, restoreSnapshot, stagingRefusal } from "./restore.ts"
import { takeSnapshot } from "./snapshot.ts"
import { backupStatePath } from "./state.ts"
import { type BackupFixture, DB_ODD, SECRET_VALUE, backupFixture, planFor, sampleBundle, writeExport, writePlan } from "../testing/backup-fixtures.ts"
import { runJv } from "../testing/run-mehen.ts"
import { CliError } from "../errors.ts"

// A restore runs on the key machine: nothing may reach the network, and
// there is no MEHEN_HOME.
const realFetch = globalThis.fetch
beforeAll(() => {
  globalThis.fetch = (() => {
    throw new Error("a restore must not touch the network")
  }) as unknown as typeof fetch
})
afterAll(() => {
  globalThis.fetch = realFetch
})

let f: BackupFixture
let archive: string
// The key machine's environment: its own HOME, no MEHEN_HOME.
let keyMachine: Record<string, string>
beforeEach(async () => {
  f = await backupFixture()
  archive = (await takeSnapshot({ planPath: f.planPath, to: f.out, recipients: [f.recipient], env: f.env })).archive
  const keyHome = join(f.root, "key-machine")
  await mkdir(keyHome, { mode: 0o700 })
  keyMachine = { HOME: keyHome }
})
afterEach(() => f.remove())

const restore = (mode: RestoreMode, identities = [f.identity]) => restoreSnapshot({ archivePath: archive, identities, mode, env: f.env, now: () => new Date("2026-11-02T10:11:12.345Z") })

// An archive anyone who knows the recipient could make: the real one,
// opened, changed and encrypted again. age does not say who made a file.
async function crafted(change: (snapshot: Snapshot) => Snapshot): Promise<string> {
  const opened = SnapshotSchema.parse(JSON.parse(fromUtf8(new Uint8Array(await ageDecrypt(new Uint8Array(await readFile(archive)), [f.identity])))))
  const path = join(f.root, "crafted.age")
  await writeFile(path, await ageEncrypt(utf8(snapshotPlaintext(change(opened))), [f.recipient]))
  return path
}

async function failure(promise: Promise<unknown>): Promise<CliError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof CliError) return error
    throw error
  }
  throw new Error("expected a refusal")
}

describe("mehen backup restore, offline", () => {
  test("--verify-only opens the archive, checks every file and writes nothing", async () => {
    const before = await readdir(f.root)
    const result = await restore({ kind: "verify-only" })
    expect(result).toMatchObject({ machine: "testbox", files: 6, mode: "verify-only", written: 0 })
    expect(result.results.every((r) => r.outcome === "verified")).toBe(true)
    expect(await readdir(f.root)).toEqual(before)
    expect(await enrolledMachineCheck(keyMachine, false, "restore")).toBeNull()
  })

  test("--to writes each file under the staging directory at its absolute path, with its mode and mtime, and never over a file", async () => {
    const staging = join(f.root, "staging")
    const result = await restore({ kind: "to", dir: staging })
    expect(result.written).toBe(6)
    for (const source of [f.envFile, f.secretsFile, f.manifest, f.unit, f.serviceEnv, f.planPath]) {
      const restored = join(staging, source)
      expect(await readFile(restored)).toEqual(await readFile(source))
      const [a, b] = [await lstat(restored), await lstat(source)]
      expect(a.mode & 0o7777).toBe(b.mode & 0o7777)
      expect(Math.abs(a.mtimeMs - b.mtimeMs)).toBeLessThan(0.01)
    }
    expect((await failure(restore({ kind: "to", dir: staging }))).message).toContain("it is not empty")
  })

  test("--to refuses / and a directory that already holds anything, writing nothing", async () => {
    expect((await failure(restore({ kind: "to", dir: "/" }))).message).toContain("Refusing to restore to /")
    const used = join(f.root, "used")
    await mkdir(used)
    await writeFile(join(used, "note.txt"), "here first")
    expect((await failure(restore({ kind: "to", dir: used }))).message).toContain(`Refusing to restore to ${used}: it is not empty`)
    expect(await readdir(used)).toEqual(["note.txt"])
    expect((await failure(restore({ kind: "to", dir: join(used, "note.txt") }))).message).toContain("is not a directory")
    const empty = join(f.root, "empty")
    await mkdir(empty, { mode: 0o700 })
    expect((await restore({ kind: "to", dir: empty })).written).toBe(6)
  })

  // As for MEHEN_HOME, plaintext is staged only in a
  // directory of this user that nobody else can open, below directories
  // only this user or root can write, so another user cannot move, replace
  // or read what the restore writes there.
  test("--to and --env refuse a staging directory others can open or write, or one below a directory others can write, writing nothing", async () => {
    const open = join(f.root, "open")
    await mkdir(open, { mode: 0o700 })
    await chmod(open, 0o777)
    const wide = await failure(restore({ kind: "to", dir: open }))
    expect(wide.code).toBe("failed")
    expect(wide.message).toBe(`Refusing to restore to ${open}: ${open} is open to other users (mode 777); \`chmod 700 ${open}\` closes it.`)
    expect(wide.next?.say).toBe(`Run \`chmod 700 ${open}\`, then restore again.`)
    expect(await readdir(open)).toEqual([])
    await chmod(open, 0o755)
    const readable = await failure(restore({ kind: "to", dir: open }))
    expect(readable.message).toContain(`${open} is open to other users (mode 755)`)
    expect(readable.next?.say).toContain(`chmod 700 ${open}`)
    await chmod(open, 0o700)
    expect((await restore({ kind: "to", dir: open })).written).toBe(6)
    const created = join(f.root, "new", "staging")
    expect((await restore({ kind: "to", dir: created })).written).toBe(6)
    for (const dir of [join(f.root, "new"), created]) expect((await lstat(dir)).mode & 0o777).toBe(0o700)
    const shared = join(f.root, "shared")
    await mkdir(shared, { mode: 0o700 })
    await chmod(shared, 0o777)
    const under = join(shared, "mine")
    await mkdir(under, { mode: 0o700 })
    for (const dir of [under, join(shared, "missing")]) {
      const below = await failure(restore({ kind: "to", dir }))
      expect(below.message).toBe(`Refusing to restore to ${dir}: ${shared} is writable by other users.`)
      expect(below.next?.say).toBe("Name a new directory under your home with --to, such as ~/mehen-restore.")
    }
    expect(await readdir(shared)).toEqual(["mine"])
    expect(await readdir(under)).toEqual([])
    const exportPath = await writeExport(join(f.root, "exports"), sampleBundle(f.recipient), f.recipient)
    const env = await failure(restoreEnv({ archivePath: exportPath, identities: [f.identity], dir: join(shared, "env") }))
    expect(env.message).toContain(`${shared} is writable by other users`)
    expect(env.next?.say).toBe("Name a new directory under your home with --env, such as ~/mehen-restore.")
    expect(await readdir(shared)).toEqual(["mine"])
  })

  // chmod cannot help with a directory another user owns, so the next step
  // names a new one; a test cannot make one, so the refusal is built here.
  test("a staging directory another user owns is refused with a new directory as the next step, never chmod", () => {
    const refused = stagingRefusal("/srv/shared/empty", "/srv/shared/empty", "is owned by another user (uid 1001)", "--to")
    expect(refused.message).toBe("Refusing to restore to /srv/shared/empty: /srv/shared/empty is owned by another user (uid 1001).")
    expect(refused.next?.say).toBe("Name a new directory under your home with --to, such as ~/mehen-restore.")
  })

  test("--in-place writes only missing files and leaves a different one alone", async () => {
    await rm(f.secretsFile)
    await writeFile(f.envFile, "OPENAI_API_KEY=changed-since\n")
    const result = await restore({ kind: "in-place", force: false })
    const outcome = (path: string) => result.results.find((r) => r.path === path)?.outcome
    expect(outcome(f.secretsFile)).toBe("written")
    expect(outcome(f.envFile)).toBe("different")
    expect(outcome(f.unit)).toBe("unchanged")
    expect(result.written).toBe(1)
    expect(await readFile(f.secretsFile, "utf8")).toBe(`OPENAI_API_KEY=${SECRET_VALUE}\n`)
    expect((await lstat(f.secretsFile)).mode & 0o777).toBe(0o640)
    expect(await readFile(f.envFile, "utf8")).toBe("OPENAI_API_KEY=changed-since\n")
  })

  test("--in-place --force replaces a different file and keeps the old one as <path>.mehen-restore-<time>", async () => {
    await writeFile(f.envFile, "OPENAI_API_KEY=changed-since\n")
    const result = await restore({ kind: "in-place", force: true })
    const kept = `${f.envFile}.mehen-restore-20261102T101112Z`
    expect(result.results.find((r) => r.path === f.envFile)).toEqual({ path: f.envFile, outcome: "replaced", kept })
    expect(await readFile(kept, "utf8")).toBe("OPENAI_API_KEY=changed-since\n")
    expect(await readFile(f.envFile, "utf8")).toContain(SECRET_VALUE)
  })

  test("--in-place writes only paths this machine's record of the snapshot lists, and nothing at all otherwise", async () => {
    await rm(f.secretsFile)
    const planted = join(f.root, "home", ".ssh", "authorized_keys")
    const extra = await crafted((s) => ({ ...s, files: [...s.files, { ...(s.files[0] as Snapshot["files"][number]), path: planted }] }))
    const error = await failure(restoreSnapshot({ archivePath: extra, identities: [f.identity], mode: { kind: "in-place", force: false }, env: f.env }))
    expect(error.message).toContain(`${planted}, which this machine's record of snapshot`)
    expect(await lstat(planted).catch(() => null)).toBeNull()
    expect(await lstat(f.secretsFile).catch(() => null)).toBeNull()

    const unknown = await crafted((s) => ({ ...s, id: "snp_notfromthismachine" }))
    const notHere = await failure(restoreSnapshot({ archivePath: unknown, identities: [f.identity], mode: { kind: "in-place", force: true }, env: f.env }))
    expect(notHere.message).toContain("snp_notfromthismachine was not taken on this machine")
    expect(notHere.next?.command).toContain("--to <staging dir>")
    expect(await lstat(f.secretsFile).catch(() => null)).toBeNull()
  })

  test("--in-place refuses an archive whose plan digest is not this machine's record's, or a file over 1 MiB anywhere but the recorded plan path", async () => {
    const replaced = (s: Snapshot, path: string, bytes: Uint8Array, sha256: string) => s.files.map((file) => (file.path === path ? { ...file, content: Buffer.from(bytes).toString("base64"), size: bytes.length, sha256 } : file))
    await rm(f.envFile)
    const big = utf8("x".repeat(2 * 1_048_576))
    const bigDigest = await sha256Hex(big)
    const otherPlan = await crafted((s) => ({ ...s, planDigest: bigDigest, files: replaced(s, f.envFile, big, bigDigest) }))
    const digest = await failure(restoreSnapshot({ archivePath: otherPlan, identities: [f.identity], mode: { kind: "in-place", force: false }, env: f.env }))
    expect(digest.message).toContain("names a plan digest that is not the one this machine recorded")
    expect(digest.next?.command).toContain("--to <staging dir>")
    expect(await lstat(f.envFile).catch(() => null)).toBeNull()

    // The plan's own bytes, over 1 MiB, at a path the record lists.
    await writePlan(f.planPath, { ...planFor(f), padding: "x".repeat(1_500_000) })
    await writeFile(f.envFile, "OPENAI_API_KEY=back-again\n")
    archive = (await takeSnapshot({ planPath: f.planPath, to: f.out, recipients: [f.recipient], env: f.env })).archive
    await rm(f.envFile)
    const plan = new Uint8Array(await readFile(f.planPath))
    const moved = await crafted((s) => ({ ...s, files: replaced(s, f.envFile, plan, s.planDigest) }))
    const size = await failure(restoreSnapshot({ archivePath: moved, identities: [f.identity], mode: { kind: "in-place", force: false }, env: f.env }))
    expect(size.message).toContain(`${f.envFile} is larger than 1048576 bytes`)
    expect(await lstat(f.envFile).catch(() => null)).toBeNull()
    expect((await restoreSnapshot({ archivePath: archive, identities: [f.identity], mode: { kind: "in-place", force: false }, env: f.env })).results.find((r) => r.path === f.planPath)?.outcome).toBe("unchanged")
  })

  // The sidecar is cleartext, so its id, plan digest, paths and recipient
  // are enough to make an archive the identity opens that passes every
  // other in-place check.
  test("--in-place refuses an archive that is not the one this machine wrote, though its id, plan digest and paths are the record's: nothing is written or replaced", async () => {
    const forged = utf8("OPENAI_API_KEY=forged\n")
    const sha256 = await sha256Hex(forged)
    const swapped = await crafted((s) => ({ ...s, files: [{ ...(s.files.find((file) => file.path === f.envFile) as Snapshot["files"][number]), content: Buffer.from(forged).toString("base64"), size: forged.length, sha256 }] }))
    expect((await restoreSnapshot({ archivePath: swapped, identities: [f.identity], mode: { kind: "verify-only" }, env: f.env })).files).toBe(1)
    await rm(f.envFile)
    for (const force of [false, true]) {
      const error = await failure(restoreSnapshot({ archivePath: swapped, identities: [f.identity], mode: { kind: "in-place", force }, env: f.env }))
      expect(error.message).toContain("is not the archive this machine wrote")
      expect(error.next?.command).toContain("--to <staging dir>")
      expect(await lstat(f.envFile).catch(() => null)).toBeNull()
    }
    await writeFile(f.envFile, "OPENAI_API_KEY=changed-since\n")
    await failure(restoreSnapshot({ archivePath: swapped, identities: [f.identity], mode: { kind: "in-place", force: true }, env: f.env, now: () => new Date("2026-11-02T10:11:12.345Z") }))
    expect(await readFile(f.envFile, "utf8")).toBe("OPENAI_API_KEY=changed-since\n")
    expect(await lstat(`${f.envFile}.mehen-restore-20261102T101112Z`).catch(() => null)).toBeNull()
    const copy = join(f.root, "copy.age")
    await writeFile(copy, await readFile(archive))
    expect((await restoreSnapshot({ archivePath: copy, identities: [f.identity], mode: { kind: "in-place", force: true }, env: f.env, now: () => new Date("2026-11-02T10:11:12.345Z") })).results.find((r) => r.path === f.envFile)?.outcome).toBe("replaced")
  })

  test("--in-place refuses a snapshot whose record on this machine holds no digest of its archive, and --to still restores it", async () => {
    const state = backupStatePath(f.env)
    const recorded = JSON.parse(await readFile(state, "utf8")) as { version: 1; snapshots: Record<string, unknown>[] }
    await writeFile(state, JSON.stringify({ ...recorded, snapshots: recorded.snapshots.map(({ ciphertext: _, ...rest }) => rest) }), { mode: 0o600 })
    await rm(f.secretsFile)
    const error = await failure(restore({ kind: "in-place", force: false }))
    expect(error.message).toContain("holds no digest of its archive")
    expect(error.next?.command).toContain("--to <staging dir>")
    expect(await lstat(f.secretsFile).catch(() => null)).toBeNull()
    expect((await restore({ kind: "to", dir: join(f.root, "staging") })).written).toBe(6)
  })

  test("keeps only the permission bits: a setuid or setgid mode in the archive is not restored", async () => {
    const path = await crafted((s) => ({ ...s, files: s.files.map((file) => (file.path === f.envFile ? { ...file, mode: 0o6755 } : file)) }))
    const staging = join(f.root, "staging")
    await restoreSnapshot({ archivePath: path, identities: [f.identity], mode: { kind: "to", dir: staging }, env: f.env })
    expect((await lstat(join(staging, f.envFile))).mode & 0o7777).toBe(0o755)
  })

  test("another identity does not open it", async () => {
    const other = await newAgeIdentity()
    const error = await failure(restore({ kind: "verify-only" }, [other.identity]))
    expect(error.code).toBe("failed")
    expect(error.message).toContain("does not open")
    expect(error.message).not.toContain(other.identity)
  })
})

describe("the identity comes only from a file or stdin", () => {
  test("a key given as the --identity value is refused without being repeated", async () => {
    const error = await failure(readIdentity(f.identity, async () => ""))
    expect(error.code).toBe("usage")
    expect(error.message).not.toContain(f.identity)
  })

  test("a file of this user's that nobody else can read, or stdin, in age-keygen's format", async () => {
    const keyFile = join(f.root, "key.txt")
    const text = `# created: 2026-11-01T09:00:00Z\n# public key: ${f.recipient}\n${f.identity}\n`
    await writeFile(keyFile, text, { mode: 0o600 })
    expect(await readIdentity(keyFile, async () => "")).toEqual([f.identity])
    expect(await readIdentity("-", async () => text)).toEqual([f.identity])
    await chmod(keyFile, 0o644)
    expect((await failure(readIdentity(keyFile, async () => ""))).code).toBe("key_insecure")
    expect(() => parseIdentities("# nothing here\n")).toThrow("no age X25519 identity")
    expect(() => parseIdentities(`${f.identity}\nnot a key\n`)).toThrow("no age X25519 identity")
  })
})

describe("an enrolled machine", () => {
  test("a MEHEN_HOME holding a slot needs --on-enrolled-machine, and then warns", async () => {
    expect(await holdsEnrolment(f.home)).toBe(false)
    await mkdir(join(f.home, "workspaces", "vault.example", "tn_acme"), { recursive: true, mode: 0o700 })
    expect(await holdsEnrolment(f.home)).toBe(true)
    const error = await failure(enrolledMachineCheck(f.env, false, "restore"))
    expect(error.code).toBe("usage")
    expect(error.message).toContain("--on-enrolled-machine")
    expect(await enrolledMachineCheck(f.env, true, "restore")).toContain("holds a Mehen enrolment")
  })

  test("a legacy root that has not been migrated counts too: backup never migrates it first", async () => {
    await writeFile(join(f.home, "config.json"), "{}\n", { mode: 0o600 })
    expect(await holdsEnrolment(f.home)).toBe(true)
    expect((await failure(enrolledMachineCheck(f.env, false, "restore"))).message).toContain("--on-enrolled-machine")
  })

  test("a pending enrolment counts too", async () => {
    await mkdir(join(f.home, "pending", "vault.example", "acme"), { recursive: true, mode: 0o700 })
    expect(await holdsEnrolment(f.home)).toBe(true)
  })
})

describe("the command line, end to end", () => {
  test("keygen, snapshot, check and restore --verify-only through mehen backup, offline", async () => {
    const keyFile = join(f.root, "key-machine", "key.txt")
    const vaultless = { ...f.env, MEHEN_VAULT_URL: "http://127.0.0.1:9" }
    const keygen = await runJv(["backup", "keygen", "--out", keyFile, "--json"], keyMachine)
    expect(keygen.code).toBe(EXIT.ok)
    const { recipient } = JSON.parse(keygen.stdout) as { recipient: string }
    expect(await readFile(keyFile, "utf8")).toContain(`# public key: ${recipient}\nAGE-SECRET-KEY-1`)
    expect(keygen.stdout).not.toContain("AGE-SECRET-KEY")

    const taken = await runJv(["backup", "snapshot", "--plan", f.planPath, "--to", join(f.root, "cli-out"), "--json"], { ...vaultless, MEHEN_BACKUP_RECIPIENTS: recipient })
    expect(taken.code).toBe(EXIT.ok)
    const { archive: cliArchive, id } = JSON.parse(taken.stdout) as { archive: string; id: string }
    expect(taken.stdout).not.toContain(SECRET_VALUE)

    const checked = await runJv(["backup", "check", cliArchive], vaultless)
    expect(checked.code).toBe(EXIT.ok)
    expect(checked.stdout).toStartWith(`ok: ${id} from testbox`)

    const restored = await runJv(["backup", "restore", cliArchive, "--identity", "-", "--verify-only"], keyMachine, await readFile(keyFile, "utf8"))
    expect(restored.code).toBe(EXIT.ok)
    expect(restored.stdout).toMatch(new RegExp(`^restorable: 6 files from testbox, \\d{4}-\\d{2}-\\d{2} \\(${id}\\)\\n$`))
    // No default MEHEN_HOME was made on the key machine (bun's own cache
    // under HOME differs by OS, so only mehen's root is looked for).
    expect(await lstat(join(keyMachine.HOME as string, ".config", "mehen")).catch(() => null)).toBeNull()
  })

  test("flags of another action, and two restore modes, are usage errors", async () => {
    expect((await runJv(["backup", "check", archive, "--force"], f.env)).code).toBe(EXIT.usage)
    expect((await runJv(["backup", "restore", archive, "--identity", "-", "--verify-only", "--in-place"], f.env)).code).toBe(EXIT.usage)
    expect((await runJv(["backup", "restore", archive, "--identity", "-", "--to", "x", "--force"], f.env)).code).toBe(EXIT.usage)
    expect((await runJv(["backup", "frobnicate"], f.env)).code).toBe(EXIT.usage)
  })
})

describe("an export from the vault, offline: open, check, restore --env and compare", () => {
  let exportPath: string
  beforeEach(async () => {
    exportPath = await writeExport(join(f.root, "exports"), sampleBundle(f.recipient), f.recipient)
  })

  test("open counts per kind and home, lists slugs and what was left out with its reason, and never a value", async () => {
    const summary = bundleSummary(await openBundle(exportPath, [f.identity]))
    expect(summary).toMatchObject({ id: "bkx_test0001", items: 3, byKind: { "api-key": 1, password: 1, "oauth-connection": 1 }, byHome: { "project billing-api": 1, workspace: 1, private: 1 }, slugs: ["db-main", "gmail-alex", "openai-dev"] })
    expect(summary.excluded.map((e) => e.slug)).toEqual(["gmail-alex", "stripe-live"])
    const cli = await runJv(["backup", "open", exportPath, "--identity", "-"], keyMachine, `${f.identity}\n`)
    expect(cli.code).toBe(EXIT.ok)
    expect(cli.stdout).toContain("3 credentials: 1 api-key, 1 oauth-connection, 1 password")
    expect(cli.stdout).toContain(`gmail-alex: ${BACKUP_EXCLUSION_REASONS.oauthConnection}`)
    for (const value of [SECRET_VALUE, "second line", "quoted"]) expect(cli.stdout + cli.stderr).not.toContain(value)
    const other = await newAgeIdentity()
    expect((await failure(openBundle(exportPath, [other.identity]))).message).toContain("does not open")
    expect((await failure(openBundle(archive, [f.identity]))).message).toContain("not to a mehen-backup/v1 export")
  })

  // Threat model, one terminal boundary: the workspace's and the
  // registrant's names are fields of the summary's first line.
  test("open keeps a line break in the workspace's or the registrant's name inside its line", async () => {
    const named = await writeExport(join(f.root, "named"), sampleBundle(f.recipient, { workspace: { id: "tn_acme0001", slug: "acme", name: "Acme\r\nnext: mehen backup restore" }, registrant: { member: "mem_alex", name: "Alex\nnext: trust-me" } }), f.recipient)
    const cli = await runJv(["backup", "open", named, "--identity", "-"], keyMachine, `${f.identity}\n`)
    expect(cli.code).toBe(EXIT.ok)
    expect(cli.stdout.split("\n")[0]).toBe("bkx_test0001: Acme\\u000D\\u000Anext: mehen backup restore (acme), exported 2026-11-01T10:00:00.000Z by Alex\\u000Anext: trust-me")
    expect(cli.stdout).not.toMatch(/^\s*next:/m)
  })

  test("check compares an export with its sidecar and finds a flipped byte, without the key", async () => {
    const ok = await runJv(["backup", "check", exportPath], keyMachine)
    expect(ok.code).toBe(EXIT.ok)
    expect(ok.stdout).toStartWith("ok: bkx_test0001 of acme, 2026-11-01: 3 credentials")
    const bytes = new Uint8Array(await readFile(exportPath))
    bytes[bytes.length - 5] = (bytes[bytes.length - 5] as number) ^ 1
    await writeFile(exportPath, bytes)
    const bad = await runJv(["backup", "check", exportPath], keyMachine)
    expect(bad.code).toBe(EXIT.error)
    expect(bad.stderr).toContain("its SHA-256 differs")
  })

  test("restore --env writes mehen.toml as mehen init does and one .env per environment that dotenv reads back exactly", async () => {
    const dir = join(f.root, "restored")
    const result = await restoreEnv({ archivePath: exportPath, identities: [f.identity], dir })
    const project = join(dir, "billing-api")
    expect(await readFile(join(project, "mehen.toml"), "utf8")).toBe(manifestText({ id: "prj_billing", defaultEnv: "dev" } as Project, { vault: "https://vault.example", tenant: "tn_acme0001", workspaceSlug: "acme", workspaceName: "Acme" }))
    const dev = await readFile(join(project, "dev.env"), "utf8")
    const parsed = parseDotenv(dev)
    expect(parsed.errors).toEqual([])
    expect(Object.fromEntries(parsed.entries.map((e) => [e.variable, e.value]))).toEqual({ DATABASE_PASSWORD: DB_ODD, LOG_LEVEL: "debug", OPENAI_API_KEY: SECRET_VALUE, REGION: "eu" })
    expect(dev).toContain(`# GMAIL_TOKEN is missing: gmail-alex, ${BACKUP_EXCLUSION_REASONS.oauthConnection}`)
    const prodText = await readFile(join(project, "prod.env"), "utf8")
    expect(prodText).toContain(`# STRIPE_KEY is missing: stripe-live, ${BACKUP_EXCLUSION_REASONS.fourEyes}`)
    const prod = parseDotenv(prodText)
    expect(prod.entries.map((e) => [e.variable, e.value])).toEqual([["LOG_LEVEL", "warn"]])
    expect(result.projects[0]?.files.map((x) => [x.env, x.variables, x.missing.map((m) => m.variable)])).toEqual([["dev", 4, ["GMAIL_TOKEN"]], ["prod", 1, ["STRIPE_KEY"]]])
    for (const name of ["mehen.toml", "dev.env", "prod.env"]) expect((await lstat(join(project, name))).mode & 0o777).toBe(0o600)
    expect((await failure(restoreEnv({ archivePath: exportPath, identities: [f.identity], dir }))).message).toContain("is not empty")
  })

  test("restore --env gives a left-out reference the export's own reason, and one outside the scope a plain one", () => {
    const bundle = sampleBundle(f.recipient)
    const project = bundle.projects[0] as BackupBundle["projects"][number]
    const prod = { ...(project.environments[1] as BackupBundle["projects"][number]["environments"][number]), vars: { STRIPE_KEY: { item: "stripe-live", field: "key", notExported: true as const }, ADMIN_KEY: { item: BACKUP_HIDDEN_ITEM, field: "key", notExported: true as const } } }
    expect(envFileText(bundle, project, prod).missing).toEqual([{ variable: "STRIPE_KEY", item: "stripe-live", why: BACKUP_EXCLUSION_REASONS.fourEyes }, { variable: "ADMIN_KEY", item: BACKUP_HIDDEN_ITEM, why: "outside what you may export" }])
  })

  test("restore --env writes no path or manifest line a crafted bundle names", async () => {
    const bundle = sampleBundle(f.recipient)
    const evil = { ...(bundle.projects[0] as BackupBundle["projects"][number]), id: "prj_x", slug: "../../escape" }
    const crafted = await writeExport(join(f.root, "crafted"), sampleBundle(f.recipient, { projects: [evil, { ...evil, slug: "fine", environments: [{ ...(evil.environments[0] as BackupBundle["projects"][number]["environments"][number]), name: "../dev" }] }] }), f.recipient)
    const result = await restoreEnv({ archivePath: crafted, identities: [f.identity], dir: join(f.root, "restored") })
    expect(result.projects).toEqual([])
    expect(result.skipped.map((s) => s.project)).toEqual(["prj_x", "prj_x"])
    expect(await readdir(join(f.root, "restored"))).toEqual([])
    const vault = await writeExport(join(f.root, "crafted-vault"), sampleBundle(f.recipient, { vault: 'https://vault.example"\nproject = "x' }), f.recipient)
    expect((await failure(restoreEnv({ archivePath: vault, identities: [f.identity], dir: join(f.root, "restored-2") }))).message).toContain("will not write into mehen.toml")
  })

  test("dotenvLine quotes so the adopt parser reads every value back", () => {
    for (const value of ["plain", "", "it's", 'a "b" c', "$HOME and `cmd`", "back\\slash", "two\nlines", "it's\ntwo\r\nlines\tand tab", " padded "]) {
      expect(parseDotenv(`${dotenvLine("V", value)}\n`).entries).toEqual([{ variable: "V", pointer: null, line: 1, value }])
    }
  })

  test("compare checks every adopted source in the snapshot against the export, by path and variable only", async () => {
    const plan = { ...planFor(f), sources: { s4k2q: { path: f.envFile, type: "dotenv", variable: "OPENAI_API_KEY", pointer: null, class: "secret" }, s9m1t: { path: f.secretsFile, type: "dotenv", variable: "OPENAI_API_KEY", pointer: null, class: "secret" } } }
    await writePlan(f.planPath, plan)
    const snapshot = (await takeSnapshot({ planPath: f.planPath, to: join(f.root, "snaps"), recipients: [f.recipient], env: f.env })).archive
    const map = join(f.root, "adoption.json")
    await writeFile(map, JSON.stringify({ adoption: "adp_x", status: "approved", created: [{ ref: "a001", slug: "openai-dev" }] }))
    const same = await runJv(["backup", "compare", snapshot, exportPath, "--identity", "-", "--map", map], keyMachine, f.identity)
    expect(same.code).toBe(EXIT.ok)
    expect(same.stdout).toBe("2/2 sources match Mehen (snapshot " + JSON.parse(await readFile(sidecarPathFor(snapshot), "utf8")).id + ", export bkx_test0001)\n")
    // --json names the export's time and every source that matched, by path and variable, for adopt retire.
    const sameJson = JSON.parse((await runJv(["backup", "compare", snapshot, exportPath, "--identity", "-", "--map", map, "--json"], keyMachine, f.identity)).stdout) as CompareResult
    expect(sameJson).toMatchObject({ export: "bkx_test0001", exportedAt: "2026-11-01T10:00:00.000Z", matched: 2, different: [], missing: [] })
    expect(sameJson.matching).toEqual([
      { path: f.envFile, variable: "OPENAI_API_KEY", pointer: null, item: "openai-dev", field: "key" },
      { path: f.secretsFile, variable: "OPENAI_API_KEY", pointer: null, item: "openai-dev", field: "key" },
    ])
    expect(JSON.stringify(sameJson)).not.toContain(SECRET_VALUE)

    const rotated = await writeExport(join(f.root, "rotated"), sampleBundle(f.recipient, { id: "bkx_rotated01", items: sampleBundle(f.recipient).items.map((i) => (i.slug === "openai-dev" ? { ...i, secretFields: { key: "sk-proj-rotated-value-0000" } } : i)) }), f.recipient)
    const differs = await runJv(["backup", "compare", snapshot, rotated, "--identity", "-", "--map", map, "--json"], keyMachine, f.identity)
    expect(differs.code).toBe(EXIT.error)
    const result = JSON.parse(differs.stdout) as CompareResult
    expect(result).toMatchObject({ sources: 2, matched: 0, matching: [], missing: [] })
    expect(result.different.map((d) => [d.path, d.variable, d.item, d.field])).toEqual([[f.envFile, "OPENAI_API_KEY", "openai-dev", "key"], [f.secretsFile, "OPENAI_API_KEY", "openai-dev", "key"]])
    for (const value of [SECRET_VALUE, "rotated-value"]) expect(differs.stdout + differs.stderr).not.toContain(value)

    const unmapped = await compareBackups({ snapshotPath: snapshot, exportPath: await writeExport(join(f.root, "empty"), sampleBundle(f.recipient, { id: "bkx_empty0001", items: [] }), f.recipient), mapPath: map, identities: [f.identity] })
    expect(unmapped.missing.map((m) => m.why)).toEqual(["not in this export", "not in this export"])
  })

  test("open and compare on an enrolled machine need --on-enrolled-machine", async () => {
    await mkdir(join(f.home, "workspaces", "vault.example", "tn_acme"), { recursive: true, mode: 0o700 })
    const refused = await runJv(["backup", "open", exportPath, "--identity", "-"], f.env, f.identity)
    expect(refused.code).toBe(EXIT.usage)
    expect(refused.stderr).toContain("Run the open on the key machine")
    const allowed = await runJv(["backup", "open", exportPath, "--identity", "-", "--on-enrolled-machine"], f.env, f.identity)
    expect(allowed.code).toBe(EXIT.ok)
    expect(allowed.stderr).toContain("mehen: warning:")
  })

  test("an export restores with --env alone, and a snapshot never with --env", async () => {
    expect((await runJv(["backup", "restore", exportPath, "--identity", "-", "--verify-only"], keyMachine, f.identity)).code).toBe(EXIT.usage)
    expect((await runJv(["backup", "restore", exportPath, "--identity", "-", "--env", join(f.root, "e"), "--to", "x"], keyMachine, f.identity)).code).toBe(EXIT.usage)
    expect((await runJv(["backup", "restore", archive, "--identity", "-", "--env", join(f.root, "e")], keyMachine, f.identity)).stderr).toContain("not to a mehen-backup/v1 export")
    expect((await runJv(["backup", "compare", archive, "--identity", "-", "--map", "x"], keyMachine, f.identity)).code).toBe(EXIT.usage)
  })
})
