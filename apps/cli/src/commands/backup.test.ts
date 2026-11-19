import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { lstat, mkdir, readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { generateBackupKey } from "../backup/keygen.ts"
import { CliError } from "../errors.ts"
import { type BackupFixture, backupFixture } from "../testing/backup-fixtures.ts"
import { runJv } from "../testing/run-mehen.ts"

let f: BackupFixture
beforeEach(async () => {
  f = await backupFixture()
})
afterEach(() => f.remove())

async function failure(promise: Promise<unknown>): Promise<CliError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof CliError) return error
    throw error
  }
  throw new Error("expected a refusal")
}

describe("mehen backup keygen", () => {
  test("writes a new identity in age-keygen's format, mode 0600, and prints only the recipient", async () => {
    const out = join(f.root, "backup-key.txt")
    const result = await runJv(["backup", "keygen", "--out", out], f.env)
    expect(result.code).toBe(EXIT.ok)
    const text = await readFile(out, "utf8")
    const recipient = result.stdout.trim()
    expect(recipient).toMatch(/^age1[0-9a-z]{58}$/)
    expect(text).toMatch(new RegExp(`^# created: \\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z\\n# public key: ${recipient}\\nAGE-SECRET-KEY-1[0-9A-Z]+\\n$`))
    expect((await lstat(out)).mode & 0o777).toBe(0o600)
    const identity = text.split("\n")[2] as string
    expect(result.stdout + result.stderr).not.toContain(identity)
  })

  test("refuses on an enrolled machine unless --on-enrolled-machine, and then warns", async () => {
    await mkdir(join(f.home, "workspaces", "vault.example", "tn_acme"), { recursive: true, mode: 0o700 })
    const out = join(f.root, "backup-key.txt")
    const refused = await runJv(["backup", "keygen", "--out", out], f.env)
    expect(refused.code).toBe(EXIT.usage)
    expect(refused.stderr).toContain("--on-enrolled-machine")
    expect(await lstat(out).catch(() => null)).toBeNull()
    const allowed = await runJv(["backup", "keygen", "--out", out, "--on-enrolled-machine"], f.env)
    expect(allowed.code).toBe(EXIT.ok)
    expect(allowed.stderr).toContain("mehen: warning:")
    expect((await lstat(out)).mode & 0o777).toBe(0o600)
  })

  test("never writes over a file, under MEHEN_HOME, inside a git work tree or to stdout", async () => {
    const existing = join(f.root, "existing.txt")
    await writeFile(existing, "keep me")
    expect((await failure(generateBackupKey({ out: existing, env: f.env }))).message).toContain("already there")
    expect(await readFile(existing, "utf8")).toBe("keep me")
    expect((await failure(generateBackupKey({ out: join(f.home, "key.txt"), env: f.env }))).message).toContain("under MEHEN_HOME")
    expect((await failure(generateBackupKey({ out: join(f.root, ".config", "mehen", "key.txt"), env: { HOME: f.root } }))).message).toContain("under MEHEN_HOME")
    await mkdir(join(f.repo, ".git"))
    expect((await failure(generateBackupKey({ out: join(f.repo, "keys", "key.txt"), env: f.env }))).message).toContain(`inside the git work tree ${f.repo}`)
    expect((await failure(generateBackupKey({ out: "-", env: f.env }))).code).toBe("usage")
  })
})

describe("mehen backup on the command line", () => {
  test("is listed in mehen --help and answers --help with its eight actions", async () => {
    const help = await runJv(["backup", "--help"], f.env)
    expect(help.code).toBe(EXIT.ok)
    for (const action of ["keygen --out", "snapshot --plan", "check <snp_id.age|export.age>", "restore <snp_id.age> --identity <file|->", "restore <export.age> --identity <file|-> --env <dir>", "export --to <dir>", "| status", "open <export.age>", "compare <snp_id.age> <export.age>"]) expect(help.stdout).toContain(action)
    expect((await runJv(["--help"], f.env)).stdout).toContain("  backup ")
  })

  test("a key typed where the archive or the action goes is refused without being repeated", async () => {
    const key = `AGE-SECRET-KEY-1${"Q".repeat(58)}`
    for (const argv of [["backup", "check", key], ["backup", "restore", key, "--identity", "-", "--verify-only"], ["backup", key], ["backup", "check", key.toLowerCase(), "--json"]]) {
      const result = await runJv(argv, f.env)
      expect(result.code).toBe(EXIT.usage)
      expect(result.stdout + result.stderr).toContain("never the key itself")
      expect((result.stdout + result.stderr).toUpperCase()).not.toContain(key.slice(0, 30))
    }
  })

  test("a key typed as --recipient, for a snapshot or an export, is refused without being repeated", async () => {
    const key = `AGE-SECRET-KEY-1${"Q".repeat(58)}`
    for (const [argv, env] of [[["backup", "snapshot", "--plan", f.planPath, "--to", f.out, "--recipient", key], f.env], [["backup", "snapshot", "--plan", f.planPath, "--to", f.out], { ...f.env, MEHEN_BACKUP_RECIPIENTS: key }], [["backup", "export", "--to", f.out, "--recipient", key], f.env], [["backup", "export", "--to", f.out, "--recipient", key.toLowerCase(), "--json"], f.env]] as const) {
      const result = await runJv([...argv], env)
      expect(result.code).toBe(EXIT.usage)
      expect(result.stdout + result.stderr).toContain("never the key itself")
      expect((result.stdout + result.stderr).toUpperCase()).not.toContain(key.slice(0, 30))
    }
  })

  test("snapshot without a recipient, or with a post-quantum one, is a usage error", async () => {
    const none = await runJv(["backup", "snapshot", "--plan", f.planPath, "--to", f.out, "--json"], f.env)
    expect(none.code).toBe(EXIT.usage)
    expect(JSON.parse(none.stdout)).toMatchObject({ error: "usage", message: expect.stringContaining("MEHEN_BACKUP_RECIPIENTS") })
    const pq = await runJv(["backup", "snapshot", "--plan", f.planPath, "--to", f.out, "--recipient", `age1pq1${"q".repeat(80)}`], f.env)
    expect(pq.code).toBe(EXIT.usage)
    expect(pq.stderr).toContain("post-quantum")
  })
})
