// Mehen is not the only thing that can open a backup: the reference age
// tools read what typage writes, and the other way round. The stock-tool
// tests run when `age` and `age-keygen` are on PATH and are skipped
// otherwise.

import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { readFile, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { BackupBundleSchema, SnapshotSchema, backupPlaintext } from "@mehen/protocol/backup"
import { utf8 } from "@mehen/protocol/bytes"
import { ageDecrypt, ageEncrypt, ephemeralAgeIdentity, newAgeIdentity } from "./age.ts"
import { generateBackupKey } from "./keygen.ts"
import { takeSnapshot } from "./snapshot.ts"
import { type BackupFixture, SECRET_VALUE, backupFixture, sampleBundle, writeExport } from "../testing/backup-fixtures.ts"

const AGE = Bun.which("age")
const AGE_KEYGEN = Bun.which("age-keygen")

let f: BackupFixture
beforeEach(async () => {
  f = await backupFixture()
})
afterEach(() => f.remove())

function run(command: string[], stdin?: Uint8Array): { code: number; stdout: Uint8Array; stderr: string } {
  const result = Bun.spawnSync(command, { stdin: stdin ?? "ignore", stdout: "pipe", stderr: "pipe" })
  return { code: result.exitCode ?? -1, stdout: new Uint8Array(result.stdout), stderr: result.stderr.toString() }
}

describe("the age library", () => {
  test("round trip to a backup identity and to an ephemeral in-memory key", async () => {
    const { identity, recipient } = await newAgeIdentity()
    expect(identity).toMatch(/^AGE-SECRET-KEY-1[0-9A-Z]+$/)
    expect(recipient).toMatch(/^age1[0-9a-z]{58}$/)
    const ephemeral = await ephemeralAgeIdentity()
    const ciphertext = await ageEncrypt(utf8("hello from mehen"), [recipient, ephemeral.recipient])
    expect(new TextDecoder().decode(await ageDecrypt(ciphertext, [identity]))).toBe("hello from mehen")
    expect(new TextDecoder().decode(await ageDecrypt(ciphertext, [ephemeral.key]))).toBe("hello from mehen")
    await expect(ageDecrypt(ciphertext, [(await newAgeIdentity()).identity])).rejects.toThrow()
    expect(ephemeral.key.extractable).toBe(false)
  })
})

describe.skipIf(AGE === null || AGE_KEYGEN === null)("the reference age tools", () => {
  test("age -d opens a snapshot, and base64 -d of a file's content is the file", async () => {
    const keyFile = join(f.root, "key.txt")
    await writeFile(keyFile, `${f.identity}\n`, { mode: 0o600 })
    const { archive } = await takeSnapshot({ planPath: f.planPath, to: f.out, recipients: [f.recipient], env: f.env })
    const opened = run([AGE as string, "-d", "-i", keyFile, archive])
    expect(opened.stderr).toBe("")
    expect(opened.code).toBe(0)
    const snapshot = SnapshotSchema.parse(JSON.parse(new TextDecoder().decode(opened.stdout)))
    const env = snapshot.files.find((file) => file.path === f.envFile)
    expect(Buffer.from(env?.content ?? "", "base64").toString()).toContain(SECRET_VALUE)
    expect(Buffer.from(env?.content ?? "", "base64")).toEqual(await readFile(f.envFile))
  })

  test("age -d opens an export to exactly the bundle, with the same age-encryption the vault pins", async () => {
    const keyFile = join(f.root, "key.txt")
    await writeFile(keyFile, `${f.identity}\n`, { mode: 0o600 })
    const bundle = sampleBundle(f.recipient)
    const archive = await writeExport(join(f.root, "exports"), bundle, f.recipient)
    const opened = run([AGE as string, "-d", "-i", keyFile, archive])
    expect(opened.stderr).toBe("")
    expect(opened.code).toBe(0)
    const text = new TextDecoder().decode(opened.stdout)
    expect(text).toBe(backupPlaintext(bundle))
    expect(BackupBundleSchema.parse(JSON.parse(text)).items[0]?.secretFields.key).toBe(SECRET_VALUE)
  })

  test("age-keygen -y derives the recipient mehen backup keygen printed, and age encrypts to it for typage to open", async () => {
    const keyFile = join(f.root, "backup-key.txt")
    const { recipient } = await generateBackupKey({ out: keyFile, env: f.env })
    const derived = run([AGE_KEYGEN as string, "-y", keyFile])
    expect(derived.code).toBe(0)
    expect(new TextDecoder().decode(derived.stdout).trim()).toBe(recipient)
    const sealed = run([AGE as string, "-r", recipient], utf8("from the reference tool"))
    expect(sealed.code).toBe(0)
    const identity = (await readFile(keyFile, "utf8")).split("\n").find((l) => l.startsWith("AGE-SECRET-KEY-1")) as string
    expect(new TextDecoder().decode(await ageDecrypt(sealed.stdout, [identity]))).toBe("from the reference tool")
  })
})
