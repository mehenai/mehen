import { describe, expect, test } from "bun:test"
import {
  BACKUP_EXCLUSION_REASONS,
  BACKUP_EXPORT_LIMITS,
  BACKUP_EXPORT_SCOPE,
  BACKUP_FORMAT,
  BACKUP_LIMITS,
  BACKUP_RECIPIENT_DELAY_MS,
  BACKUP_SIDECAR_FORMAT,
  type BackupBundle,
  BackupBundleSchema,
  BackupRecipientAddSchema,
  type BackupSidecar,
  BackupSidecarSchema,
  backupCiphertextBase64,
  backupExportFileName,
  backupIsStale,
  backupPlaintext,
  backupRecipientAddAction,
  backupScopeDigest,
  SNAPSHOT_FORMAT,
  SNAPSHOT_ID,
  SNAPSHOT_SIDECAR_FORMAT,
  type Snapshot,
  SnapshotPathSchema,
  SnapshotSchema,
  type SnapshotSidecar,
  SnapshotSidecarSchema,
  ageRecipientFingerprint,
  parseAgeRecipient,
  sha256Hex,
  snapshotPlaintext,
} from "./backup.ts"
import { sha256B64, utf8 } from "./bytes.ts"
import { canonicalJson } from "./canonical-json.ts"
import { RESTRICTION_MS, WORKSPACE_WHILE_RESTRICTED, workspaceAllowedWhileRestricted } from "./step-up-rules.ts"
import { WorkspaceNoticePayloadSchema, WorkspaceStepUpActionSchema } from "./workspace.ts"

// The recipient in age's README, and one typage generated.
const README_RECIPIENT = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
const RECIPIENT = "age177alz07ndcqgev0uv2m05rq8wy7dktmnfn3u4d3yr8q0wsawffgqryyulm"

describe("age recipients", () => {
  test("an X25519 recipient with a good checksum parses", () => {
    for (const ok of [README_RECIPIENT, RECIPIENT]) expect(parseAgeRecipient(ok)).toEqual({ ok: true, recipient: ok })
    expect(parseAgeRecipient(` ${RECIPIENT}\n`)).toEqual({ ok: true, recipient: RECIPIENT })
  })

  test("post-quantum, plugin, tag and SSH recipients are refused, each with its reason", () => {
    const refused = (text: string) => {
      const parsed = parseAgeRecipient(text)
      if (parsed.ok) throw new Error(`${text} parsed`)
      return parsed.reason
    }
    expect(refused(`age1pq1${"q".repeat(1900)}`)).toContain("post-quantum")
    expect(refused("age1yubikey1qwt50d05nh5vutpdzmlg5wn80xq5negm4uj9ghv0snvdd3yysf5yw3rhl3t")).toContain("plugin")
    expect(refused(`age1tag1${"q".repeat(60)}`)).toContain("plugin and tag")
    expect(refused("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@example")).toContain("SSH")
    expect(refused("ssh-rsa AAAAB3NzaC1yc2E alice")).toContain("SSH")
  })

  test("a wrong character, a wrong length, upper case or an identity is refused", () => {
    const flipped = `${RECIPIENT.slice(0, 20)}${RECIPIENT[20] === "q" ? "p" : "q"}${RECIPIENT.slice(21)}`
    expect(parseAgeRecipient(flipped)).toEqual({ ok: false, reason: expect.stringContaining("checksum") })
    expect(parseAgeRecipient(RECIPIENT.slice(0, -1)).ok).toBe(false)
    expect(parseAgeRecipient(RECIPIENT.toUpperCase()).ok).toBe(false)
    expect(parseAgeRecipient("AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGP").ok).toBe(false)
    expect(parseAgeRecipient("").ok).toBe(false)
  })

  test("the fingerprint is the recipient's first 12 and last 8 characters", () => {
    expect(ageRecipientFingerprint(RECIPIENT)).toBe("age177alz07n...gqryyulm")
  })
})

describe("snapshot ids and paths", () => {
  test("a snapshot id is snp_ and up to 60 id characters", () => {
    for (const ok of ["snp_a", "snp_K2m9-q4_x", `snp_${"a".repeat(60)}`]) expect(SNAPSHOT_ID.test(ok), ok).toBe(true)
    for (const bad of ["snp_", "adp_k2m9", "snp_a/b", "snp_a b", `snp_${"a".repeat(61)}`, "snp_a.."]) expect(SNAPSHOT_ID.test(bad), bad).toBe(false)
  })

  test("a captured path is absolute with no empty, . or .. component", () => {
    for (const ok of ["/a", "/Users/sam/code/billing-api/.env", "/x/.config/y.env"]) expect(SnapshotPathSchema.safeParse(ok).success, ok).toBe(true)
    for (const bad of ["a/b", "/", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\0b", "../etc/passwd"]) expect(SnapshotPathSchema.safeParse(bad).success, bad).toBe(false)
  })
})

const CONTENT = utf8("OPENAI_API_KEY=sk-proj-abc\n")

async function snapshot(): Promise<Snapshot> {
  return {
    format: SNAPSHOT_FORMAT,
    id: "snp_k2m9q4",
    machine: "sam-mac-mini",
    createdAt: "2026-11-01T09:00:00.000Z",
    planDigest: await sha256Hex(utf8("{}")),
    files: [
      {
        path: "/Users/sam/code/billing-api/.env",
        mode: 0o600,
        uid: 501,
        gid: 20,
        user: "sam",
        group: "staff",
        mtimeMs: 1_761_900_000_123.5,
        size: CONTENT.length,
        sha256: await sha256Hex(CONTENT),
        content: Buffer.from(CONTENT).toString("base64"),
      },
    ],
  }
}

describe("the snapshot plaintext", () => {
  test("parses strictly and serialises as canonical JSON", async () => {
    const value = await snapshot()
    expect(SnapshotSchema.parse(value)).toEqual(value)
    const text = snapshotPlaintext(value)
    expect(text.startsWith('{"createdAt":"2026-11-01T09:00:00.000Z","files":[{"content":')).toBe(true)
    expect(SnapshotSchema.parse(JSON.parse(text))).toEqual(value)
    expect(SnapshotSchema.safeParse({ ...value, extra: 1 }).success).toBe(false)
    expect(SnapshotSchema.safeParse({ ...value, format: "mehen-snapshot/v2" }).success).toBe(false)
  })

  test("a file over the cap, a mode with type bits, bad base64 or a relative path is refused", async () => {
    const value = await snapshot()
    const file = value.files[0] as Snapshot["files"][number]
    for (const bad of [{ size: BACKUP_LIMITS.maxFileBytes + 1 }, { mode: 0o100600 }, { content: "not base64!" }, { path: "relative/.env" }, { sha256: "AB".repeat(32) }]) {
      expect(SnapshotSchema.safeParse({ ...value, files: [{ ...file, ...bad }] }).success, JSON.stringify(bad)).toBe(false)
    }
  })

  // Seen on a real machine: a 1.1 MB plan was refused as a source.
  test("the plan, the file planDigest names, may be up to 16 MiB; every other file stays at 1 MiB", async () => {
    const value = await snapshot()
    const file = value.files[0] as Snapshot["files"][number]
    const plan = { ...file, path: "/Users/sam/.mehen/adopt/mac/plan.json", sha256: value.planDigest, size: 1_500_000 }
    expect(SnapshotSchema.safeParse({ ...value, files: [file, plan] }).success).toBe(true)
    expect(SnapshotSchema.safeParse({ ...value, files: [file, { ...plan, size: BACKUP_LIMITS.maxPlanBytes }] }).success).toBe(true)
    expect(SnapshotSchema.safeParse({ ...value, files: [file, { ...plan, size: BACKUP_LIMITS.maxPlanBytes + 1 }] }).success).toBe(false)
    const big = SnapshotSchema.safeParse({ ...value, files: [{ ...file, size: 1_500_000 }, plan] })
    expect(big.success).toBe(false)
    expect(big.error?.issues.map((i) => [i.path.join("."), i.message])).toEqual([["files.0.size", "only the plan may be larger than 1048576 bytes"]])
  })

  test("sha256Hex is lower-case hex of SHA-256", async () => {
    expect(await sha256Hex(utf8("abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  })
})

describe("the sidecar", () => {
  const sidecar = (): SnapshotSidecar => ({
    format: SNAPSHOT_SIDECAR_FORMAT,
    id: "snp_k2m9q4",
    machine: "sam-mac-mini",
    createdAt: "2026-11-01T09:00:00.000Z",
    planDigest: "0".repeat(64),
    recipients: [{ recipient: RECIPIENT, fingerprint: ageRecipientFingerprint(RECIPIENT) }],
    files: 1,
    paths: ["/Users/sam/code/billing-api/.env"],
    ciphertext: { bytes: 400, sha256: "1".repeat(64) },
    selfCheck: "passed",
  })

  test("holds paths and counts, and has no member for a length or a content hash", () => {
    expect(SnapshotSidecarSchema.parse(sidecar())).toEqual(sidecar())
    for (const extra of [{ sizes: [1] }, { hashes: ["0".repeat(64)] }, { content: "x" }]) expect(SnapshotSidecarSchema.safeParse({ ...sidecar(), ...extra }).success).toBe(false)
  })

  test("needs a passed self-check and at least one X25519 recipient", () => {
    expect(SnapshotSidecarSchema.safeParse({ ...sidecar(), selfCheck: "failed" }).success).toBe(false)
    expect(SnapshotSidecarSchema.safeParse({ ...sidecar(), recipients: [] }).success).toBe(false)
    expect(SnapshotSidecarSchema.safeParse({ ...sidecar(), recipients: [{ recipient: `age1pq1${"q".repeat(100)}`, fingerprint: "x" }] }).success).toBe(false)
  })
})

describe("layer 2: recipients, the step-ups and the notice", () => {
  test("adding a recipient is refused while restricted; removing one is allowed", () => {
    expect(WORKSPACE_WHILE_RESTRICTED["backup.recipient_add"]).toBe("refused")
    expect(WORKSPACE_WHILE_RESTRICTED["backup.recipient_remove"]).toBe("allowed")
    expect(workspaceAllowedWhileRestricted({ type: "backup.recipient_add", recipient: RECIPIENT, label: "Safe", scopeDigest: "d" })).toBe(false)
    expect(workspaceAllowedWhileRestricted({ type: "backup.recipient_remove", id: "bkr_x" })).toBe(true)
  })

  test("the add step-up binds the recipient, the label and the scope digest", async () => {
    const action = await backupRecipientAddAction({ recipient: RECIPIENT, label: "Paper in the safe" })
    expect(action).toEqual({ type: "backup.recipient_add", recipient: RECIPIENT, label: "Paper in the safe", scopeDigest: await backupScopeDigest() })
    expect(WorkspaceStepUpActionSchema.parse(action)).toEqual(action)
    expect(await backupScopeDigest()).toBe(await sha256B64(canonicalJson(BACKUP_EXPORT_SCOPE)))
    expect(BACKUP_RECIPIENT_DELAY_MS).toBe(RESTRICTION_MS)
  })

  test("only X25519 recipients and a short label without control characters register", () => {
    expect(BackupRecipientAddSchema.safeParse({ recipient: RECIPIENT, label: "Safe" }).success).toBe(true)
    for (const recipient of [`age1pq1${"q".repeat(100)}`, "ssh-ed25519 AAAA x", `${RECIPIENT} `]) expect(BackupRecipientAddSchema.safeParse({ recipient, label: "Safe" }).success).toBe(false)
    for (const label of ["", " ", "x".repeat(65), "a\nb"]) expect(BackupRecipientAddSchema.safeParse({ recipient: RECIPIENT, label }).success).toBe(false)
  })

  test("the backup_recipient notice", () => {
    const payload = { kind: "backup_recipient", workspace: { id: "tn_x", slug: "work", name: "Work" }, member: "mem_owner", name: "Alex", recipient: { id: "bkr_x", fingerprint: ageRecipientFingerprint(RECIPIENT), label: "Safe" }, change: "added", activeAt: "2026-11-02T09:00:00.000Z", by: "mem_owner", at: "2026-11-01T09:00:00.000Z" } as const
    expect(WorkspaceNoticePayloadSchema.parse(payload)).toEqual(payload)
    expect(WorkspaceNoticePayloadSchema.safeParse({ ...payload, change: "renamed" }).success).toBe(false)
    expect(WorkspaceNoticePayloadSchema.safeParse({ ...payload, recipient: { ...payload.recipient, recipient: RECIPIENT } }).success).toBe(false)
  })

  test("staleness: an active recipient with changes and no export within seven days", () => {
    const now = Date.parse("2026-11-10T00:00:00.000Z")
    const at = (days: number) => new Date(now - days * 86_400_000).toISOString()
    expect(backupIsStale({ status: "active", lastExport: null, changedSince: 3 }, now)).toBe(true)
    expect(backupIsStale({ status: "active", lastExport: { id: "bkx_a", at: at(8), items: 3 }, changedSince: 3 }, now)).toBe(true)
    expect(backupIsStale({ status: "active", lastExport: { id: "bkx_a", at: at(6), items: 3 }, changedSince: 3 }, now)).toBe(false)
    expect(backupIsStale({ status: "active", lastExport: { id: "bkx_a", at: at(30), items: 3 }, changedSince: 0 }, now)).toBe(false)
    expect(backupIsStale({ status: "pending", lastExport: null, changedSince: 3 }, now)).toBe(false)
    expect(backupIsStale({ status: "active", lastExport: null, changedSince: null }, now)).toBe(false)
  })
})

describe("layer 2: the bundle", () => {
  const bundle = (): BackupBundle => ({
    format: BACKUP_FORMAT,
    id: "bkx_k2m9q4",
    vault: "https://vault.example",
    workspace: { id: "tn_x", slug: "work", name: "Work" },
    exportedAt: "2026-11-01T09:00:00.000Z",
    registrant: { member: "mem_owner", name: "Alex" },
    recipient: { id: "bkr_x", fingerprint: ageRecipientFingerprint(RECIPIENT) },
    auditHead: { seq: 41, hash: "h" },
    items: [{ id: "itm_a", slug: "openai", kind: "api-key", provider: "openai", account: null, home: { kind: "workspace" }, tags: [], binding: { hosts: ["api.openai.com"] }, policy: { default: "allow", rules: [] }, ceiling: "relay", injection: null, description: null, publicFields: {}, secretFields: { key: "sk-test" }, version: 2, rotatedAt: null }],
    projects: [{ id: "prj_a", slug: "billing", remotes: ["github.com/a/b"], defaultEnv: "dev", environments: [{ name: "dev", protected: false, fences: [], fourEyes: false, vars: { OPENAI_API_KEY: { item: "openai", field: "key" }, LOG_LEVEL: { plain: "info" }, STRIPE_KEY: { item: "stripe", field: "key", notExported: true } } }] }],
    overrides: [],
    excluded: [{ slug: "stripe", reason: BACKUP_EXCLUSION_REASONS.fourEyes }],
  })

  test("parses, and its plaintext is canonical JSON", () => {
    expect(BackupBundleSchema.parse(bundle())).toEqual(bundle())
    expect(backupPlaintext(bundle())).toBe(canonicalJson(bundle()))
    expect(JSON.parse(backupPlaintext(bundle())).format).toBe("mehen-backup/v1")
  })

  test("refuses a wrong format, an unknown member, too many items and a bad id", () => {
    expect(BackupBundleSchema.safeParse({ ...bundle(), format: "mehen-backup/v2" }).success).toBe(false)
    expect(BackupBundleSchema.safeParse({ ...bundle(), extra: 1 }).success).toBe(false)
    expect(BackupBundleSchema.safeParse({ ...bundle(), id: "snp_x" }).success).toBe(false)
    const item = bundle().items[0] as BackupBundle["items"][number]
    expect(BackupBundleSchema.safeParse({ ...bundle(), items: Array.from({ length: BACKUP_EXPORT_LIMITS.maxItems + 1 }, () => item) }).success).toBe(false)
  })

  test("the sidecar says what the file is with no slug, value or length inside", () => {
    const sidecar: BackupSidecar = { format: BACKUP_SIDECAR_FORMAT, id: "bkx_k2m9q4", workspace: { id: "tn_x", slug: "work", name: "Work" }, recipient: { id: "bkr_x", fingerprint: "f" }, exportedAt: "2026-11-01T09:00:00.000Z", items: 1, projects: 1, excluded: 1, ciphertext: { bytes: 400, sha256: "1".repeat(64) } }
    expect(BackupSidecarSchema.parse(sidecar)).toEqual(sidecar)
    for (const extra of [{ slugs: ["openai"] }, { plaintextBytes: 10 }]) expect(BackupSidecarSchema.safeParse({ ...sidecar, ...extra }).success).toBe(false)
  })
})

describe("layer 2: the export on the wire", () => {
  test("the ciphertext travels as standard padded base64, as `base64 -d` reads it", () => {
    for (const length of [0, 1, 2, 3, 4, 250]) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + 251) % 256)
      const text = backupCiphertextBase64(bytes)
      expect(text).toBe(Buffer.from(bytes).toString("base64"))
    }
  })

  test("the file is named for the workspace, the day and the export", () => {
    expect(backupExportFileName({ id: "bkx_k2m9q4", workspace: { id: "tn_x", slug: "work", name: "Work" }, exportedAt: "2026-11-01T23:59:00.000Z" })).toBe("mehen-work-2026-11-01-bkx_k2m9q4.age")
  })
})
