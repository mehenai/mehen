// A machine about to adopt, in a temporary directory: a repo with a .env
// and a mehen.toml, a private secrets file, a service unit with its env
// file, the adopt plan naming them, a private MEHEN_HOME and a backup key;
// and an export from the vault as `mehen backup export` writes one.

import { mkdir, realpath, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { BACKUP_EXCLUSION_REASONS, BACKUP_FORMAT, BACKUP_SIDECAR_FORMAT, type BackupBundle, type BackupExportMeta, ageRecipientFingerprint, backupExportFileName, backupPlaintext, sha256Hex } from "@mehen/protocol/backup"
import { utf8 } from "@mehen/protocol/bytes"
import { ageEncrypt, newAgeIdentity } from "../backup/age.ts"
import { sidecarPathFor } from "../backup/check.ts"
import { tempDir } from "./run-mehen.ts"

export const SECRET_VALUE = "sk-proj-Zq81mXv0LpR7tYw3NcB5"
export const DB_PASSWORD = "hunter2-correct-horse-battery"

export type BackupFixture = {
  root: string
  home: string
  repo: string
  envFile: string
  manifest: string
  secretsFile: string
  unit: string
  serviceEnv: string
  planPath: string
  out: string
  env: Record<string, string>
  identity: string
  recipient: string
  remove(): Promise<void>
}

export async function writePlan(path: string, plan: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(plan, null, 2)}\n`, { mode: 0o600 })
}

export function planFor(f: Pick<BackupFixture, "repo" | "envFile" | "secretsFile" | "unit" | "serviceEnv">): Record<string, unknown> {
  return {
    version: 1,
    machine: "testbox",
    workspace: "acme",
    vault: "https://vault.example",
    scan: "2026-11-01T09:00:00Z",
    items: [{ ref: "a001", include: true, slug: "openai-dev", kind: "api-key", fields: { key: { from: ["s4k2q", "s9m1t"] } } }],
    sources: {
      s4k2q: { path: f.envFile, variable: "OPENAI_API_KEY", class: "secret" },
      s9m1t: { path: f.secretsFile, variable: "OPENAI_API_KEY", class: "secret" },
      s7p0a: { path: f.envFile, variable: "DATABASE_URL", class: "secret" },
    },
    repos: [{ root: f.repo, remote: "github.com/acme/billing-api", files: [] }],
    services: [{ unit: f.unit, envFile: f.serviceEnv, env: "local", vars: {} }],
  }
}

export async function backupFixture(): Promise<BackupFixture> {
  const dir = await tempDir()
  const root = await realpath(dir.path)
  const home = join(root, "mehen-home")
  const repo = join(root, "code", "billing-api")
  await mkdir(home, { mode: 0o700 })
  await mkdir(repo, { recursive: true })
  await mkdir(join(root, ".local-secrets"))
  await mkdir(join(root, "LaunchAgents"))
  await mkdir(join(root, "config"))
  const f = {
    root,
    home,
    repo,
    envFile: join(repo, ".env"),
    manifest: join(repo, "mehen.toml"),
    secretsFile: join(root, ".local-secrets", "openai.env"),
    unit: join(root, "LaunchAgents", "ai.test.mobile.plist"),
    serviceEnv: join(root, "config", "mobile.env"),
    planPath: join(root, "plan.json"),
    out: join(root, "Backups", "mehen"),
  }
  await writeFile(f.envFile, `OPENAI_API_KEY=${SECRET_VALUE}\nDATABASE_URL=postgres://app:${DB_PASSWORD}@db.internal/app\n`, { mode: 0o600 })
  await writeFile(f.manifest, 'workspace = "acme"\nproject = "billing-api"\n', { mode: 0o644 })
  await writeFile(f.secretsFile, `OPENAI_API_KEY=${SECRET_VALUE}\n`, { mode: 0o640 })
  await writeFile(f.unit, "<plist><dict><key>Label</key><string>ai.test.mobile</string></dict></plist>\n", { mode: 0o644 })
  await writeFile(f.serviceEnv, `TELEGRAM_BOT_TOKEN=${DB_PASSWORD}-tg\n`, { mode: 0o600 })
  await writePlan(f.planPath, planFor(f))
  const { identity, recipient } = await newAgeIdentity()
  return { ...f, env: { MEHEN_HOME: home, HOME: root }, identity, recipient, remove: () => dir.remove() }
}

// ---- exports from the vault -------------------------------------------------

export const DB_ODD = "it's \"quoted\" $HOME `x` \\ end\nsecond line\ttab"

// A mehen-backup/v1 bundle as the vault builds one: a project credential, a
// workspace one with a value no plain quoting survives, an OAuth
// connection without its values, a four-eyes credential left out, a plain
// variable the registrant overrides and a reference outside the scope.
export function sampleBundle(recipient: string, over: Partial<BackupBundle> = {}): BackupBundle {
  const item = (slug: string, kind: string, home: BackupBundle["items"][number]["home"], secretFields: Record<string, string>): BackupBundle["items"][number] => ({ id: `itm_${slug.replaceAll("-", "")}`, slug, kind, provider: null, account: null, home, tags: [], binding: null, policy: null, ceiling: "relay", injection: null, description: null, publicFields: { region: "eu" }, secretFields, version: 1, rotatedAt: null })
  return {
    format: BACKUP_FORMAT,
    id: "bkx_test0001",
    vault: "https://vault.example",
    workspace: { id: "tn_acme0001", slug: "acme", name: "Acme" },
    exportedAt: "2026-11-01T10:00:00.000Z",
    registrant: { member: "mem_alex", name: "Alex" },
    recipient: { id: "bkr_key00001", fingerprint: ageRecipientFingerprint(recipient) },
    auditHead: { seq: 42, hash: "9f2c" },
    items: [
      item("openai-dev", "api-key", { kind: "project", project: "prj_billing" }, { key: SECRET_VALUE }),
      item("db-main", "password", { kind: "workspace" }, { password: DB_ODD }),
      item("gmail-alex", "oauth-connection", { kind: "member", member: "mem_alex" }, {}),
    ],
    projects: [
      {
        id: "prj_billing",
        slug: "billing-api",
        remotes: ["github.com/acme/billing-api"],
        defaultEnv: "dev",
        environments: [
          { name: "dev", protected: false, fences: [], fourEyes: false, vars: { OPENAI_API_KEY: { item: "openai-dev", field: "key" }, DATABASE_PASSWORD: { item: "db-main", field: "password" }, LOG_LEVEL: { plain: "info" }, GMAIL_TOKEN: { item: "gmail-alex", field: "access_token" }, REGION: { item: "db-main", field: "region" } } },
          { name: "prod", protected: true, fences: [], fourEyes: true, vars: { STRIPE_KEY: { item: "stripe-live", field: "key", notExported: true }, LOG_LEVEL: { plain: "warn" } } },
        ],
      },
    ],
    overrides: [{ project: "prj_billing", environment: "dev", variable: "LOG_LEVEL", source: { kind: "plain", value: "debug" } }],
    excluded: [
      { slug: "gmail-alex", reason: BACKUP_EXCLUSION_REASONS.oauthConnection },
      { slug: "stripe-live", reason: BACKUP_EXCLUSION_REASONS.fourEyes },
    ],
    ...over,
  }
}

// The meta the vault reports beside the ciphertext of `bundle`.
export async function exportMeta(bundle: BackupBundle, ciphertext: Uint8Array): Promise<BackupExportMeta> {
  return { id: bundle.id, workspace: bundle.workspace, recipient: bundle.recipient, exportedAt: bundle.exportedAt, items: bundle.items.length, projects: bundle.projects.length, excluded: bundle.excluded.length, ciphertext: { bytes: ciphertext.length, sha256: await sha256Hex(ciphertext) } }
}

// Writes `bundle`, encrypted to `recipient`, and its sidecar into `dir` as
// `mehen backup export` does; the archive's path.
export async function writeExport(dir: string, bundle: BackupBundle, recipient: string): Promise<string> {
  const ciphertext = await ageEncrypt(utf8(backupPlaintext(bundle)), [recipient])
  const meta = await exportMeta(bundle, ciphertext)
  await mkdir(dir, { recursive: true })
  const archive = join(dir, backupExportFileName(meta))
  await writeFile(archive, ciphertext, { mode: 0o600 })
  await writeFile(sidecarPathFor(archive), `${JSON.stringify({ format: BACKUP_SIDECAR_FORMAT, ...meta }, null, 2)}\n`, { mode: 0o600 })
  return archive
}
