import { afterEach, describe, expect, it, spyOn } from "bun:test"
import { mkdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs"
import * as fsPromises from "node:fs/promises"
import { join } from "node:path"
import type { CliError } from "../errors.ts"
import { tempDir } from "../run/fake-vault-api.ts"
import { OutputGuard } from "./output-guard.ts"
import { type ScanOptions, readScan, scan, scanCounts } from "./scan.ts"
import { archivedPath, readSource } from "./sources.ts"

const OPENAI = "sk-proj-SENTINELopenai0123456789abcdef"
const PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEASENTINELpem0123456789abcdefghijklmnopqrstuv\n-----END RSA PRIVATE KEY-----"
const TOKEN = "SENTINELtok9fQ2xLm7Rv4Kp8Zw3Hn6Jd1Bs5Yc0Ta"
const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function git(cwd: string, ...args: string[]): void {
  Bun.spawnSync(["git", ...args], { cwd, stdout: "ignore", stderr: "ignore" })
}

function machine(): string {
  const home = realpathSync(tempDir("mehen-adopt-scan-"))
  dirs.push(home)
  const repo = join(home, "code", "billing-api")
  mkdirSync(repo, { recursive: true })
  git(repo, "init", "-q")
  git(repo, "remote", "add", "origin", "git@github.com:acme/billing-api.git")
  writeFileSync(join(repo, ".env"), `OPENAI_API_KEY=${OPENAI}\nLOG_LEVEL=debug\nDATABASE_URL=postgres://u:SENTINELdbpass@db/x\n`)
  writeFileSync(join(repo, ".env.example"), "OPENAI_API_KEY=\n")
  mkdirSync(join(home, ".local-secrets"))
  writeFileSync(join(home, ".local-secrets", "openai.env"), `OPENAI_API_KEY=${OPENAI}\n`)
  return home
}

function options(home: string, overrides: Partial<ScanOptions> = {}): ScanOptions {
  return { home, machine: "test-mac", roots: [{ path: join(home, "code"), depth: 6 }, { path: join(home, ".local-secrets"), depth: 2 }], defaults: false, include: [], exclude: [], excludeDirs: [], guard: new OutputGuard(), ...overrides }
}

describe("scan", () => {
  it("finds names, classes and repos, and writes no value", async () => {
    const home = machine()
    const guard = new OutputGuard()
    const result = await scan(options(home, { guard }))
    const rows = result.entries.map((e) => [e.path.slice(home.length), e.variable, e.class, e.provider ?? e.kind, e.home])
    expect(rows).toEqual([
      ["/.local-secrets/openai.env", "OPENAI_API_KEY", "secret", "openai", "private"],
      ["/code/billing-api/.env", "OPENAI_API_KEY", "secret", "openai", "project"],
      ["/code/billing-api/.env", "LOG_LEVEL", "config", null, "project"],
      ["/code/billing-api/.env", "DATABASE_URL", "secret", "database-url", "project"],
    ])
    expect(result.entries[1]?.repo).toEqual({ root: join(home, "code", "billing-api"), remote: "github.com/acme/billing-api" })
    expect(JSON.stringify(result)).not.toContain("SENTINEL")
    expect(guard.clean(OPENAI)).toBe(false)
    expect(scanCounts(result)).toEqual({ files: 2, secrets: 3, distinct: 2, config: 1, unsupported: 0 })
  })

  // A scan written by 0.3.6 has no publicLooksSecret: it is not corrupt,
  // only older than the plan that reads it.
  it("says a scan without publicLooksSecret, configLooksSecret or liveKey was written by an older mehen, and anything else is not a scan file", async () => {
    const home = machine()
    const result = await scan(options(home))
    const older = join(home, "older-scan.json")
    writeFileSync(older, JSON.stringify({ ...result, entries: result.entries.map(({ publicLooksSecret: _, ...e }) => e) }), { mode: 0o600 })
    const refusal = await readScan(older).catch((error: unknown) => error as CliError)
    expect(refusal).toMatchObject({ message: `${older} was written by an older mehen; scan again.`, next: { command: "mehen adopt scan", say: "Scan again with this mehen; the plan is built from a fresh scan." } })
    // Nor one without liveKey: its plan could not tell which keys are live.
    const noLive = join(home, "no-live-scan.json")
    writeFileSync(noLive, JSON.stringify({ ...result, entries: result.entries.map(({ liveKey: _, ...e }) => e) }), { mode: 0o600 })
    await expect(readScan(noLive)).rejects.toThrow(`${noLive} was written by an older mehen; scan again.`)
    // Nor one without configLooksSecret: its plan could map config the vault refuses.
    const noConfig = join(home, "no-config-scan.json")
    writeFileSync(noConfig, JSON.stringify({ ...result, entries: result.entries.map(({ configLooksSecret: _, ...e }) => e) }), { mode: 0o600 })
    await expect(readScan(noConfig)).rejects.toThrow(`${noConfig} was written by an older mehen; scan again.`)
    const other = join(home, "other.json")
    writeFileSync(other, JSON.stringify({ version: 1, entries: "no" }), { mode: 0o600 })
    await expect(readScan(other)).rejects.toThrow(`${other} is not an adopt scan file.`)
    const current = join(home, "scan.json")
    writeFileSync(current, JSON.stringify(result), { mode: 0o600 })
    expect((await readScan(current)).entries).toHaveLength(result.entries.length)
  })

  it("records whether each secret is a live key, and writes no value", async () => {
    const home = machine()
    const repo = join(home, "code", "billing-api")
    writeFileSync(join(repo, ".env.local"), "STRIPE_SECRET_KEY=sk_live_SENTINELstripe0123456789\nSTRIPE_TEST_KEY=sk_test_SENTINELstripe0123456789\n")
    const result = await scan(options(home))
    expect(result.entries.map((e) => [e.variable, e.liveKey])).toEqual([["OPENAI_API_KEY", false], ["OPENAI_API_KEY", false], ["LOG_LEVEL", false], ["DATABASE_URL", false], ["STRIPE_SECRET_KEY", true], ["STRIPE_TEST_KEY", false]])
    const file = join(home, "scan.json")
    writeFileSync(file, JSON.stringify(result), { mode: 0o600 })
    const text = readFileSync(file, "utf8")
    expect(text).not.toContain("SENTINEL")
    expect((await readScan(file)).entries.map((e) => e.liveKey)).toEqual(result.entries.map((e) => e.liveKey))
    // Adopt reconcile: each entry carries its file's mtime, which submit sends.
    expect(result.entries.map((e) => e.mtime)).toEqual(result.entries.map((e) => statSync(e.path).mtime.toISOString()))
    expect((await readScan(file)).entries.map((e) => e.mtime)).toEqual(result.entries.map((e) => e.mtime))
    // A scan 0.3.15 or earlier wrote has none and still loads.
    writeFileSync(file, JSON.stringify({ ...result, entries: result.entries.map(({ mtime: _, ...e }) => e) }), { mode: 0o600 })
    expect((await readScan(file)).entries.map((e) => e.mtime)).toEqual(result.entries.map(() => undefined))
  })

  // A settings file that names the variable holding a token (pi's
  // `"botTokenEnv": "SLACK_BOT_TOKEN"`) beside the .env that sets it: the
  // name is unknown-class, so it was a needle, and the scan stopped on its
  // own output.
  it("writes the scan when one file's value is another file's variable name", async () => {
    const home = machine()
    const app = join(home, "code", "billing-api")
    writeFileSync(join(app, "settings.json"), JSON.stringify({ slack: { botTokenEnv: "SLACK_BOT_TOKEN" }, providers: { ollama: { apiKey: "ollama" } } }))
    writeFileSync(join(app, ".env.local"), "SLACK_BOT_TOKEN=xoxb-SENTINEL-0123456789-abcdefghij\n")
    const guard = new OutputGuard()
    const result = await scan(options(home, { guard, include: ["**/settings.json"] }))
    expect(result.entries.map((e) => e.variable ?? e.pointer)).toContain("/slack/botTokenEnv")
    const text = JSON.stringify(result)
    expect(text).toContain("SLACK_BOT_TOKEN")
    expect(guard.clean(text)).toBe(true)
    expect(guard.clean("xoxb-SENTINEL-0123456789-abcdefghij")).toBe(false)
  })

  it("labels equal values alike, with labels that differ from run to run", async () => {
    const home = machine()
    const first = await scan(options(home))
    const second = await scan(options(home))
    const labels = (r: typeof first) => r.entries.filter((e) => e.variable === "OPENAI_API_KEY").map((e) => e.dup)
    const [a, b] = labels(first)
    expect(a).toMatch(/^d[a-z2-7]{6}$/)
    expect(a).toBe(b as string)
    expect(labels(second)[0]).not.toBe(a as string)
    expect(first.entries.find((e) => e.variable === "DATABASE_URL")?.dup).toBeNull()
    expect(first.entries.map((e) => e.id)).toEqual(second.entries.map((e) => e.id))
  })

  it("skips symlinks out of the root, big files, binaries and other users' files", async () => {
    const home = machine()
    const outside = join(home, "outside.env")
    writeFileSync(outside, "SECRET_KEY=abc\n")
    symlinkSync(outside, join(home, "code", "billing-api", ".env.linked"))
    writeFileSync(join(home, "code", "big.env"), `A=${"x".repeat(1024 * 1024)}\n`)
    writeFileSync(join(home, "code", "bin.env"), new Uint8Array([65, 61, 0, 1, 2]))
    const result = await scan(options(home))
    expect(result.skipped.map((s) => [s.path.slice(home.length), s.why]).sort()).toEqual([
      ["/code/big.env", "over 1 MiB"],
      ["/code/billing-api/.env.linked", "a symlink out of the root"],
      ["/code/bin.env", "binary"],
    ])
    const getuid = process.getuid
    process.getuid = () => 4242
    try {
      expect(await readSource(join(home, "code", "billing-api", ".env"))).toEqual({ ok: false, why: "owned by another user" })
    } finally {
      process.getuid = getuid
    }
    expect(await readSource(join(home, "code", "billing-api", ".env.linked"))).toEqual({ ok: false, why: "a symlink" })
  })

  it("refuses a file swapped between the lstat and the open", async () => {
    const home = machine()
    const path = join(home, "code", "billing-api", ".env")
    const real = await fsPromises.lstat(path)
    const swapped = spyOn(fsPromises, "lstat").mockImplementation((async () => Object.assign(Object.create(Object.getPrototypeOf(real)), real, { ino: real.ino + 1 })) as unknown as typeof fsPromises.lstat)
    try {
      expect(await readSource(path)).toEqual({ ok: false, why: "changed while it was read" })
    } finally {
      swapped.mockRestore()
    }
    expect((await readSource(path)).ok).toBe(true)
  })

  it("marks archived paths stale, and a value superseded only by a newer file in the same place", async () => {
    const home = machine()
    const old = join(home, "code", "archive", "old-thing")
    mkdirSync(old, { recursive: true })
    writeFileSync(join(old, ".env"), "OPENAI_API_KEY=sk-proj-SENTINELolder0123456789abcdef\n")
    const past = new Date(Date.now() - 400 * 24 * 3_600_000)
    const { utimesSync } = await import("node:fs")
    utimesSync(join(old, ".env"), past, past)
    writeFileSync(join(home, ".local-secrets", "openai-old.env"), "OPENAI_API_KEY=sk-proj-SENTINELolder0123456789abcdef\n")
    utimesSync(join(home, ".local-secrets", "openai-old.env"), new Date(Date.now() - 86_400_000), new Date(Date.now() - 86_400_000))
    const result = await scan(options(home))
    const stale = (path: string) => result.entries.find((e) => e.path === path)?.stale
    expect(stale(join(old, ".env"))).toEqual(["file unchanged for 12 months", "archived path"])
    expect(stale(join(home, ".local-secrets", "openai-old.env"))).toEqual(["superseded by a newer file"])
    expect(stale(join(home, ".local-secrets", "openai.env"))).toEqual([])
  })

  it("marks a folder named _archive or .old as archived, whatever its file times", async () => {
    const home = machine()
    for (const folder of ["_archive", ".old"]) {
      const dir = join(home, "code", folder, "billing-api")
      mkdirSync(dir, { recursive: true })
      writeFileSync(join(dir, ".env"), `STRIPE_SECRET_KEY=sk_live_SENTINEL${folder.replace(/\W/g, "")}0123456789abcdef\n`)
    }
    const result = await scan(options(home))
    const stale = (path: string) => result.entries.find((e) => e.path === path)?.stale
    expect(stale(join(home, "code", "_archive", "billing-api", ".env"))).toEqual(["archived path"])
    expect(stale(join(home, "code", ".old", "billing-api", ".env"))).toEqual(["archived path"])
  })

  it("marks a folder with a retirement or backup suffix as archived, not a bare word inside a name", async () => {
    const home = "/Users/alex"
    for (const folder of [".config/ci-runner.retired-20261003", ".config/ci-runner.retired", "code/app.bak", "code/app.BACKUP", "code/config.old", "code/billing-old", "code/app.orig", "code/app~"]) {
      expect([folder, archivedPath(join(home, folder, ".env"))]).toEqual([folder, true])
    }
    for (const folder of ["code/oldfield", "code/backup-tool", "code/bakery", "code/retired-tools", "code/app.retirement", "code/golden-old-api", "code/app.older"]) {
      expect([folder, archivedPath(join(home, folder, ".env"))]).toEqual([folder, false])
    }
    expect(archivedPath(join(home, "code", "billing-api", ".env.bak"))).toBe(false)
    const machineHome = machine()
    const retired = join(machineHome, "code", "ci-runner.retired-20261003")
    mkdirSync(retired, { recursive: true })
    writeFileSync(join(retired, ".env"), "STRIPE_SECRET_KEY=sk_live_SENTINELretired0123456789abcdef\n")
    const result = await scan(options(machineHome))
    expect(result.entries.find((e) => e.path === join(retired, ".env"))?.stale).toEqual(["archived path"])
  })

  // Seen in review: the file rule took keys.env.bak-20261027, but the folder
  // rule left app.bak-20261027/ live.
  it("marks a folder with a suffix and a date or number after it as archived", () => {
    const home = "/Users/alex"
    for (const folder of ["code/app.bak-20261027", "code/config.old-2024", "code/app.backup.1", "code/app.orig-2", ".config/ci-runner.retired.2", "code/app.BAK.20261027"]) {
      expect([folder, archivedPath(join(home, folder, ".env"))]).toEqual([folder, true])
    }
    for (const folder of ["code/app.older", "code/app.bakery", "code/app.retirement", "code/app.backups", "code/old-api", "code/app.oldfield"]) {
      expect([folder, archivedPath(join(home, folder, ".env"))]).toEqual([folder, false])
    }
  })

  it("marks a folder retired with a dash or an underscore as archived, with or without a date after it", async () => {
    const home = "/Users/alex"
    for (const folder of [".config/ci-runner-retired", ".config/ci-runner_retired", ".config/ci-runner-retired-20261003", ".config/ci-runner_retired_20261003", ".config/ci-runner-retired.2", "code/app-RETIRED"]) {
      expect([folder, archivedPath(join(home, folder, ".env"))]).toEqual([folder, true])
    }
    for (const folder of ["code/retired-tools", "code/retired", "code/unretired", "code/app-retirement", "code/app_retiree"]) {
      expect([folder, archivedPath(join(home, folder, ".env"))]).toEqual([folder, false])
    }
    const machineHome = machine()
    const retired = join(machineHome, ".config", "ci-runner-retired-20261003")
    mkdirSync(retired, { recursive: true })
    writeFileSync(join(retired, ".env"), "STRIPE_SECRET_KEY=sk_live_SENTINELretired0123456789abcdef\n")
    const result = await scan(options(machineHome, { roots: [{ path: join(machineHome, ".config"), depth: 4 }] }))
    expect(result.entries.find((e) => e.path === join(retired, ".env"))?.stale).toEqual(["archived path"])
  })

  it("a -old folder that is itself a repo root with an origin stays live; one without an origin, or below such a repo, is archived", async () => {
    const home = "/Users/alex"
    const site = join(home, "code", "site-old")
    expect(archivedPath(join(site, ".env"), site)).toBe(false)
    expect(archivedPath(join(site, "web", ".env"), site)).toBe(false)
    expect(archivedPath(join(site, ".env"), null)).toBe(true)
    expect(archivedPath(join(site, "billing-old", ".env"), site)).toBe(true)
    expect(archivedPath(join(home, "code", "app.bak", ".env"), join(home, "code", "app.bak"))).toBe(true)
    const machineHome = machine()
    const live = join(machineHome, "code", "site-old")
    const dead = join(machineHome, "code", "billing-old")
    for (const dir of [live, dead]) {
      mkdirSync(dir, { recursive: true })
      Bun.spawnSync(["git", "init", "-q"], { cwd: dir })
      writeFileSync(join(dir, ".env"), `STRIPE_SECRET_KEY=sk_live_SENTINEL${dir.length}old0123456789abcdef\n`)
    }
    Bun.spawnSync(["git", "remote", "add", "origin", "https://github.com/acme/site-old"], { cwd: live })
    const result = await scan(options(machineHome))
    const stale = (dir: string) => result.entries.find((e) => e.path === join(dir, ".env"))?.stale ?? []
    expect(stale(live)).not.toContain("archived path")
    expect(stale(dead)).toContain("archived path")
  })

  it("reads no example settings, and marks test fixtures and backup copies stale", async () => {
    const home = machine()
    const repo = join(home, "code", "billing-api")
    writeFileSync(join(repo, "config.example.json"), JSON.stringify({ apiKey: "sk-proj-SENTINELexample0123456789abc" }))
    mkdirSync(join(repo, "tests"))
    writeFileSync(join(repo, "tests", ".env"), "OPENAI_API_KEY=sk-proj-SENTINELfixture0123456789abc\n")
    writeFileSync(join(home, ".local-secrets", "openai.env.bak-20261027"), `OPENAI_API_KEY=${OPENAI}\n`)
    const result = await scan(options(home))
    const stale = (path: string) => result.entries.find((e) => e.path === path)?.stale
    expect(result.entries.some((e) => e.path.endsWith("config.example.json"))).toBe(false)
    expect(stale(join(repo, "tests", ".env"))).toEqual(["test or example folder"])
    expect(stale(join(home, ".local-secrets", "openai.env.bak-20261027"))).toEqual(["backup copy"])
    expect(stale(join(home, ".local-secrets", "openai.env"))).toEqual([])
  })

  it("keeps another environment's or another repo's own value fresh", async () => {
    const home = machine()
    const repo = join(home, "code", "billing-api")
    writeFileSync(join(repo, ".env.production"), "OPENAI_API_KEY=sk-proj-SENTINELprod0123456789abcdefgh\n")
    const other = join(home, "code", "search-api")
    mkdirSync(other)
    git(other, "init", "-q")
    git(other, "remote", "add", "origin", "git@github.com:acme/search-api.git")
    writeFileSync(join(other, ".env"), "OPENAI_API_KEY=sk-proj-SENTINELsearch0123456789abcdef\n")
    const result = await scan(options(home))
    const openai = result.entries.filter((e) => e.variable === "OPENAI_API_KEY" && e.path.includes("/code/"))
    expect(openai.map((e) => [e.path.slice(home.length), e.stale])).toEqual([
      ["/code/billing-api/.env", []],
      ["/code/billing-api/.env.production", []],
      ["/code/search-api/.env", []],
    ])
  })

  it("keeps another folder's value in a monorepo fresh, and an override file is never superseded by its base", async () => {
    const home = machine()
    const repo = join(home, "code", "billing-api")
    const { utimesSync } = await import("node:fs")
    const yesterday = new Date(Date.now() - 86_400_000)
    for (const app of ["web", "api"]) mkdirSync(join(repo, "apps", app), { recursive: true })
    writeFileSync(join(repo, "apps", "web", ".env"), "OPENAI_API_KEY=sk-proj-SENTINELweb0123456789abcdefghi\n")
    utimesSync(join(repo, "apps", "web", ".env"), yesterday, yesterday)
    writeFileSync(join(repo, "apps", "api", ".env"), "OPENAI_API_KEY=sk-proj-SENTINELapi0123456789abcdefghi\n")
    writeFileSync(join(repo, ".env.local"), "OPENAI_API_KEY=sk-proj-SENTINELlocal0123456789abcdefgh\n")
    utimesSync(join(repo, ".env.local"), yesterday, yesterday)
    const result = await scan(options(home))
    const openai = result.entries.filter((e) => e.variable === "OPENAI_API_KEY" && e.path.startsWith(repo))
    expect(openai.map((e) => [e.path.slice(repo.length), e.stale])).toEqual([
      ["/.env", []],
      ["/.env.local", []],
      ["/apps/api/.env", []],
      ["/apps/web/.env", []],
    ])
  })

  // Seen on a real machine: an old worktree's .env with a rotated-away key
  // was as fresh as the main checkout's, so both were planned.
  it("supersedes an older worktree's or clone's value by a newer one of the same repository, and not an equal one", async () => {
    const home = machine()
    const repo = join(home, "code", "billing-api")
    const { utimesSync } = await import("node:fs")
    const yesterday = new Date(Date.now() - 86_400_000)
    const checkouts = [join(repo, ".worktrees", "rotated"), join(repo, ".worktrees", "same"), join(home, "code", "clone", "billing-api")]
    for (const dir of checkouts) {
      mkdirSync(dir, { recursive: true })
      git(dir, "init", "-q")
      git(dir, "remote", "add", "origin", "https://github.com/acme/billing-api")
    }
    const [rotated, same, clone] = checkouts as [string, string, string]
    writeFileSync(join(rotated, ".env"), "OPENAI_API_KEY=sk-proj-SENTINELrotated0123456789abcdef\n")
    writeFileSync(join(same, ".env"), `OPENAI_API_KEY=${OPENAI}\n`)
    mkdirSync(join(clone, "apps", "web"), { recursive: true })
    writeFileSync(join(clone, "apps", "web", ".env"), "OPENAI_API_KEY=sk-proj-SENTINELwebapp0123456789abcdef\n")
    for (const path of [join(rotated, ".env"), join(same, ".env"), join(clone, "apps", "web", ".env")]) utimesSync(path, yesterday, yesterday)
    const result = await scan(options(home))
    const openai = result.entries.filter((e) => e.variable === "OPENAI_API_KEY" && e.path.startsWith(join(home, "code")))
    expect(openai.map((e) => [e.path.slice(home.length), e.repo?.remote, e.stale])).toEqual([
      ["/code/billing-api/.env", "github.com/acme/billing-api", []],
      ["/code/billing-api/.worktrees/rotated/.env", "github.com/acme/billing-api", ["superseded by a newer file"]],
      ["/code/billing-api/.worktrees/same/.env", "github.com/acme/billing-api", []],
      ["/code/clone/billing-api/apps/web/.env", "github.com/acme/billing-api", []],
    ])
  })

  // Adopt reconcile: the gh login and a Google refresh token are connectors,
  // left in place and never uploaded, their values still held back.
  it("reads the gh login and a Google refresh token as connectors, and writes no value", async () => {
    const home = machine()
    mkdirSync(join(home, ".config", "gh"), { recursive: true })
    writeFileSync(join(home, ".config", "gh", "hosts.yml"), "github.com:\n    oauth_token: gho_SENTINELgh0123456789abcdef\n    user: alex\n")
    writeFileSync(join(home, "code", "billing-api", ".env.local"), "GMAIL_REFRESH_TOKEN=1//0gSENTINELrefresh0123456789abcdef\n")
    const guard = new OutputGuard()
    const result = await scan(options(home, { guard, defaults: true }))
    const connectors = result.entries.filter((e) => e.status === "connector").map((e) => [e.path.slice(home.length), e.variable ?? e.pointer, e.provider])
    expect(connectors).toEqual([["/.config/gh/hosts.yml", "/github.com/oauth_token", "github-oauth"], ["/code/billing-api/.env.local", "GMAIL_REFRESH_TOKEN", "google-gmail"]])
    const text = JSON.stringify(result)
    expect(text).not.toContain("SENTINEL")
    expect(guard.clean("gho_SENTINELgh0123456789abcdef")).toBe(false)
    expect(guard.clean("1//0gSENTINELrefresh0123456789abcdef")).toBe(false)
  })

  it("keeps a unit's EnvironmentFile with its unit when the walk reaches the file first", async () => {
    const home = machine()
    const config = join(home, ".config")
    mkdirSync(join(config, "app"), { recursive: true })
    mkdirSync(join(config, "systemd", "user"), { recursive: true })
    writeFileSync(join(config, "app", "svc.env"), "API_TOKEN=SENTINEL-token-0123456789abcdef\n")
    const unit = join(config, "systemd", "user", "app.service")
    writeFileSync(unit, "[Service]\nEnvironmentFile=%h/.config/app/svc.env\nExecStart=/usr/bin/app\n")
    const result = await scan(options(home, { roots: [{ path: config, depth: 4 }], platform: "linux" }))
    expect(result.entries.map((e) => [e.path.slice(home.length), e.variable, e.unit?.slice(home.length), e.category])).toEqual([["/.config/app/svc.env", "API_TOKEN", "/.config/systemd/user/app.service", "service"]])
    expect(result.units).toEqual([{ path: unit, type: "systemd", envFiles: [join(config, "app", "svc.env")] }])
  })

  // Seen on a real machine: a GitHub App key, an Apple .p8 and a bare token
  // kept as files in .local-secrets were read as NAME=value lines, gave one
  // error per line, and never reached the plan.
  it("reads a key kept on its own in .local-secrets whole, named by its file, and one error for a file it cannot read", async () => {
    const home = machine()
    const dir = join(home, ".local-secrets")
    writeFileSync(join(dir, "github-app.private-key.pem"), `${PEM}\n`)
    writeFileSync(join(dir, "ci-executor-token"), `${TOKEN}\n`)
    writeFileSync(join(dir, "vpn.md"), "# VPN\n\nuser: sam\npassword: SENTINEL-in-prose\n")
    writeFileSync(join(dir, "dump.json"), '{"access_token":"SENTINEL-dump-0123456789abcdef"}\n')
    const guard = new OutputGuard()
    const result = await scan(options(home, { guard }))
    const rows = result.entries.filter((e) => e.type === "secrets-file").map((e) => [e.path.slice(dir.length), e.variable, e.pointer, e.class, e.kind])
    expect(rows).toEqual([
      ["/ci-executor-token", null, "", "secret", "api-key"],
      ["/github-app.private-key.pem", null, "", "secret", "file"],
    ])
    expect(result.errors.map((e) => [e.path.slice(dir.length), e.line, e.why])).toEqual([
      ["/dump.json", 1, "a JSON file that is not settings: move what it holds by hand"],
      ["/vpn.md", 1, "not NAME=value lines, one key or one token: move what it holds by hand"],
    ])
    expect(JSON.stringify(result)).not.toContain("SENTINEL")
    expect(guard.clean(TOKEN)).toBe(false)
    expect(guard.clean(`${PEM}\n`)).toBe(false)
  })

  it("never enters an excluded folder", async () => {
    const home = machine()
    const result = await scan(options(home, { excludeDirs: [join(home, ".local-secrets")] }))
    expect(result.entries.some((e) => e.path.includes(".local-secrets"))).toBe(false)
  })

  it("never enters an excluded folder named through a symlink, nor reads one through a symlinked file", async () => {
    const home = machine()
    symlinkSync(join(home, ".local-secrets"), join(home, "secrets-link"))
    const fenced = join(home, "code", "billing-api", "fenced")
    mkdirSync(fenced)
    writeFileSync(join(fenced, ".env"), "SECRET_KEY=SENTINEL-fenced-0123456789\n")
    symlinkSync(join(fenced, ".env"), join(home, "code", "billing-api", ".env.fenced"))
    const result = await scan(options(home, { excludeDirs: [join(home, "secrets-link"), fenced] }))
    expect(result.entries.map((e) => e.path.slice(home.length))).toEqual(["/code/billing-api/.env", "/code/billing-api/.env", "/code/billing-api/.env"])
  })

  it("scans a single regular file passed as a root, and skips a symlinked root", async () => {
    const home = machine()
    const envPath = join(home, "code", "billing-api", ".env")
    const linkPath = join(home, "code", "billing-api", ".env.link")
    symlinkSync(envPath, linkPath)

    const single = await scan(options(home, { roots: [{ path: envPath, depth: 0 }], defaults: false }))
    expect(single.files).toBe(1)
    expect(single.entries.every((e) => e.path === envPath)).toBe(true)
    expect(JSON.stringify(single)).not.toContain("SENTINEL")

    const linked = await scan(options(home, { roots: [{ path: linkPath, depth: 0 }], defaults: false }))
    expect(linked.files).toBe(0)
    expect(linked.skipped).toContainEqual({ path: linkPath, why: "a symlink" })
  })
})
