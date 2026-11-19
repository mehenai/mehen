import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { lstat, open, readdir, stat, symlink, unlink, utimes } from "node:fs/promises"
import { join } from "node:path"
import { type Ask, type AskUrl, approvalAsk, askUrl, policyAsk, enrolAsk, intakeAsk, reauthAsk } from "./ask.ts"
import { LOCK_WAIT_MS, type LedgerScope, REISSUE_MIN_REMAINING_MS, addLedgerEntry, findLedgerEntry, ledgerPath, pickLedgerEntry, pruneLedger, readLedger, reissuableEntry, remainingMs, removeLedgerEntries, removeLedgerEntry, writeLedger } from "./ledger.ts"
import { tempDir } from "./testing/run-mehen.ts"

const by = { device: "sam-mac-mini", session: "pi-4f2a" }
const now = new Date("2026-10-24T16:14:00Z")
const later = (minutes: number) => new Date(now.getTime() + minutes * 60_000).toISOString()
// The identity this ledger is read and written under; the enrol scope has no
// workspace or device yet.
const V: LedgerScope = { vaultUrl: "https://v", workspace: "tn_test00000001", device: "dev_test00000001", workspaceSlug: "space" }
const ENROL: LedgerScope = { vaultUrl: "https://v", workspace: null, device: null }
// Links are under the workspace's canonical slug (design 15.6); the enrol
// scope reads an enrolment's link under its recorded intent.
const link = (url: string): AskUrl => (askUrl(url, { vaultUrl: V.vaultUrl, workspaceSlug: "space" }) as { url: AskUrl }).url
const identity = { origin: V.vaultUrl, workspace: V.workspace, device: V.device }

const intake = intakeAsk({ id: "int_1", url: link("https://v/w/space/i/int_1"), name: "openai-new", kind: "api-key", provider: "openai", reason: "r", expiresAt: later(24 * 60), requestedBy: by })
const approval = approvalAsk({ id: "apr_1", url: link("https://v/w/space/a/apr_1"), summary: "Send", bindingCode: "K7Q2MX", expiresAt: later(58), requestedBy: by })
const enrol = enrolAsk({ id: "enr_1", url: link("https://v/w/space/e/ABCD2345"), name: "test-mac", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", expiresAt: later(15), requestedBy: by })
const jwk = { kty: "EC" as const, crv: "P-256" as const, x: "x".repeat(43), y: "y".repeat(43) }

let dir: { path: string; remove(): Promise<void> }
beforeEach(async () => {
  dir = await tempDir()
})
afterEach(() => dir.remove())

describe("ledger file", () => {
  test("lives at <config dir>/ledger.json, mode 0600, and a missing file is an empty ledger", async () => {
    expect(await readLedger(dir.path, V, now)).toEqual([])
    await addLedgerEntry(dir.path, V, { ask: intake, slug: "openai-new", command: "mehen request api-key --name openai-new", now })
    expect(ledgerPath(dir.path)).toBe(join(dir.path, "ledger.json"))
    expect((await stat(ledgerPath(dir.path))).mode & 0o777).toBe(0o600)
    const entries = await readLedger(dir.path, V, now)
    expect(entries).toHaveLength(1)
    expect(entries[0]).toEqual({ ask: intake, createdAt: now.toISOString(), ...identity, slug: "openai-new", command: "mehen request api-key --name openai-new" })
  })

  test("is written atomically: no temp file is left behind and the content is whole JSON", async () => {
    await addLedgerEntry(dir.path, V, { ask: intake, slug: "openai-new", now })
    await addLedgerEntry(dir.path, V, { ask: approval, now })
    expect(await readdir(dir.path)).toEqual(["ledger.json"])
    const parsed = JSON.parse(await Bun.file(ledgerPath(dir.path)).text()) as { entries: unknown[] }
    expect(parsed.entries).toHaveLength(2)
  })

  test("holds only the known fields: anything else on an ask or an entry is dropped before it hits the disk", async () => {
    const leaky = { ...intake, secret: "sk-should-never-be-written", check: { ...intake.check, token: "nope" } } as unknown as Ask
    await addLedgerEntry(dir.path, V, { ask: leaky, slug: "openai-new", now, ...({ value: "sk-also-never" } as object) })
    const text = await Bun.file(ledgerPath(dir.path)).text()
    expect(text).not.toContain("sk-should-never-be-written")
    expect(text).not.toContain("sk-also-never")
    expect(text).not.toContain("nope")
    expect(text).not.toContain("token")
  })

  test("an enrolment keeps the public JWK, the code, the name and the backend, and refuses a private key", async () => {
    await addLedgerEntry(dir.path, ENROL, { ask: enrol, enrol: { code: "ABCD2345", name: "test-mac", backend: "software", jwk, workspace: "space", team: null }, now })
    const [entry] = await readLedger(dir.path, ENROL, now)
    expect(entry?.enrol).toEqual({ code: "ABCD2345", name: "test-mac", backend: "software", jwk, workspace: "space", team: null })
    const withPrivate = { ...jwk, d: "d".repeat(43) }
    const enrolEntry = (patch: object) => ({ ask: enrol, createdAt: now.toISOString(), origin: V.vaultUrl, workspace: null, device: null, slug: null, command: null, enrol: { code: "A", name: "n", backend: "software", jwk, workspace: "space", team: null, ...patch } })
    expect(pickLedgerEntry(enrolEntry({ jwk: withPrivate }), ENROL)).toBeNull()
    // The workspace intent is part of the entry: without it a wait could not check the answer.
    expect(pickLedgerEntry(enrolEntry({ workspace: undefined }), ENROL)).toBeNull()
    expect(pickLedgerEntry(enrolEntry({ workspace: "Not A Slug" }), ENROL)).toBeNull()
    expect(pickLedgerEntry(enrolEntry({ team: 7 }), ENROL)).toBeNull()
    expect(pickLedgerEntry(enrolEntry({ team: "ci" }), ENROL)?.enrol?.team).toBe("ci")
  })

  test("a corrupt file or an entry that is not an ask reads as empty rather than being trusted", async () => {
    await Bun.write(ledgerPath(dir.path), "{ not json")
    expect(await readLedger(dir.path, V, now)).toEqual([])
    await Bun.write(ledgerPath(dir.path), JSON.stringify({ entries: [{ ask: { kind: "approval", id: "apr_x" }, createdAt: now.toISOString(), ...identity }, { ask: intake, createdAt: now.toISOString(), ...identity, slug: null, command: null }] }))
    const entries = await readLedger(dir.path, V, now)
    expect(entries.map((e) => e.ask.id)).toEqual(["int_1"])
  })

  test("adding the same id again replaces the earlier entry", async () => {
    await addLedgerEntry(dir.path, V, { ask: approval, now })
    await addLedgerEntry(dir.path, V, { ask: { ...approval, expiresAt: later(90) }, now })
    const entries = await readLedger(dir.path, V, now)
    expect(entries).toHaveLength(1)
    expect(entries[0]?.ask.expiresAt).toBe(later(90))
  })

  test("removeLedgerEntry drops one id and leaves the rest", async () => {
    await addLedgerEntry(dir.path, V, { ask: intake, slug: "openai-new", now })
    await addLedgerEntry(dir.path, V, { ask: approval, now })
    await removeLedgerEntry(dir.path, V, "apr_1", now)
    expect((await readLedger(dir.path, V, now)).map((e) => e.ask.id)).toEqual(["int_1"])
  })
})

describe("ledger links and the file itself", () => {
  test("an entry whose link is not on the vault is refused on read: foreign origin, lookalike host, userinfo, another port, http, a hidden character", async () => {
    const entry = (url: string) => ({ ask: { ...approval, id: "apr_ok", url }, createdAt: now.toISOString(), ...identity, slug: null, command: null })
    const hostile = [
      "https://evil.example/a/apr_1",
      "https://v.evil.example/a/apr_1",
      "https://evil.example@v/a/apr_1",
      "https://v:8443/a/apr_1",
      "http://v/a/apr_1",
      "https://v/w/space/a/apr_1\u200b",
    ]
    await Bun.write(ledgerPath(dir.path), JSON.stringify({ entries: [...hostile.map(entry), entry("https://v/w/space/a/apr_ok")] }))
    const entries = await readLedger(dir.path, V, now)
    expect(entries.map((e) => e.ask.url)).toEqual(["https://v/w/space/a/apr_ok"])
    for (const url of hostile) expect(pickLedgerEntry(entry(url), V)).toBeNull()
  })

  test("a hostile link cannot be written either, and a ledger read for another vault URL is empty", async () => {
    await expect(addLedgerEntry(dir.path, V, { ask: { ...approval, url: "https://evil.example/a/apr_1" }, now })).rejects.toThrow("whose link is on the vault")
    await addLedgerEntry(dir.path, V, { ask: approval, now })
    expect(await readLedger(dir.path, { ...V, vaultUrl: "https://other.example" }, now)).toEqual([])
  })

  test("an entry is read only under the identity it was written under: another workspace, device or the enrol scope sees nothing", async () => {
    await addLedgerEntry(dir.path, V, { ask: approval, now })
    await addLedgerEntry(dir.path, ENROL, { ask: enrol, enrol: { code: "ABCD2345", name: "test-mac", backend: "software", jwk, workspace: "space", team: null }, now })
    expect((await readLedger(dir.path, V, now)).map((e) => e.ask.id)).toEqual(["apr_1"])
    expect((await readLedger(dir.path, ENROL, now)).map((e) => e.ask.id)).toEqual(["enr_1"])
    expect(await readLedger(dir.path, { ...V, workspace: "tn_other00000001" }, now)).toEqual([])
    expect(await readLedger(dir.path, { ...V, device: "dev_other00000001" }, now)).toEqual([])
    // The same workspace id at another origin is another identity.
    expect(await readLedger(dir.path, { ...V, vaultUrl: "https://v.other" }, now)).toEqual([])
    const entries = JSON.parse(await Bun.file(ledgerPath(dir.path)).text()) as { entries: Record<string, unknown>[] }
    expect(entries.entries.map((e) => [e.origin, e.workspace, e.device])).toEqual([[V.vaultUrl, V.workspace, V.device], [V.vaultUrl, null, null]])
    // A hand-edited identity on an otherwise good entry is dropped, never adopted.
    expect(pickLedgerEntry({ ask: approval, createdAt: now.toISOString(), ...identity, workspace: "tn_other00000001", slug: null, command: null }, V)).toBeNull()
    expect(pickLedgerEntry({ ask: approval, createdAt: now.toISOString(), ...identity, origin: undefined, slug: null, command: null }, V)).toBeNull()
  })

  // Supplied provenance must be the reading scope's own identity
  // and name the accepted link's slug; the link's route must be the ask's
  // kind and id. Any disagreement drops the entry: nothing is stripped or
  // kept as evidence.
  test("foreign inner provenance with a matching outer identity drops the entry; valid provenance round-trips", async () => {
    const context = { origin: V.vaultUrl, workspace: { id: V.workspace as string, slug: "space", name: "Space" }, device: V.device as string }
    const entry = (patch: object) => ({ ask: { ...approval, context: { ...context, ...patch } }, createdAt: now.toISOString(), ...identity, slug: null, command: null })
    expect(pickLedgerEntry(entry({}), V)?.ask.context).toEqual(context)
    for (const foreign of [
      { workspace: { ...context.workspace, id: "tn_other00000001" } },
      { workspace: { ...context.workspace, slug: "other-space" } },
      { device: "dev_other00000001" },
      { origin: "https://v.other" },
      { workspace: null },
      { workspace: "space" },
      { device: 7 },
    ]) {
      expect(pickLedgerEntry(entry(foreign), V)).toBeNull()
    }
    // Stored under the file and read back: the foreign one is gone, the valid one stays.
    await Bun.write(ledgerPath(dir.path), JSON.stringify({ entries: [entry({}), { ...entry({ workspace: { ...context.workspace, id: "tn_other00000001" } }), ask: { ...approval, id: "apr_2", url: approval.url.replace("apr_1", "apr_2"), context: { ...context, workspace: { ...context.workspace, id: "tn_other00000001" } } } }] }))
    expect((await readLedger(dir.path, V, now)).map((e) => e.ask.id)).toEqual(["apr_1"])
    // Under the enrol scope, provenance names no workspace or device, and a workspace there refuses.
    const enrolEntry = { ask: { ...enrol, context: { origin: V.vaultUrl, workspace: null, device: null } }, createdAt: now.toISOString(), origin: V.vaultUrl, workspace: null, device: null, slug: null, command: null, enrol: { code: "ABCD2345", name: "n", backend: "software", jwk, workspace: "space", team: null } }
    expect(pickLedgerEntry(enrolEntry, ENROL)?.ask.context).toEqual({ origin: V.vaultUrl, workspace: null, device: null })
    expect(pickLedgerEntry({ ...enrolEntry, ask: { ...enrolEntry.ask, context } }, ENROL)).toBeNull()
  })

  test("a link on another kind's route or another ask's id drops the entry, for every kind", () => {
    const at = (path: string) => link(`${V.vaultUrl}/w/space${path}`)
    const ok = (ask: Ask) => pickLedgerEntry({ ask, createdAt: now.toISOString(), ...identity, slug: null, command: null }, V)
    expect(ok(approval)).not.toBeNull()
    expect(ok({ ...approval, url: at("/a/apr_other") })).toBeNull()
    expect(ok({ ...approval, url: at("/i/apr_1") })).toBeNull()
    expect(ok({ ...approval, url: at("/c/con_1") })).toBeNull()
    expect(ok({ ...intake, url: at("/i/int_other") })).toBeNull()
    expect(ok({ ...intake, url: at("/a/apr_1") })).toBeNull()
    expect(ok(intake)).not.toBeNull()
    expect(ok({ ...approval, url: at("/") })).toBeNull()
    expect(ok({ ...approval, url: at("/items/openai") })).toBeNull()
    // The enrolment code is the one exception: its route carries the code, not the enr_ id.
    const enrolled = (ask: Ask, intent: string) => pickLedgerEntry({ ask, createdAt: now.toISOString(), origin: V.vaultUrl, workspace: null, device: null, slug: null, command: null, enrol: { code: "ABCD2345", name: "n", backend: "software", jwk, workspace: intent, team: null } }, ENROL)
    expect(enrolled(enrol, "space")).not.toBeNull()
    expect(enrolled({ ...enrol, url: at("/a/apr_1") }, "space")).toBeNull()
    expect(enrolled(enrol, "other-space")).toBeNull()
    // A reconnect may point at the credential's page only with no id of its own.
    const reconnect = reauthAsk({ id: "con_9", url: at("/c/con_9"), name: "gmail", provider: "google-gmail", account: null, expiresAt: null, requestedBy: by })
    expect(ok(reconnect)).not.toBeNull()
    expect(ok({ ...reconnect, id: "", url: at("/items/gmail-alex") })).not.toBeNull()
    expect(ok({ ...reconnect, url: at("/items/gmail-alex") })).toBeNull()
  })

  test("a write under one identity keeps the other identities' entries in the same file", async () => {
    await addLedgerEntry(dir.path, ENROL, { ask: enrol, enrol: { code: "ABCD2345", name: "test-mac", backend: "software", jwk, workspace: "space", team: null }, now })
    await addLedgerEntry(dir.path, V, { ask: approval, now })
    await removeLedgerEntry(dir.path, V, "apr_1", now)
    await writeLedger(dir.path, V, [{ ask: intake, createdAt: now.toISOString(), ...identity, slug: "openai-new", command: null }], now)
    expect((await readLedger(dir.path, ENROL, now)).map((e) => e.ask.id)).toEqual(["enr_1"])
    expect((await readLedger(dir.path, V, now)).map((e) => e.ask.id)).toEqual(["int_1"])
  })

  test("a symbolic link in place of the ledger is refused with a warning, read as empty, and replaced by a real file on write", async () => {
    const target = join(dir.path, "elsewhere.json")
    await Bun.write(target, JSON.stringify({ entries: [{ ask: approval, createdAt: now.toISOString(), ...identity, slug: null, command: null }] }))
    await symlink(target, ledgerPath(dir.path))
    const stderr: string[] = []
    const original = process.stderr.write.bind(process.stderr)
    process.stderr.write = ((chunk: string | Uint8Array) => {
      stderr.push(String(chunk))
      return true
    }) as typeof process.stderr.write
    try {
      expect(await readLedger(dir.path, V, now)).toEqual([])
    } finally {
      process.stderr.write = original
    }
    expect(stderr.join("")).toContain("is a symbolic link")
    await addLedgerEntry(dir.path, V, { ask: intake, slug: "openai-new", now })
    const info = await lstat(ledgerPath(dir.path))
    expect(info.isSymbolicLink()).toBe(false)
    expect(info.mode & 0o777).toBe(0o600)
    expect(JSON.parse(await Bun.file(target).text()).entries).toHaveLength(1)
    expect((await readLedger(dir.path, V, now)).map((e) => e.ask.id)).toEqual(["int_1"])
  })
})

describe("prune", () => {
  test("drops entries whose link has expired, on read and on write", async () => {
    await writeLedger(dir.path, V, [
      { ask: intake, createdAt: now.toISOString(), ...identity, slug: "openai-new", command: null },
      { ask: { ...approval, id: "apr_old", expiresAt: later(-1) }, createdAt: now.toISOString(), ...identity, slug: null, command: null },
    ], now)
    expect((await readLedger(dir.path, V, now)).map((e) => e.ask.id)).toEqual(["int_1"])
    expect((await readLedger(dir.path, V, new Date(now.getTime() + 25 * 3_600_000))).map((e) => e.ask.id)).toEqual([])
  })

  test("an entry with no expiry is kept for its kind's documented lifetime from creation", () => {
    const noExpiry = { ask: { ...approval, expiresAt: null }, createdAt: now.toISOString(), ...identity, slug: null, command: null }
    expect(remainingMs(noExpiry, now)).toBe(60 * 60_000)
    expect(pruneLedger([noExpiry], new Date(now.getTime() + 59 * 60_000))).toHaveLength(1)
    expect(pruneLedger([noExpiry], new Date(now.getTime() + 61 * 60_000))).toHaveLength(0)
    const intakeNoExpiry = { ask: { ...intake, expiresAt: null }, createdAt: now.toISOString(), ...identity, slug: "openai-new", command: null }
    expect(remainingMs(intakeNoExpiry, now)).toBe(24 * 3_600_000)
  })
})

describe("lookup", () => {
  const entries = [
    { ask: intake, createdAt: now.toISOString(), ...identity, slug: "openai-new", command: null },
    { ask: approval, createdAt: now.toISOString(), ...identity, slug: null, command: null },
  ]

  test("finds by id, then by the slug the ask creates", () => {
    expect(findLedgerEntry(entries, "apr_1")?.ask.id).toBe("apr_1")
    expect(findLedgerEntry(entries, "openai-new")?.ask.id).toBe("int_1")
    expect(findLedgerEntry(entries, "nothing")).toBeNull()
  })

  test("re-issue: an open intake for the slug counts only while it has more than two minutes left", () => {
    expect(REISSUE_MIN_REMAINING_MS).toBe(120_000)
    expect(reissuableEntry(entries, "intake", "openai-new", now)?.ask.id).toBe("int_1")
    expect(reissuableEntry(entries, "connect", "openai-new", now)).toBeNull()
    expect(reissuableEntry(entries, "intake", "other", now)).toBeNull()
    const nearlyGone = new Date(Date.parse(intake.expiresAt as string) - 60_000)
    expect(reissuableEntry(entries, "intake", "openai-new", nearlyGone)).toBeNull()
    const justEnough = new Date(Date.parse(intake.expiresAt as string) - REISSUE_MIN_REMAINING_MS - 1000)
    expect(reissuableEntry(entries, "intake", "openai-new", justEnough)?.ask.id).toBe("int_1")
  })
})


describe("ledger process lock", () => {
  const lockPath = () => `${ledgerPath(dir.path)}.lock`

  async function holdLock(ageMs = 0, pid = process.pid): Promise<void> {
    const handle = await open(lockPath(), "wx", 0o600)
    await handle.writeFile(JSON.stringify({ pid, at: new Date(Date.now() - ageMs).toISOString() }))
    await handle.close()
    if (ageMs) await utimes(lockPath(), new Date(Date.now() - ageMs), new Date(Date.now() - ageMs))
  }

  // Each child says ready once ledger.ts is loaded and starts when its stdin
  // closes, so both queue their writes together however slowly they load.
  // Twenty writes queue on one lock, which on a loaded runner can take longer
  // than the default 2 s wait, so the children wait up to 20 s.
  test("two real processes interleave 20 adds and removals without losing unrelated entries", async () => {
    await writeLedger(dir.path, V, Array.from({ length: 10 }, (_, i) => ({ ask: { ...approval, id: `apr_old${i}`, url: approval.url.replace("apr_1", `apr_old${i}`) }, createdAt: now.toISOString(), ...identity, slug: null, command: null })), now)
    const script = `
      import { addLedgerEntry, removeLedgerEntry } from ${JSON.stringify(new URL("./ledger.ts", import.meta.url).href)};
      const { dir, vault, ask, now, offset } = JSON.parse(process.argv[1]);
      const lockWaitMs = 20_000;
      process.stdout.write("ready\\n");
      await Bun.stdin.text();
      await Promise.all(Array.from({ length: 5 }, async (_, i) => {
        const n = i + offset;
        await addLedgerEntry(dir, vault, { ask: { ...ask, id: "apr_new" + n, url: ask.url.replace("apr_1", "apr_new" + n) }, now: new Date(now), lockWaitMs });
        await removeLedgerEntry(dir, vault, "apr_old" + n, new Date(now), { lockWaitMs });
      }));
    `
    const children = [0, 5].map((offset) => Bun.spawn([process.execPath, "--eval", script, JSON.stringify({ dir: dir.path, vault: V, ask: approval, now, offset })], { stdin: "pipe", stdout: "pipe", stderr: "pipe", timeout: 30_000 }))
    const firstLine = async (stream: ReadableStream<Uint8Array>) => {
      const reader = stream.getReader()
      let text = ""
      while (!text.includes("\n")) {
        const { value, done } = await reader.read()
        if (done) break
        text += new TextDecoder().decode(value)
      }
      reader.releaseLock()
      return text
    }
    expect(await Promise.all(children.map((child) => firstLine(child.stdout)))).toEqual(["ready\n", "ready\n"])
    for (const child of children) child.stdin.end()
    for (const child of children) {
      expect(await child.exited).toBe(0)
      expect(await new Response(child.stderr).text()).toBe("")
    }
    expect((await readLedger(dir.path, V, now)).map((entry) => entry.ask.id).sort()).toEqual(Array.from({ length: 10 }, (_, i) => `apr_new${i}`))
    expect(await readdir(dir.path)).toEqual(["ledger.json"])
  }, 30_000)

  test("recovers an old lock left by a dead process, including concurrent reapers", async () => {
    const child = Bun.spawn([process.execPath, "--eval", ""], { stdout: "ignore", stderr: "ignore" })
    await child.exited
    await holdLock(11_000, child.pid)
    await Promise.all([addLedgerEntry(dir.path, V, { ask: intake, now }), addLedgerEntry(dir.path, V, { ask: approval, now })])
    expect((await readLedger(dir.path, V, now)).map((entry) => entry.ask.id).sort()).toEqual(["apr_1", "int_1"])
    expect(await readdir(dir.path)).toEqual(["ledger.json"])
  })

  test("a reaper that crashed mid-check does not stop a dead writer's lock being recovered", async () => {
    const child = Bun.spawn([process.execPath, "--eval", ""], { stdout: "ignore", stderr: "ignore" })
    await child.exited
    await holdLock(11_000, child.pid)
    await Bun.write(`${lockPath()}.reap`, "")
    const old = new Date(Date.now() - 11_000)
    await utimes(`${lockPath()}.reap`, old, old)
    await addLedgerEntry(dir.path, V, { ask: approval, now })
    expect((await readLedger(dir.path, V, now)).map((entry) => entry.ask.id)).toEqual(["apr_1"])
    expect(await readdir(dir.path)).toEqual(["ledger.json"])
  })

  test("a fresh reap guard is left to its reaper", async () => {
    const child = Bun.spawn([process.execPath, "--eval", ""], { stdout: "ignore", stderr: "ignore" })
    await child.exited
    await holdLock(11_000, child.pid)
    await Bun.write(`${lockPath()}.reap`, "")
    const original = process.stderr.write
    let warned = ""
    process.stderr.write = ((chunk: string) => { warned += chunk; return true }) as typeof process.stderr.write
    try {
      await addLedgerEntry(dir.path, V, { ask: approval, now })
    } finally {
      process.stderr.write = original
      await unlink(`${lockPath()}.reap`).catch(() => undefined)
      await unlink(lockPath()).catch(() => undefined)
    }
    expect(warned).toContain("ledger.json is busy")
    expect(await readLedger(dir.path, V, now)).toEqual([])
  })

  test("recovers an interrupted empty lock only after it is stale", async () => {
    await Bun.write(lockPath(), "")
    const old = new Date(Date.now() - 11_000)
    await utimes(lockPath(), old, old)
    await addLedgerEntry(dir.path, V, { ask: approval, now })
    expect((await readLedger(dir.path, V, now)).map((entry) => entry.ask.id)).toEqual(["apr_1"])
    expect(await readdir(dir.path)).toEqual(["ledger.json"])
  })

  test("waits for a fresh lock before reading, then preserves that writer's entry", async () => {
    await holdLock()
    let finished = false
    const adding = addLedgerEntry(dir.path, V, { ask: approval, now }).then(() => { finished = true })
    try {
      await Bun.sleep(100)
      expect(finished).toBe(false)
      expect((await stat(lockPath())).mode & 0o777).toBe(0o600)
      await Bun.write(ledgerPath(dir.path), JSON.stringify({ entries: [{ ask: intake, createdAt: now.toISOString(), ...identity, slug: null, command: null }] }))
    } finally {
      await unlink(lockPath()).catch(() => undefined)
      await adding
    }
    expect((await readLedger(dir.path, V, now)).map((entry) => entry.ask.id).sort()).toEqual(["apr_1", "int_1"])
  })

  test("an old lock belonging to a live process times out safely for every write entry point", async () => {
    await addLedgerEntry(dir.path, V, { ask: intake, now })
    const before = await Bun.file(ledgerPath(dir.path)).text()
    await holdLock(11_000)
    const stderr: string[] = []
    const original = process.stderr.write
    process.stderr.write = ((chunk: string | Uint8Array) => { stderr.push(String(chunk)); return true }) as typeof process.stderr.write
    const started = performance.now()
    try {
      const [entry] = await Promise.all([
        addLedgerEntry(dir.path, V, { ask: { ...approval, what: "secret-sentinel" }, now }),
        removeLedgerEntry(dir.path, V, intake.id, now),
        removeLedgerEntries(dir.path, V, () => true, now),
        writeLedger(dir.path, V, []),
      ])
      expect(entry.ask.id).toBe(approval.id)
    } finally {
      process.stderr.write = original
    }
    expect(LOCK_WAIT_MS).toBe(2_000)
    expect(performance.now() - started).toBeGreaterThanOrEqual(1_900)
    expect(performance.now() - started).toBeLessThan(2_500)
    expect(await Bun.file(ledgerPath(dir.path)).text()).toBe(before)
    expect(await Bun.file(lockPath()).exists()).toBe(true)
    expect(stderr).toHaveLength(4)
    expect(new Set(stderr).size).toBe(1)
    expect(stderr[0]).toBe("mehen: warning: ledger.json is busy or unavailable; the command succeeded without updating the local ask ledger.\n")
    expect(stderr.join("")).not.toContain(dir.path)
    expect(stderr.join("")).not.toContain("secret-sentinel")
  })

  test("an unavailable lock skips bookkeeping without leaking filesystem errors", async () => {
    await symlink("/not-a-real-ledger-lock", lockPath())
    const stderr: string[] = []
    const original = process.stderr.write
    process.stderr.write = ((chunk: string | Uint8Array) => { stderr.push(String(chunk)); return true }) as typeof process.stderr.write
    try {
      await addLedgerEntry(lockPath(), V, { ask: approval, now })
    } finally {
      process.stderr.write = original
    }
    expect(stderr.join("")).toContain("without updating the local ask ledger")
    expect(stderr.join("")).not.toContain(dir.path)
    expect(await Bun.file(ledgerPath(dir.path)).exists()).toBe(false)
  })
})

test("policy asks round-trip in the current enrolment with locked add/remove", async () => {
  const ask = policyAsk({ id: "pol_x", url: link(`${V.vaultUrl}/w/space/p/pol_x`), summary: "Relax a route", bindingCode: "CODE", expiresAt: null, requestedBy: by })
  await Promise.all([addLedgerEntry(dir.path, V, { ask, now }), addLedgerEntry(dir.path, V, { ask: approval, now })])
  const entries = await readLedger(dir.path, V, now)
  expect(findLedgerEntry(entries, "pol_x")?.ask).toEqual(ask)
  expect(remainingMs(entries.find((e) => e.ask.id === "pol_x")!, now)).toBe(3_600_000)
  await removeLedgerEntry(dir.path, V, "pol_x", now)
  expect((await readLedger(dir.path, V, now)).map((e) => e.ask.id)).toEqual(["apr_1"])
})

test("ledger refuses policy asks with foreign origins or mismatched ids/routes", () => {
  const ask = policyAsk({ id: "pol_x", url: link(`${V.vaultUrl}/w/space/p/pol_x`), summary: "Relax a route", bindingCode: null, expiresAt: null, requestedBy: by })
  for (const extra of [{ id: "" }, { id: "apr_x" }, { url: `${V.vaultUrl}/w/space/p/pol_other` }, { url: `${V.vaultUrl}/w/space/a/apr_x` }, { url: `${V.vaultUrl}/p/pol_x` }, { url: "https://evil.example/p/pol_x" }]) {
    expect(pickLedgerEntry({ ask: { ...ask, ...extra }, createdAt: now.toISOString(), ...identity, slug: null, command: null }, V)).toBeNull()
  }
})
