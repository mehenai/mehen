import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { mkdir, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { EXIT, UPSTREAM_HEADER } from "@mehen/protocol/api"
import { MOCK_EXPIRES_AT, MockVault, vaultError } from "../testing/mock-vault.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
  vault.overrides.clear()
  vault.sequences.clear()
  await vault.enrolSoftware(dir.path)
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

// The words a POSIX shell reads from a command line of bare words and
// single-quoted ones ('\'' for a quote), as mehen prints them.
function shellWords(line: string): string[] {
  const words: string[] = []
  let word: string | null = null
  for (let i = 0; i < line.length; i++) {
    const c = line[i] as string
    if (c === "'") {
      const end = line.indexOf("'", i + 1)
      word = (word ?? "") + line.slice(i + 1, end)
      i = end
    } else if (c === "\\") {
      word = (word ?? "") + line[++i]
    } else if (c === " ") {
      if (word !== null) words.push(word)
      word = null
    } else word = (word ?? "") + c
  }
  if (word !== null) words.push(word)
  return words
}

async function writePlan(plan: unknown, name = "plan.json"): Promise<string> {
  const folder = join(dir.path, "work")
  await mkdir(folder, { recursive: true })
  const path = join(folder, name)
  await writeFile(path, typeof plan === "string" ? plan : JSON.stringify(plan))
  return path
}

function bundleBodies(): { requests: Record<string, unknown>[]; reason?: string }[] {
  return vault.seen.filter((s) => s.method === "POST" && s.path === "/v1/approvals/bundles").map((s) => JSON.parse(s.body))
}

type Result = { index: number; outcome: string; approval?: string; bindingCode?: string; repeat: string | null; note?: string; error?: { error: string; message: string } }

const notText = new Uint8Array([0xff, 0xfe, 0x00, 0x41])

// Runs a printed repeat as a shell would and returns what reached the relay.
async function runRepeat(repeat: string): Promise<{ code: number; relayed: unknown[] }> {
  const relayed: unknown[] = []
  vault.relay = (request) => {
    relayed.push(request)
    return new Response("ok", { status: 200, headers: { [UPSTREAM_HEADER]: "1" } })
  }
  const words = shellWords(repeat)
  expect(words.slice(0, 2)).toEqual(["mehen", "fetch"])
  return { code: (await runJv(words.slice(1), env)).code, relayed }
}

describe("mehen plan submit", () => {
  test("each request goes to the vault as mehen fetch builds it, and its repeat sends the same bytes with --approval", async () => {
    await mkdir(join(dir.path, "work"), { recursive: true })
    await writeFile(join(dir.path, "work", "d1 contoso.json"), '{"name":"contoso"}\n')
    const path = await writePlan({
      version: 1,
      reason: "Set up the Contoso infrastructure",
      project: "prj_3kQ9vXyZ7",
      env: "dev",
      requests: [
        { item: "openai-personal", method: "post", url: "https://api.openai.com/v1/files", headers: ["Content-Type: application/json", "X-Note:  it's  "], body: '{"say":"it\'s here"}' },
        { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/files?purpose=a b", body: "@d1 contoso.json" },
        { item: "openai-personal", method: "PUT", url: "https://api.openai.com/v1/blob", headers: ["Content-Type: application/octet-stream"], bodyBase64: Buffer.from(notText).toString("base64") },
      ],
    })
    const result = await runJv(["plan", "submit", path, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const out = json(result) as { bundle: string; url: string; ask: Record<string, unknown>; next: Record<string, unknown>; results: Result[]; counts: unknown }
    const [body] = bundleBodies()
    expect(body?.reason).toBe("Set up the Contoso infrastructure")
    expect(body?.requests).toHaveLength(3)
    expect(out.bundle).toMatch(/^bnd_/)
    expect(out.url).toBe(`${vault.url}/w/mock-space/g/${out.bundle}`)
    expect(out.ask).toMatchObject({ kind: "bundle", id: out.bundle, url: out.url, check: { label: "codes", value: "CODE1, CODE2, CODE3 (3)" }, expiresAt: MOCK_EXPIRES_AT, wait: `mehen wait ${out.bundle} --timeout 60 --json` })
    expect(out.ask.what).toBe("Approve 3 requests together: Set up the Contoso infrastructure")
    expect(out.next).toMatchObject({ url: out.url, command: `mehen wait ${out.bundle} --timeout 60 --json` })
    expect(out.counts).toEqual({ ask: 3, allowed: 0, refused: 0 })
    const [text, file, bytes] = out.results as [Result, Result, Result]
    expect(text).toMatchObject({ index: 0, outcome: "ask", bindingCode: "CODE1" })
    expect(text.repeat).toContain(`-d '{"say":"it'\\''s here"}'`)
    expect(file.repeat).toContain(`-d '@${join(dir.path, "work", "d1 contoso.json")}'`)
    expect(bytes.repeat).toBeNull()
    expect(bytes.note).toBe(
      `The body is not text a shell command can carry, so there is no repeat: write the same bytes to a file and run mehen fetch openai-personal PUT https://api.openai.com/v1/blob -H 'Content-Type: application/octet-stream' -d @<a file holding these bytes> --project prj_3kQ9vXyZ7 --env dev --approval ${bytes.approval}`,
    )
    // Each repeat, run as printed, sends what the bundle held plus its approval.
    for (const [index, entry] of [text, file].entries()) {
      const relayed: unknown[] = []
      vault.relay = (request) => {
        relayed.push(request)
        return new Response("ok", { status: 200, headers: { [UPSTREAM_HEADER]: "1" } })
      }
      const words = shellWords(entry.repeat as string)
      expect(words.slice(0, 2)).toEqual(["mehen", "fetch"])
      expect(words.slice(-2)).toEqual(["--approval", entry.approval as string])
      expect((await runJv(words.slice(1), env)).code).toBe(EXIT.ok)
      expect(relayed).toEqual([{ ...(body?.requests[index] as Record<string, unknown>), approval: entry.approval }])
    }
  })

  test("a body, header or env starting with - repeats in the parser's inline form, so every printed repeat runs", async () => {
    const multipart = '--boundary\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n--boundary--\r\n'
    const path = await writePlan({
      version: 1,
      project: "prj_3kQ9vXyZ7",
      env: "--x",
      requests: [
        { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/files", headers: ["Content-Type: multipart/form-data; boundary=boundary"], body: multipart },
        { item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/b", headers: ["--x-odd:  1 "], body: "-1" },
      ],
    })
    const result = await runJv(["plan", "submit", path, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const out = json(result) as { results: Result[] }
    const body = bundleBodies().at(-1)
    const [first, second] = out.results as [Result, Result]
    expect(first.repeat).toContain(`'--data=--boundary`)
    expect(first.repeat).toContain("--env=--x")
    expect(second.repeat).toContain("'--header=--x-odd:  1 '")
    expect(second.repeat).toContain("--data=-1")
    for (const [index, entry] of [first, second].entries()) {
      const { code, relayed } = await runRepeat(entry.repeat as string)
      expect(code).toBe(EXIT.ok)
      expect(relayed).toEqual([{ ...(body?.requests[index] as Record<string, unknown>), approval: entry.approval }])
    }
  })

  test("a text body holding NUL, which no command-line argument carries, has no repeat and the note instead", async () => {
    const path = await writePlan({ version: 1, requests: [{ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", body: "a\u0000b" }] })
    const result = await runJv(["plan", "submit", path, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const [entry] = (json(result) as { results: Result[] }).results as [Result]
    expect(entry.repeat).toBeNull()
    expect(entry.note).toStartWith("The body is not text a shell command can carry, so there is no repeat")
  })

  test("human output: the bundle's ask, each request with its repeat, then the wait command", async () => {
    const path = await writePlan({ version: 1, requests: [{ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", body: "one" }, { item: "github-work", method: "DELETE", url: "https://api.github.com/repos/acme/app" }] })
    const result = await runJv(["plan", "submit", path], env)
    expect(result.code).toBe(EXIT.ok)
    const lines = result.stdout.trimEnd().split("\n")
    const bundle = /bnd_mock\d+/.exec(result.stdout)?.[0] as string
    expect(result.stdout).toContain("Approve 2 requests together")
    expect(result.stdout).toContain(`  open:    ${vault.url}/w/mock-space/g/${bundle}`)
    expect(result.stdout).toContain("CODE1, CODE2 (2)")
    expect(lines.find((l) => /^request 1: POST https:\/\/api\.openai\.com\/v1\/a with openai-personal: waits for approval apr_mock\d+, code CODE1$/.test(l))).toBeDefined()
    expect(lines.find((l) => l.startsWith("  repeat: mehen fetch github-work DELETE https://api.github.com/repos/acme/app --approval apr_"))).toBeDefined()
    expect(lines.at(-1)).toBe(`then:    mehen wait ${bundle}`)
  })

  test("an ask a mandate could cover carries mandateCover on its result, its page checked, and a mandate: line under the request", async () => {
    const page = `${vault.url}/w/mock-space/mandates/mdt_live`
    vault.overrides.set("POST /v1/approvals/bundles", () =>
      Response.json({
        bundle: "bnd_cover",
        url: `${vault.url}/w/mock-space/g/bnd_cover`,
        expiresAt: MOCK_EXPIRES_AT,
        results: [
          { index: 0, outcome: "ask", approval: "apr_one", bindingCode: "CODE1", mandateCover: { classes: ["read", "send"], state: "outside_schedule", mandate: "mdt_live", url: "https://evil.example/x" } },
          { index: 1, outcome: "ask", approval: "apr_two", bindingCode: "CODE2", mandateCover: { state: "bored" } },
        ],
      }),
    )
    const path = await writePlan({ version: 1, requests: [{ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", body: "one" }, { item: "github-work", method: "DELETE", url: "https://api.github.com/repos/acme/app" }] })
    const result = await runJv(["plan", "submit", path, "--json"], env)
    const out = json(result) as { results: Record<string, unknown>[] }
    expect(out.results[0]).toMatchObject({ mandateCover: { classes: ["read", "send"], state: "outside_schedule", mandate: "mdt_live", url: page } })
    expect(out.results[1]).not.toHaveProperty("mandateCover")
    expect(result.stdout).not.toContain("evil.example")
    const lines = (await runJv(["plan", "submit", path], env)).stdout.split("\n")
    const first = lines.findIndex((l) => l.startsWith("request 1:"))
    expect(lines[first + 1]).toBe(`  mandate: This machine's mandate does not cover this time; it covers its hours only (${page}).`)
    expect(lines.filter((l) => l.startsWith("  mandate:"))).toHaveLength(1)
  })

  test("when nothing waits it says so plainly, exits 0, and a refused request has no repeat", async () => {
    vault.overrides.set("POST /v1/approvals/bundles", () =>
      Response.json({
        bundle: "bnd_quiet",
        url: `${vault.url}/w/mock-space/g/bnd_quiet`,
        expiresAt: MOCK_EXPIRES_AT,
        results: [
          { index: 0, outcome: "allowed" },
          { index: 1, outcome: "refused", error: { error: "policy_denied", message: "Deleting repositories is refused.", next: { url: "https://evil.example/x", say: "Do not." } } },
        ],
      }),
    )
    const path = await writePlan({ version: 1, requests: [{ item: "openai-personal", method: "GET", url: "https://api.openai.com/v1/models" }, { item: "github-work", method: "DELETE", url: "https://api.github.com/repos/acme/app" }] })
    const human = await runJv(["plan", "submit", path], env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).not.toContain("mehen wait")
    expect(human.stdout).not.toContain("evil.example")
    expect(human.stdout.trimEnd().split("\n").at(-1)).toBe("Nothing in this plan waits for a human: 1 can be sent now with the repeat commands above; 1 was refused.")
    const result = await runJv(["plan", "submit", path, "--json"], env)
    const out = json(result) as { ask?: unknown; results: Result[]; next: { say: string } }
    expect(out.ask).toBeUndefined()
    expect(out.results[0]).toMatchObject({ outcome: "allowed", repeat: "mehen fetch openai-personal GET https://api.openai.com/v1/models" })
    expect(out.results[1]).toMatchObject({ outcome: "refused", repeat: null, error: { error: "policy_denied", message: "Deleting repositories is refused.", next: { say: "Do not." } } })
    expect(out.next.say).toContain("Nothing in this plan waits for a human")
    expect(result.stdout).not.toContain("evil.example")
  })

  test("a bundle the vault made where no /g/ link can be checked still gives its results and mehen wait bnd_, exit 0, with the refused-link warning", async () => {
    await dir.remove()
    dir = await tempDir()
    env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url }
    await vault.enrolSoftware(dir.path, { config: { workspaceSlug: undefined } })
    const path = await writePlan({ version: 1, requests: [{ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", body: "one" }] })
    const result = await runJv(["plan", "submit", path, "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const out = json(result) as { bundle: string; url: unknown; ask?: unknown; next: { url?: string; command: string; say: string }; results: Result[] }
    expect(out.bundle).toMatch(/^bnd_/)
    expect(out.ask).toBeUndefined()
    expect(out.url).toBeNull()
    expect(out.next).not.toHaveProperty("url")
    expect(out.next.command).toBe(`mehen wait ${out.bundle} --timeout 60 --json`)
    expect(out.results[0]).toMatchObject({ outcome: "ask", approval: expect.stringMatching(/^apr_/), repeat: expect.stringContaining("--approval apr_") })
    expect(result.stderr).toContain("mehen: warning: The vault returned a link that is not on")
    const human = await runJv(["plan", "submit", path], env)
    expect(human.code).toBe(EXIT.ok)
    expect(human.stdout).not.toContain("/g/bnd_")
    expect(human.stdout.trimEnd().split("\n").at(-1)).toMatch(/^then: {4}mehen wait bnd_mock\d+$/)
  })

  test("more than 20 requests, or more than the vault reads in one body, is a usage error and sends nothing", async () => {
    const before = bundleBodies().length
    const many = Array.from({ length: 21 }, () => ({ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", body: "x" }))
    const tooMany = await runJv(["plan", "submit", await writePlan({ version: 1, requests: many }), "--json"], env)
    expect(tooMany.code).toBe(EXIT.usage)
    expect(json(tooMany).message).toContain("has 21 requests; a bundle holds at most 20")
    const big = "a".repeat(400_000)
    const large = await runJv(["plan", "submit", await writePlan({ version: 1, requests: [1, 2].map(() => ({ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", body: big })) }), "--json"], env)
    expect(large.code).toBe(EXIT.usage)
    expect(json(large).message).toContain("the vault reads at most 1000000 in one bundle")
    expect(bundleBodies().length).toBe(before)
  })

  test("a plan mehen cannot read names the request and what is wrong, and sends nothing", async () => {
    const before = vault.seen.length
    const cases: [unknown, string][] = [
      ["not json", "is not JSON"],
      [{ version: 2, requests: [] }, "is not a plan mehen can read"],
      [{ version: 1, requests: [{ item: "openai-personal", method: "GET", url: "https://api.openai.com/", extra: 1 }] }, 'is not a plan mehen can read: Request 1 of the plan: Unrecognized key: "extra"'],
      [{ version: 1, requests: [{ item: "openai-personal", method: "GET", url: "https://api.openai.com/" }, { item: "openai-personal", method: 5, url: "https://api.openai.com/" }] }, "is not a plan mehen can read: Request 2 of the plan: method: "],
      [{ version: 1, project: "prj_3kQ9vXyZ7", requests: [{ item: "openai-personal", method: "GET", url: "https://api.openai.com/" }] }, "--project and --env go together"],
      [{ version: 1, requests: [{ item: "openai-personal", method: "GET", url: "https://api.openai.com/" }, { item: "openai-personal", method: "POST", url: "https://api.openai.com/", body: "x", bodyBase64: "eA==" }] }, "Request 2 of the plan: give body or bodyBase64, not both."],
      [{ version: 1, requests: [{ item: "openai-personal", method: "POST", url: "https://api.openai.com/", body: "@missing.json" }] }, `Request 1 of the plan: cannot read the body from ${join(dir.path, "work", "missing.json")}`],
      [{ version: 1, requests: [{ item: "openai-personal", method: "POST", url: "https://api.openai.com/", body: "-" }] }, "Request 1 of the plan: a plan body cannot be read from stdin"],
      [{ version: 1, requests: [{ item: "openai-personal", method: "GET", url: "https://api.openai.com/", headers: ["no colon"] }] }, 'Request 1 of the plan: Header "no colon" must look like "Name: value".'],
    ]
    for (const [plan, message] of cases) {
      const result = await runJv(["plan", "submit", await writePlan(plan), "--json"], env)
      expect(result.code).toBe(EXIT.usage)
      expect(String(json(result).message)).toContain(message)
    }
    expect((await runJv(["plan", "check", await writePlan({ version: 1, requests: [] }), "--json"], env)).code).toBe(EXIT.usage)
    expect(vault.seen.length).toBe(before)
  })

  test("a vault without bundles refuses forbidden, and mehen says to send the requests one by one", async () => {
    const path = await writePlan({ version: 1, requests: [{ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", body: "one" }] })
    vault.overrides.set("POST /v1/approvals/bundles", () => vaultError("forbidden", "Asking for several requests at once is not available yet."))
    const off = await runJv(["plan", "submit", path, "--json"], env)
    expect(off.code).toBe(EXIT.refused)
    expect(json(off)).toMatchObject({ error: "forbidden", message: "Asking for several requests at once is not available yet.", next: { say: "Send the requests one by one with mehen fetch; each that needs approval asks on its own." } })
    vault.overrides.set("POST /v1/approvals/bundles", () => vaultError("not_found", "No route POST /v1/approvals/bundles."))
    const old = await runJv(["plan", "submit", path, "--json"], env)
    expect(old.code).toBe(EXIT.refused)
    expect(json(old)).toMatchObject({ error: "forbidden", next: { say: "Send the requests one by one with mehen fetch; each that needs approval asks on its own." } })
    // Any other refusal of the whole plan is the vault's own.
    vault.overrides.set("POST /v1/approvals/bundles", () => vaultError("rate_limited", "This machine's open asks and these 1 requests would pass its 20."))
    const full = await runJv(["plan", "submit", path, "--json"], env)
    expect(full.code).toBe(EXIT.transient)
    expect(json(full)).toMatchObject({ error: "rate_limited" })
  })

  test("the bundle is recorded, so mehen pending lists it and mehen wait bnd_ follows it", async () => {
    const path = await writePlan({ version: 1, requests: [{ item: "openai-personal", method: "POST", url: "https://api.openai.com/v1/a", body: "one" }] })
    const out = json(await runJv(["plan", "submit", path, "--json"], env)) as { bundle: string; results: Result[] }
    vault.pending = []
    const pending = json(await runJv(["pending", "--json"], env)) as { pending: { kind: string; id: string }[] }
    expect(pending.pending).toContainEqual(expect.objectContaining({ kind: "bundle", id: out.bundle }))
    vault.sequences.set(`bundle:${out.bundle}`, [{ bundle: out.bundle, approvals: [{ id: out.results[0]?.approval, status: "approved" }] }])
    const waited = await runJv(["wait", out.bundle, "--json"], env)
    expect(waited.code).toBe(EXIT.ok)
    expect(json(waited)).toMatchObject({ id: out.bundle, kind: "bundle", bundle: out.bundle, approvals: [{ status: "approved" }] })
    vault.pending = null
  })
})
