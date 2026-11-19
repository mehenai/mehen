import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { EXIT, type ItemDescription, type ItemDescriptionPosture } from "@mehen/protocol/api"
import { OAUTH_PROVIDERS, type OAuthProviderTemplate, connectionPolicy } from "@mehen/protocol/templates"
import { MOCK_TENANT, MOCK_WORKSPACE, MockVault, item } from "../testing/mock-vault.ts"
import { type JvResult, runJv, tempDir } from "../testing/run-mehen.ts"
import { LEASE_ONLY_HOST } from "@mehen/protocol/binding"
import { plainStyler, plainText, stripStyle, styler } from "../tty.ts"
import { itemPolicyLines, lastUsedText, lsLines, relativeAgo, showLines, statusWord, tryCommand } from "./items.ts"

let vault: MockVault
let dir: { path: string; remove(): Promise<void> }
let env: Record<string, string>

beforeAll(() => {
  vault = new MockVault()
})
afterAll(() => vault.stop())
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path, MEHEN_VAULT_URL: vault.url, TZ: "UTC" }
  vault.overrides.clear()
  vault.sequences.clear()
  vault.enrolOutcome = { pendingPolls: 2, result: "active" }
  vault.items.splice(2)
})
afterEach(async () => dir.remove())

function json(result: JvResult): Record<string, unknown> {
  return JSON.parse(result.stdout) as Record<string, unknown>
}

async function enrolled(): Promise<string> {
  return vault.enrolSoftware(dir.path)
}

const ESC = "\u001b"
const RLO = "\u202e"
const GMAIL = "/gmail/v1/users/*"
const gmail = OAUTH_PROVIDERS["google-gmail"] as OAuthProviderTemplate

// The live gmail-alex item (UX-MEHEN-TOOLS 2.7): the google-gmail connection
// policy, 14 rules, approve by default.
function gmailAlex(extra: Partial<ItemDescription> = {}): ItemDescription {
  return item("gmail-alex", {
    kind: "oauth-connection",
    provider: "google-gmail",
    account: "alexrae@example.com",
    accountVerified: true,
    tags: ["mail"],
    ceiling: "relay",
    hosts: ["gmail.googleapis.com"],
    status: "active",
    description: "Gmail for alexrae@example.com",
    binding: gmail.upstream.binding,
    policy: connectionPolicy(gmail),
    injection: gmail.upstream.injection,
    secretFields: [
      { name: "access_token", set: true, length: 253, prefix: "", fingerprint: "jYYZ_C4NljMe" },
      { name: "refresh_token", set: true, length: 103, prefix: "", fingerprint: "yYtjo679-4mr" },
    ],
    lastUsedAt: "2026-10-24T17:06:12.000Z",
    ...extra,
  })
}

describe("mehen ls", () => {
  test("lists items, with filters passed to the vault", async () => {
    await enrolled()
    const all = await runJv(["ls", "--json"], env)
    expect(all.code).toBe(EXIT.ok)
    expect((json(all).items as { slug: string }[]).map((i) => i.slug)).toEqual(["openai-personal", "github-work"])
    const tagged = await runJv(["ls", "--tag", "code", "--json"], env)
    expect((json(tagged).items as { slug: string }[]).map((i) => i.slug)).toEqual(["github-work"])
    expect(vault.seen.at(-1)?.search).toBe("?tag=code")
  })

  test("the table without colour: hosts joined with a comma and space, needs_reauth as words, no REVIEW column unless needed", async () => {
    await enrolled()
    vault.items.push(gmailAlex({ status: "needs_reauth", hosts: ["gmail.googleapis.com", "www.googleapis.com"] }))
    vault.items.push(item("sam-key", { account: "sam@example.com", accountVerified: false, status: "disabled" }))
    const result = await runJv(["ls"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout.split("\n")).toEqual([
      "ITEM             KIND              PROVIDER      ACCOUNT                       STATUS        HOSTS",
      "openai-personal  api-key           openai        -                             active        api.openai.com",
      "github-work      bearer-token      github-pat    -                             active        api.github.com",
      "gmail-alex       oauth-connection  google-gmail  alexrae@example.com           needs reauth  gmail.googleapis.com, www.googleapis.com",
      "sam-key          api-key           openai        sam@example.com (unverified)  disabled      api.openai.com",
      "",
    ])
    expect(result.stdout).not.toContain(ESC)
    expect(result.stdout).not.toContain("needs_reauth")
  })

  test("the table with colour: status in the closed style set, (unverified) and ! red, columns still aligned", async () => {
    await enrolled()
    vault.items.push(gmailAlex({ status: "needs_reauth" }))
    vault.items.push(item("sam-key", { account: "sam@example.com", accountVerified: false, status: "disabled", review: { reason: "an upstream echoed its value back", since: "2026-10-23T10:00:00.000Z" } }))
    vault.items.push(item("retrying", { status: "refresh_retrying" }))
    const result = await runJv(["ls"], { ...env, FORCE_COLOR: "1" })
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).toContain(`${ESC}[32mactive${ESC}[0m`)
    expect(result.stdout).toContain(`${ESC}[33mneeds reauth${ESC}[0m`)
    expect(result.stdout).toContain(`${ESC}[33mrefresh retrying${ESC}[0m`)
    expect(result.stdout).toContain(`${ESC}[31mdisabled${ESC}[0m`)
    expect(result.stdout).toContain(`sam@example.com ${ESC}[31m(unverified)${ESC}[0m`)
    expect(result.stdout).toContain(`${ESC}[31m!${ESC}[0m`)
    expect(result.stdout).toContain(`sam-key ${ESC}[31mneeds review${ESC}[0m: an upstream echoed its value back`)
    const plain = stripStyle(result.stdout).split("\n")
    const header = plain[0] as string
    expect(header).toBe("ITEM             KIND              PROVIDER      ACCOUNT                       STATUS            REVIEW  HOSTS")
    const hostsAt = header.indexOf("HOSTS")
    const statusAt = header.indexOf("STATUS")
    for (const row of plain.slice(1, 6)) {
      expect(row.slice(hostsAt)).toMatch(/^api\.|^gmail\./)
      expect(row.slice(statusAt)).toMatch(/^(active|needs reauth|disabled|refresh retrying) /)
    }
    expect(plain[4]).toContain("  !       api.openai.com")
    const noColour = await runJv(["ls"], env)
    expect(noColour.stdout).not.toContain(ESC)
    expect(stripStyle(result.stdout)).toBe(noColour.stdout)
  })

  test("colour obeys NO_COLOR and is off on a pipe", async () => {
    await enrolled()
    expect((await runJv(["ls"], env)).stdout).not.toContain(ESC)
    expect((await runJv(["ls"], { ...env, FORCE_COLOR: "1", NO_COLOR: "" })).stdout).toContain(ESC)
  })

  test("a hidden or ESC character in an item name, account or host prints spelled out", async () => {
    await enrolled()
    vault.items.push(item(`evil${ESC}[31mred`, { account: `sam${RLO}@example.com`, accountVerified: false, hosts: [`api.${RLO}example.com`] }))
    const result = await runJv(["ls"], { ...env, FORCE_COLOR: "1" })
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).toContain("evil\\u001B[31mred")
    expect(result.stdout).toContain("sam[RLO U+202E]@example.com")
    expect(result.stdout).toContain("api.[RLO U+202E]example.com")
    expect(result.stdout).not.toContain(RLO)
    expect(result.stdout).not.toContain(`${ESC}[31mred`)
    const escapes = result.stdout.match(/\u001b\[[0-9;]*m/g) ?? []
    expect(escapes.every((e) => e === `${ESC}[32m` || e === `${ESC}[31m` || e === `${ESC}[0m`)).toBe(true)
    expect(stripStyle(result.stdout)).toContain("sam[RLO U+202E]@example.com (unverified)  active")
  })

  test("with an unknown kind is a usage error", async () => {
    await enrolled()
    expect((await runJv(["ls", "--kind", "nonsense"], env)).code).toBe(EXIT.usage)
  })

  test("--json: the summary fields and the workspace each item is in, nothing more, no colour", async () => {
    await enrolled()
    vault.items.push(gmailAlex({ review: { reason: "r", since: "2026-10-23T10:00:00.000Z" } }))
    const result = await runJv(["ls", "--json"], { ...env, FORCE_COLOR: "1" })
    expect(result.stdout).not.toContain(ESC)
    expect(json(result)).toEqual({
      items: [
        { slug: "openai-personal", kind: "api-key", provider: "openai", account: null, accountVerified: false, tags: ["ai"], ceiling: "placeholder", hosts: ["api.openai.com"], status: "active", updatedAt: "2026-10-24T00:00:00.000Z", workspace: MOCK_WORKSPACE },
        { slug: "github-work", kind: "bearer-token", provider: "github-pat", account: null, accountVerified: false, tags: ["code"], ceiling: "placeholder", hosts: ["api.github.com"], status: "active", updatedAt: "2026-10-24T00:00:00.000Z", workspace: MOCK_WORKSPACE },
        {
          slug: "gmail-alex",
          kind: "oauth-connection",
          provider: "google-gmail",
          account: "alexrae@example.com",
          accountVerified: true,
          tags: ["mail"],
          ceiling: "relay",
          hosts: ["gmail.googleapis.com"],
          status: "active",
          review: { reason: "r", since: "2026-10-23T10:00:00.000Z" },
          updatedAt: "2026-10-24T00:00:00.000Z",
          workspace: MOCK_WORKSPACE,
        },
      ],
    })
  })

  // Ls spans the allowed set; --workspace and MEHEN_WORKSPACES narrow it.
  test("spans every active workspace, each item with its workspace and a WORKSPACE column; a refusing vault is named, not hidden", async () => {
    const SECOND = { id: "tn_second00000001", slug: "second-space", name: "Second Space" }
    await enrolled()
    const b = await vault.enrolSoftware(dir.path, { config: { tenant: SECOND.id, workspaceSlug: SECOND.slug, workspaceName: SECOND.name } })
    const all = json(await runJv(["ls", "--json"], env)) as { items: { slug: string; workspace: { id: string } }[] }
    expect(all.items.map((i) => [i.slug, i.workspace.id])).toEqual([["openai-personal", MOCK_TENANT], ["github-work", MOCK_TENANT], ["openai-personal", SECOND.id], ["github-work", SECOND.id]])
    // Each workspace's list was signed by its own device, for its own tenant.
    expect(vault.seen.filter((c) => c.path === "/v1/items").slice(-2).map((c) => c.claims.ten)).toEqual([MOCK_TENANT, SECOND.id])
    const human = await runJv(["ls"], env)
    expect(human.stdout.split("\n")[0]).toMatch(/^ITEM\s+WORKSPACE\s+KIND/)
    expect(human.stdout).toMatch(/openai-personal\s+second-space\s+api-key/)
    const named = json(await runJv(["ls", "--json", "--workspace", SECOND.slug], env)) as { items: { workspace: { id: string } }[] }
    expect(new Set(named.items.map((i) => i.workspace.id))).toEqual(new Set([SECOND.id]))
    const narrowed = json(await runJv(["ls", "--json"], { ...env, MEHEN_WORKSPACES: "mock-space" })) as { items: { workspace: { id: string } }[] }
    expect(new Set(narrowed.items.map((i) => i.workspace.id))).toEqual(new Set([MOCK_TENANT]))
    // One refusing vault: the other's items, and a warning naming the slot.
    const record = vault.devices.get(b)
    if (record) record.revoked = true
    const partly = await runJv(["ls", "--json"], env)
    expect(partly.code).toBe(EXIT.ok)
    expect(new Set((json(partly) as { items: { workspace: { id: string } }[] }).items.map((i) => i.workspace.id))).toEqual(new Set([MOCK_TENANT]))
    expect(partly.stderr).toContain(`the vault for ${vault.slotDir(dir.path, SECOND.id)} could not be asked (device_revoked`)
    // Named, the refusal is the answer.
    const refused = await runJv(["ls", "--json", "--workspace", SECOND.slug], env)
    expect(refused.code).toBe(EXIT.identity)
    expect(json(refused)).toMatchObject({ error: "device_revoked" })
  })
})

describe("mehen show", () => {
  test("prints public metadata only, dropping anything unexpected", async () => {
    await enrolled()
    vault.items.push({ ...item("leaky-item"), value: "sk-should-never-show" } as ReturnType<typeof item>)
    const result = await runJv(["show", "leaky-item", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).not.toContain("sk-should-never-show")
    expect(json(result)).toMatchObject({ slug: "leaky-item", kind: "api-key", binding: { hosts: ["api.openai.com"] } })
    const human = await runJv(["show", "leaky-item"], env)
    expect(human.stdout).toContain("mehen://leaky-item")
    expect(human.stdout).not.toContain("sk-should-never-show")
  })

  // ItemDescription.pushes (design push-providers 3.3 point 5): the latest
  // push to each destination, present only once the item was pushed.
  const PUSHES = [
    { push: "psh_1", destination: "github:acme/app/OPENAI_API_KEY", words: "GitHub acme/app, Actions secret OPENAI_API_KEY", field: "key", version: 3, current: true, via: "github-pat-ci", state: "done", outcome: "replaced", providerStatus: 204, at: "2026-10-24T09:15:00.000Z", by: "Alex" },
    { push: "psh_2", destination: "vercel:shop/production/OPENAI_API_KEY", words: "Vercel shop, production variable OPENAI_API_KEY", field: "key", version: 2, current: false, via: null, state: "done", outcome: "set", providerStatus: 201, at: "2026-10-20T08:00:00.000Z", by: "mac-mini" },
    { push: "psh_3", destination: "github:acme/fork/OPENAI_API_KEY", words: "GitHub acme/fork, Actions secret OPENAI_API_KEY", field: "key", version: 3, current: true, via: "github-pat-ci", state: "failed", outcome: null, providerStatus: 403, at: "2026-10-24T09:20:00.000Z", by: "Alex", message: "provider body sk-provider-said" },
    { push: "psh_4", destination: "cloudflare:0123456789abcdef0123456789abcdef/mailer/OPENAI_API_KEY", words: "Cloudflare Worker mailer in account 0123456789abcdef0123456789abcdef, secret OPENAI_API_KEY", field: "key", version: 3, current: true, via: "cf-deploy", state: "unknown", outcome: null, providerStatus: null, at: "2026-10-24T09:25:00.000Z" },
    { push: "psh_5", destination: "github:acme/app/dependabot/OPENAI_API_KEY", words: "GitHub acme/app, Dependabot secret OPENAI_API_KEY", field: "key", version: 3, current: true, via: "github-pat-ci", state: "not_sent", outcome: null, providerStatus: null, at: "2026-10-24T09:30:00.000Z" },
  ] as NonNullable<ItemDescription["pushes"]>

  test("show --json keeps an item's pushes field by field, never who asked, and an item never pushed has none", async () => {
    await enrolled()
    vault.items.push(item("openai-prod", { version: 3, pushes: PUSHES }))
    const result = await runJv(["show", "openai-prod", "--json"], env)
    expect(result.code).toBe(EXIT.ok)
    const picked = PUSHES.map(({ by: _by, ...record }) => { const { message: _message, ...kept } = record as typeof record & { message?: string }; return kept })
    expect(json(result).pushes).toEqual(picked)
    for (const hidden of ["sk-provider-said", "Alex", "mac-mini", "\"by\""]) expect(result.stdout).not.toContain(hidden)
    expect(json(await runJv(["show", "openai-personal", "--json"], env))).not.toHaveProperty("pushes")
  })

  test("show prints one line per destination the item was pushed to, with its version and date, never the via, who or the provider's words", async () => {
    await enrolled()
    vault.items.push(item("openai-prod", { version: 3, pushes: PUSHES }))
    const result = await runJv(["show", "openai-prod"], env)
    expect(result.code).toBe(EXIT.ok)
    const lines = result.stdout.split("\n")
    const first = lines.findIndex((line) => line.includes("GitHub acme/app, Actions"))
    expect(lines.slice(first, first + 5)).toEqual([
      "  pushed to GitHub acme/app, Actions secret OPENAI_API_KEY (version 3) 2026-10-24 09:15",
      "  pushed to Vercel shop, production variable OPENAI_API_KEY (version 2, older than current) 2026-10-20 08:00",
      "  push to GitHub acme/fork, Actions secret OPENAI_API_KEY failed (version 3, provider said 403) 2026-10-24 09:20",
      "  push to Cloudflare Worker mailer in account 0123456789abcdef0123456789abcdef, secret OPENAI_API_KEY unconfirmed (version 3) 2026-10-24 09:25",
      "  push to GitHub acme/app, Dependabot secret OPENAI_API_KEY not sent (version 3) 2026-10-24 09:30",
    ])
    for (const hidden of ["github-pat-ci", "cf-deploy", "Alex", "mac-mini", "sk-provider-said", "psh_"]) expect(result.stdout).not.toContain(hidden)
    expect((await runJv(["show", "openai-personal"], env)).stdout).not.toContain("push")
  })

  // With pushes switched on the vault sends an empty list for an item never
  // pushed (apps/vault/src/vault/areas/items-workspace.ts, pushesOf).
  test("show prints no push lines for an item whose pushes are an empty list", async () => {
    await enrolled()
    vault.items.push(item("openai-staging", { pushes: [] }))
    const result = await runJv(["show", "openai-staging"], env)
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).toContain("mehen://openai-staging")
    expect(result.stdout).not.toContain("push")
    expect(json(await runJv(["show", "openai-staging", "--json"], env))).toHaveProperty("pushes", [])
  })

  test("the live gmail-alex item, line for line (UX-MEHEN-TOOLS 2.7), with the summary from the matchers", async () => {
    await enrolled()
    vault.items.push(gmailAlex())
    const result = await runJv(["show", "gmail-alex"], env)
    expect(result.code).toBe(EXIT.ok)
    const lines = result.stdout.split("\n")
    expect(lines.slice(0, 7)).toEqual([
      "gmail-alex  (mehen://gmail-alex)",
      "  kind:      oauth-connection, provider google-gmail (Gmail)",
      "  account:   alexrae@example.com (verified)",
      "  about:     Gmail for alexrae@example.com",
      "  status:    active, ceiling relay, version 1",
      "  goes to:   gmail.googleapis.com /gmail/v1/**, /upload/gmail/v1/**",
      "  Base policy: approve by default (14 rules; mehen show gmail-alex --json for all of them)",
    ])
    expect(lines.slice(7, 10)).toEqual([
      `    without a human:  GET/HEAD anywhere; POST on ${GMAIL}/drafts, /upload${GMAIL}/drafts; POST on ${GMAIL}/messages/*/modify, ${GMAIL}/threads/*/modify, ${GMAIL}/messages/batchModify`,
      `    needs approval:   POST/PUT on ${GMAIL}/messages/send, /upload${GMAIL}/messages/send; POST/PUT on ${GMAIL}/messages/import, ${GMAIL}/messages/insert, /upload${GMAIL}/messages/import, /upload${GMAIL}/messages/insert; DELETE on ${GMAIL}/messages/*, ${GMAIL}/threads/*; (1 more); anything else`,
      `    refused:          POST/PUT/PATCH/DELETE on ${GMAIL}/settings/forwardingAddresses, ${GMAIL}/settings/forwardingAddresses/**, ${GMAIL}/settings/autoForwarding; POST/PUT/PATCH/DELETE on ${GMAIL}/settings/delegates, ${GMAIL}/settings/delegates/**; POST/PUT/PATCH/DELETE on ${GMAIL}/settings/filters, ${GMAIL}/settings/filters/**; (4 more)`,
    ])
    expect(lines.slice(10)).toEqual([
      "  Effective floors: unavailable from this vault",
      "  Read mehen policy show gmail-alex for current policy state. A saved base allow does not remove a floor.",
      "  tags:      mail",
      "  secret access_token:  set, 253 chars, fingerprint jYYZ_C4NljMe",
      "  secret refresh_token: set, 103 chars, fingerprint yYtjo679-4mr",
      expect.stringMatching(/^ {2}last used: 2026-10-24 17:06 \(\d+ (min|h|days) ago\)$/),
      "  try:       mehen check gmail-alex GET https://gmail.googleapis.com/gmail/v1",
      "",
    ])
  })

  test("untrusted notes are never shown: the template's notes and a deceptive note both stay out", async () => {
    await enrolled()
    vault.items.push(gmailAlex())
    const live = await runJv(["show", "gmail-alex"], env)
    const notes = connectionPolicy(gmail).rules.flatMap((rule) => (rule.note ? [rule.note] : []))
    expect(notes.length).toBe(14)
    for (const note of notes.filter((n) => n.includes(" "))) expect(live.stdout).not.toContain(note)
    expect(live.stdout).not.toMatch(/\breads\b/)
    expect(live.stdout).not.toContain("sends email as you")
    expect(live.stdout).not.toContain("forwarding sends every message elsewhere")
    vault.items.push(
      item("sneaky-key", {
        policy: {
          default: "approve",
          rules: [
            { action: "allow", methods: ["POST"], paths: ["/v1/messages/send"], note: "read mail" },
            { action: "deny", methods: ["GET"], paths: ["/v1/labels"], note: "sends email as you" },
          ],
        },
      }),
    )
    const sneaky = await runJv(["show", "sneaky-key"], env)
    expect(sneaky.code).toBe(EXIT.ok)
    expect(sneaky.stdout).not.toContain("read mail")
    expect(sneaky.stdout).not.toContain("sends email as you")
    expect(sneaky.stdout).toContain("    without a human:  POST on /v1/messages/send\n")
    expect(sneaky.stdout).toContain("    needs approval:   anything else\n")
    expect(sneaky.stdout).toContain("    refused:          GET on /v1/labels\n")
    expect(json(await runJv(["show", "sneaky-key", "--json"], env)).policy).toEqual(vault.items.at(-1)?.policy)
  })

  test("a hidden or ESC character in a rule path, host, description or field prints spelled out", async () => {
    await enrolled()
    vault.items.push(
      item("odd-key", {
        description: `about${ESC}[2J`,
        binding: { hosts: [`api.${RLO}example.com`], paths: [`/v1/${RLO}safe`] },
        policy: { default: "deny", rules: [{ action: "allow", methods: ["GET"], paths: [`/v1/${ESC}[31m/red`, `/v1/\u200bzw`] }] },
        publicFields: { [`name${RLO}`]: `value${ESC}[0m` },
      }),
    )
    const result = await runJv(["show", "odd-key"], { ...env, FORCE_COLOR: "1" })
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).toContain("  about:     about\\u001B[2J")
    expect(result.stdout).toContain("  goes to:   api.[RLO U+202E]example.com /v1/[RLO U+202E]safe")
    expect(result.stdout).toContain("    without a human:  GET on /v1/\\u001B[31m/red, /v1/[ZWSP U+200B]zw")
    expect(result.stdout).toContain("    refused:          anything else")
    expect(result.stdout).toMatch(/^ {2}name\[RLO U\+202E\]: +value\\u001B\[0m$/m)
    expect(result.stdout).not.toContain(RLO)
    expect(result.stdout).not.toContain("\u200b")
    expect(result.stdout).not.toContain(`${ESC}[2J`)
    expect(result.stdout).not.toContain(`${ESC}[31m/red`)
    expect(result.stdout).not.toContain("  try:")
  })

  test("last used is local time with a relative tail, and never when unset", async () => {
    await enrolled()
    const threeMinutesAgo = new Date(Date.now() - 3 * 60_000).toISOString()
    vault.items.push(item("used-key", { lastUsedAt: threeMinutesAgo }))
    const used = await runJv(["show", "used-key"], env)
    const stamp = threeMinutesAgo.slice(0, 16).replace("T", " ")
    expect(used.stdout).toContain(`  last used: ${stamp} (3 min ago)\n`)
    expect((await runJv(["show", "openai-personal"], env)).stdout).toContain("  last used: never\n")
    vault.items.push(item("odd-time", { lastUsedAt: "not a time" }))
    expect((await runJv(["show", "odd-time"], env)).stdout).toContain("  last used: not a time\n")
  })

  test("try: is a mehen check of a request inside the binding, or absent when none can be built", async () => {
    await enrolled()
    vault.items.push(item("any-host", { binding: { hosts: ["*.example.com"] } }))
    vault.items.push(item("posts-only", { binding: { hosts: ["api.example.com"], methods: ["POST"], paths: ["/v1/things/*/send"] } }))
    expect((await runJv(["show", "openai-personal"], env)).stdout).toContain("  try:       mehen check openai-personal GET https://api.openai.com/\n")
    expect((await runJv(["show", "any-host"], env)).stdout).not.toContain("  try:")
    expect((await runJv(["show", "posts-only"], env)).stdout).toContain("  try:       mehen check posts-only POST https://api.example.com/v1/things/example/send\n")
  })

  test("colour: the status word and the account marker, nothing else", async () => {
    await enrolled()
    vault.items.push(gmailAlex({ status: "needs_reauth", accountVerified: false }))
    const result = await runJv(["show", "gmail-alex"], { ...env, FORCE_COLOR: "1" })
    expect(result.stdout).toContain(`  status:    ${ESC}[33mneeds reauth${ESC}[0m, ceiling relay`)
    expect(result.stdout).toContain(`  account:   alexrae@example.com ${ESC}[31m(unverified)${ESC}[0m`)
    expect((result.stdout.match(/\u001b\[[0-9;]*m/g) ?? []).length).toBe(4)
    expect(stripStyle(result.stdout)).toBe((await runJv(["show", "gmail-alex"], env)).stdout)
  })

  test("ls and show carry the review flag, in --json and as needs review: <reason>", async () => {
    await enrolled()
    const review = { reason: "an upstream echoed its value back", since: "2026-10-23T10:00:00.000Z" }
    vault.items.push(item("echoed-key", { review }))
    const listed = (json(await runJv(["ls", "--json"], env)).items as { slug: string; review?: unknown }[]).find((i) => i.slug === "echoed-key")
    expect(listed?.review).toEqual(review)
    expect((json(await runJv(["ls", "--json"], env)).items as { slug: string; review?: unknown }[]).find((i) => i.slug === "openai-personal")).not.toHaveProperty("review")
    const ls = await runJv(["ls"], env)
    expect(ls.stdout).toContain("STATUS  REVIEW  HOSTS")
    expect(ls.stdout).toContain("echoed-key needs review: an upstream echoed its value back")
    expect(json(await runJv(["show", "echoed-key", "--json"], env)).review).toEqual(review)
    expect((await runJv(["show", "echoed-key"], env)).stdout).toContain("  review:    needs review: an upstream echoed its value back (since 2026-10-23T10:00:00.000Z)")
    expect((await runJv(["show", "openai-personal"], env)).stdout).not.toContain("needs review")
  })

  test("--json is unchanged: the description fields as the vault sent them, no colour, no summary", async () => {
    await enrolled()
    vault.items.push(gmailAlex())
    const result = await runJv(["show", "gmail-alex", "--json"], { ...env, FORCE_COLOR: "1" })
    expect(result.code).toBe(EXIT.ok)
    expect(result.stdout).not.toContain(ESC)
    expect(json(result)).toEqual(gmailAlex())
    expect(Object.keys(json(result))).toEqual([
      "slug",
      "kind",
      "provider",
      "account",
      "accountVerified",
      "tags",
      "ceiling",
      "hosts",
      "status",
      "updatedAt",
      "description",
      "publicFields",
      "secretFields",
      "binding",
      "policy",
      "injection",
      "version",
      "lastUsedAt",
      "rotatedAt",
    ])
  })

  test("of a missing item exits 1 with the vault's next", async () => {
    await enrolled()
    const result = await runJv(["show", "nope-item", "--json"], env)
    expect(result.code).toBe(EXIT.error)
    expect(json(result)).toEqual({ error: "not_found", message: "No item nope-item.", next: { command: "mehen ls", say: "List the items." } })
  })

  test("with an invalid slug is a usage error and sends nothing", async () => {
    await enrolled()
    const before = vault.seen.length
    expect((await runJv(["show", "Bad_Slug"], env)).code).toBe(EXIT.usage)
    expect(vault.seen.length).toBe(before)
  })
})

describe("the pieces", () => {
  const now = new Date("2026-10-24T17:09:30.000Z")

  test("relativeAgo", () => {
    expect(relativeAgo("2026-10-24T17:09:00.000Z", now)).toBe("just now")
    expect(relativeAgo("2026-10-24T17:06:12.000Z", now)).toBe("3 min ago")
    expect(relativeAgo("2026-10-24T15:10:00.000Z", now)).toBe("2 h ago")
    expect(relativeAgo("2026-10-23T05:00:00.000Z", now)).toBe("36 h ago")
    expect(relativeAgo("2026-10-20T17:00:00.000Z", now)).toBe("4 days ago")
    expect(relativeAgo("yesterday", now)).toBeNull()
  })

  test("lastUsedText", () => {
    expect(lastUsedText(null, now)).toBe("never")
    expect(lastUsedText("2026-10-24T17:06:12.000Z", now, "UTC")).toBe("2026-10-24 17:06 (3 min ago)")
    expect(lastUsedText("2026-10-24T17:06:12.000Z", now, "Europe/London")).toBe("2026-10-24 18:06 (3 min ago)")
    expect(lastUsedText("garbage", now)).toBe("garbage")
  })

  test("statusWord uses the status tones and plain words", () => {
    const s = styler(true)
    expect(statusWord("active", s)).toEqual({ text: "active", style: "ok" })
    expect(statusWord("needs_reauth", s)).toEqual({ text: "needs reauth", style: "warn" })
    expect(statusWord("refresh_retrying", s)).toEqual({ text: "refresh retrying", style: "warn" })
    expect(statusWord("disabled", s)).toEqual({ text: "disabled", style: "danger" })
    expect(statusWord("disabled", plainStyler())).toEqual({ text: "disabled" })
  })

  test("itemPolicyLines counts rules and puts anything else on the default's line", () => {
    expect(itemPolicyLines({ slug: "k", policy: { default: "allow", rules: [] } })).toEqual({ heading: "allow by default (no rules)", allowed: "anything", approve: "nothing", deny: "nothing" })
    expect(itemPolicyLines({ slug: "k", policy: { default: "deny", rules: [{ action: "allow", methods: ["GET"] }] } })).toEqual({
      heading: "deny by default (1 rule; mehen show k --json for it)",
      allowed: "GET anywhere",
      approve: "nothing",
      deny: "anything else",
    })
    const many = itemPolicyLines({
      slug: "k",
      policy: { default: "approve", rules: ["/a", "/b", "/c", "/d", "/e"].map((p) => ({ action: "approve" as const, methods: ["POST"], paths: [p] })) },
    })
    expect(many.approve).toBe("POST on /a; POST on /b; POST on /c; (2 more); anything else")
  })

  test("tryCommand refuses anything that is not a plain request inside the binding", () => {
    expect(tryCommand("k", { hosts: ["api.openai.com"] })).toBe("mehen check k GET https://api.openai.com/")
    expect(tryCommand("k", { hosts: ["gmail.googleapis.com"], paths: ["/gmail/v1/**"] })).toBe("mehen check k GET https://gmail.googleapis.com/gmail/v1")
    expect(tryCommand("k", { hosts: ["api.example.com"], paths: ["/v1/things/*/send", "/v2/**"] })).toBe("mehen check k GET https://api.example.com/v1/things/example/send")
    expect(tryCommand("k", { hosts: ["api.example.com"], paths: ["/a/**/b"] })).toBe("mehen check k GET https://api.example.com/a/b")
    expect(tryCommand("k", { hosts: ["*.example.com"] })).toBeNull()
    expect(tryCommand("k", { hosts: ["*.example.com", "api.example.com"] })).toBe("mehen check k GET https://api.example.com/")
    expect(tryCommand("k", { hosts: ["api.example.com"], schemes: ["wss"] })).toBeNull()
    expect(tryCommand("k", { hosts: ["api.example.com"], schemes: ["http"], ports: [8080] })).toBeNull()
    expect(tryCommand("k", { hosts: ["api.example.com"], methods: ["PATCH", "PUT"] })).toBe("mehen check k PATCH https://api.example.com/")
    expect(tryCommand("k", { hosts: ["api.example.com"], methods: ["POST", "GET"] })).toBe("mehen check k GET https://api.example.com/")
    expect(tryCommand("k", { hosts: ["api.example.com"], methods: ["GET; rm -rf"] })).toBeNull()
    expect(tryCommand("k", { hosts: ["api.example.com; touch x"] })).toBeNull()
    expect(tryCommand("k", { hosts: ["api.example.com"], paths: ["/v1/$(id)/x"] })).toBeNull()
    expect(tryCommand("k", { hosts: ["api.example.com"], paths: [`/v1/${RLO}x`] })).toBeNull()
    expect(tryCommand("k", { hosts: ["api.example.com"], paths: ["/v1/a b"] })).toBeNull()
  })

  test("ls and show say no host for a lease-only credential, never the reserved host", () => {
    const leaseOnly = item("jwt-secret", { kind: "generic", provider: null, ceiling: "lease", hosts: [LEASE_ONLY_HOST], binding: { hosts: [LEASE_ONLY_HOST] }, injection: null })
    const ls = lsLines([leaseOnly], plainStyler()).map(plainText).join("\n")
    expect(ls).toMatch(/jwt-secret +generic +- +- +active +no host$/)
    const show = showLines(leaseOnly, "jwt-secret", plainStyler(), { now, timeZone: "UTC" }).map(plainText).join("\n")
    expect(show).toContain("  goes to:   no host: only delivered into a process with mehen run\n")
    expect(show).not.toContain("  try:")
    expect(`${ls}${show}`).not.toContain(LEASE_ONLY_HOST)
    expect(showLines({ ...leaseOnly, kind: "hmac-key", ceiling: "sign" }, "jwt-secret", plainStyler(), { now, timeZone: "UTC" }).map(plainText)).toContain("  goes to:   no host: stored only; a human can allow mehen run by setting its ceiling to lease")
  })

  test("showLines never puts a style on text that came from the vault", () => {
    const lines = showLines(gmailAlex({ slug: `x${ESC}[31m` }), "x", styler(true), { now, timeZone: "UTC" })
    const styled = lines.flatMap((line) => (typeof line === "string" ? [] : Array.isArray(line) ? line : [line])).filter((s) => s.style !== undefined)
    expect(styled.map((s) => s.text)).toEqual(["(verified)", "active"])
  })
})

test("refusal/a saved base allow never claims to remove stronger effective floors", async () => {
  await enrolled()
  vault.items.push(item("floor-key", { policy: { default: "allow", rules: [] }, policyFloor: [{ id: "floor.test", host: "api.example.com", action: "approve", reason: "persistence", rule: { action: "approve", paths: ["/hooks/**"] }, ruleDigest: "digest" }] }))
  const result = await runJv(["show", "floor-key"], env)
  expect(result.stdout).toContain("Base policy:")
  expect(result.stdout).toContain("Effective floors:")
  expect(result.stdout).toContain("approve: api.example.com")
  expect(result.stdout).toContain("A saved base allow does not remove a floor.")
  expect(json(await runJv(["show", "floor-key", "--json"], env))).toMatchObject({ policy: { default: "allow" }, policyFloor: [{ id: "floor.test", action: "approve" }] })
})

test("show prints how careful the credential is for this machine, and nothing about other machines; --json keeps the posture's own fields", async () => {
  await enrolled()
  const catalogue = { template: "github", version: 2 }
  vault.items.push(
    item("routine-key", { posture: { level: "routine", coversThisKey: true, catalogue, machines: ["dev_other"], names: ["Other's laptop"] } as ItemDescriptionPosture }),
    item("guest-key", { posture: { level: "routine", coversThisKey: false, catalogue } }),
    item("trust-key", { posture: { level: "trust", coversThisKey: true, catalogue } }),
    item("ask-key", { posture: { level: "ask", coversThisKey: false, catalogue: null } }),
    item("old-key"),
  )
  const careful = async (slug: string) => (await runJv(["show", slug], env)).stdout.split("\n").filter((line) => line.includes("How careful"))
  expect(await careful("routine-key")).toEqual(["  How careful: routine building allowed for this machine"])
  expect(await careful("guest-key")).toEqual(["  How careful: asks for every change"])
  expect(await careful("trust-key")).toEqual(["  How careful: this machine is trusted: changes go through except those that always ask"])
  expect(await careful("ask-key")).toEqual(["  How careful: asks for every change"])
  expect(await careful("old-key")).toEqual([])
  const routine = await runJv(["show", "routine-key"], env)
  expect(routine.stdout).not.toContain("dev_other")
  expect(routine.stdout).not.toContain("Other's laptop")
  expect(json(await runJv(["show", "routine-key", "--json"], env)).posture).toEqual({ level: "routine", coversThisKey: true, catalogue })
  expect(json(await runJv(["show", "old-key", "--json"], env))).not.toHaveProperty("posture")
})
