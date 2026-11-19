import { describe, expect, test } from "bun:test"
import {
  withContext,
  type Ask,
  type AskUrl,
  adoptionAsk,
  approvalAsk,
  bundleAsk,
  policyAsk,
  askForError,
  askFromError,
  askLines,
  askNext,
  askResourceLink,
  askSay,
  askText,
  clockText,
  connectAsk,
  enrolAsk,
  expiryText,
  intakeAsk,
  reauthAsk,
  relativeExpiry,
  requestedBy,
  unfreezeAsk,
  askUrl,
  askUrlFor,
  isAskId,
  isWaitId,
  mandateAsk,
  mandatePageUrlFor,
  mandateProposalUrlFor,
} from "./ask.ts"
import { CliError } from "./errors.ts"
import type { AskVault } from "./ask.ts"
import { type Segment, plainText, qrWidth, stripStyle, styler, terminalText } from "./tty.ts"

const by = { device: "sam-mac-mini", session: "pi-4f2a" }
const now = new Date("2026-10-24T16:14:00Z")
const clock = { now, timeZone: "UTC" }
// Every link is checked against a vault with its canonical workspace slug: under
// the fresh-start model (design 15.6) only a /w/<slug>/ route of the
// context's own workspace is a trusted ask link.
const VAULT = { vaultUrl: "https://app.mehen.dev", workspaceSlug: "personal" }

// A link on the vault, checked; the test fails loudly if it is not one.
function link(url: string, vault: AskVault = VAULT): AskUrl {
  const checked = askUrl(url, vault)
  if (!checked) throw new Error(`test link ${url} is not on ${JSON.stringify(vault)}`)
  return checked.url
}

const text = (line: Segment[] | undefined): string => plainText(line ?? [])

const approval = approvalAsk({
  id: "apr_7Hq2",
  url: link("https://app.mehen.dev/w/personal/a/apr_7Hq2"),
  summary: "Send an email to sam@example.com",
  item: "gmail-alex",
  account: "alexrae@example.com",
  bindingCode: "K7Q2MX",
  expiresAt: "2026-10-24T17:12:00Z",
  requestedBy: by,
})
const intake = intakeAsk({
  id: "int_3kQ9vXyZ7",
  url: link("https://app.mehen.dev/w/personal/i/int_3kQ9vXyZ7"),
  name: "openai-new",
  kind: "api-key",
  provider: "openai",
  reason: "summarise the support inbox",
  expiresAt: "2026-10-25T16:20:24.164Z",
  requestedBy: by,
})
const enrol = enrolAsk({
  id: "enr_9m2kQ",
  url: link("https://app.mehen.dev/w/personal/e/K7Q2MXAB"),
  name: "sam-mac-mini",
  backend: "secure-enclave",
  fingerprint: "ZLSQ 8ZY0 FNHK WLS5",
  expiresAt: "2026-10-24T16:29:00Z",
  requestedBy: by,
})
const connect = connectAsk({
  id: "con_1",
  url: link("https://app.mehen.dev/w/personal/c/con_1"),
  name: "gmail-alex",
  provider: "google-gmail",
  account: "alex@example.com",
  reason: "read and draft replies",
  expiresAt: "2026-10-24T16:29:00Z",
  requestedBy: by,
})
const reconnect = reauthAsk({ id: "con_9Kp", url: link("https://app.mehen.dev/w/personal/c/con_9Kp"), name: "gmail-alex", provider: "google-gmail", account: "alex@example.com", expiresAt: null, requestedBy: by })
const unfreeze = unfreezeAsk({ url: link("https://app.mehen.dev/w/personal/"), requestedBy: by })

const EVERY_KIND: Ask[] = [enrol, intake, connect, reconnect, approval, unfreeze]

describe("builders", () => {
  test("an enrol ask carries its intent as intent and whether it was claimed, never a verified workspace; no other kind carries either", () => {
    const withIntent = enrolAsk({ id: "enr_9m2kQ", url: link("https://app.mehen.dev/w/personal/e/K7Q2MXAB"), name: "m", backend: "software", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", expiresAt: null, requestedBy: by, intent: { workspace: "personal", team: "ci" }, claimed: true })
    expect(withIntent).toMatchObject({ intent: { workspace: "personal", team: "ci" }, claimed: true })
    expect(withIntent.context).toBeUndefined()
    for (const ask of [intake, connect, reconnect, approval, unfreeze]) {
      expect("intent" in ask).toBe(false)
      expect("claimed" in ask).toBe(false)
    }
  })

  test("each kind carries the contract's fields, title and check label", () => {
    expect(enrol).toMatchObject({ kind: "enrol", title: "Approve this machine", check: { label: "fingerprint", value: "ZLSQ 8ZY0 FNHK WLS5" }, wait: "mehen wait enr_9m2kQ --timeout 60 --json", account: null })
    expect(enrol.what).toBe("Approve sam-mac-mini (Secure Enclave key) and choose what it may use")
    expect(intake).toMatchObject({ kind: "intake", title: "Add a credential", check: { label: "asked by", value: "sam-mac-mini, session pi-4f2a" }, wait: "mehen wait int_3kQ9vXyZ7 --timeout 60 --json" })
    expect(intake.what).toBe("Add openai-new (OpenAI API key, goes to api.openai.com) so the agent can summarise the support inbox")
    expect(connect).toMatchObject({ kind: "connect", title: "Connect an account", check: { label: "account", value: "alex@example.com" }, account: "alex@example.com" })
    expect(connect.what).toBe("Connect gmail-alex to Gmail as alex@example.com so the agent can read and draft replies")
    expect(reconnect).toMatchObject({ kind: "reconnect", title: "Reconnect an account", check: { label: "account", value: "alex@example.com" }, what: "Reconnect gmail-alex to Gmail as alex@example.com" })
    expect(approval).toMatchObject({ kind: "approval", title: "Approve a request", check: { label: "code", value: "K7Q2MX" }, account: "alexrae@example.com", wait: "mehen wait apr_7Hq2 --timeout 60 --json" })
    expect(approval.what).toBe("Send an email to sam@example.com, from gmail-alex (alexrae@example.com)")
    expect(unfreeze).toMatchObject({ kind: "unfreeze", id: "", title: "Unfreeze the vault", check: null, expiresAt: null, wait: null })
    for (const ask of EVERY_KIND) {
      expect(Object.keys(ask).sort()).toEqual(["account", "check", "expiresAt", "id", "kind", "requestedBy", "title", "url", "wait", "what"])
    }
  })

  test("an intake without a template describes the kind and the proposed hosts; an oauth-client intake names the redirect URI", () => {
    const proposed = intakeAsk({ id: "int_1", url: link("https://v/w/vee/i/int_1", { vaultUrl: "https://v", workspaceSlug: "vee" }), name: "acme-key", kind: "api-key", provider: null, reason: "call Acme", hosts: ["api.acme.test"], expiresAt: null, requestedBy: by })
    expect(proposed.what).toBe("Add acme-key (api-key, goes to api.acme.test) so the agent can call Acme")
    const client = intakeAsk({ id: "int_2", url: link("https://v/w/vee/i/int_2", { vaultUrl: "https://v", workspaceSlug: "vee" }), name: "google-oauth-client", kind: "oauth-client", provider: "google-oauth-client", reason: "connect Gmail", redirectUri: "https://app.mehen.dev/oauth/callback", expiresAt: null, requestedBy: by })
    expect(client.what).toBe("Add google-oauth-client (Google OAuth client, redirect URI https://app.mehen.dev/oauth/callback) so the agent can connect Gmail")
    const noSession = intakeAsk({ ...proposed, requestedBy: { device: "box", session: null } } as never)
    expect(noSession.check).toEqual({ label: "asked by", value: "box" })
  })

  test("a connect without an expected account has no check; an approval without a binding code has none either", () => {
    expect(connectAsk({ ...connect, account: null } as never).check).toBeNull()
    expect(approvalAsk({ id: "apr_1", url: link("https://v/w/vee/a/apr_1", { vaultUrl: "https://v", workspaceSlug: "vee" }), summary: "Send", bindingCode: null, expiresAt: null, requestedBy: by }).check).toBeNull()
  })

  test("requestedBy uses the short host name and a valid MEHEN_SESSION only", () => {
    expect(requestedBy({ MEHEN_SESSION: "pi-4f2a" }).session).toBe("pi-4f2a")
    expect(requestedBy({ MEHEN_SESSION: "has spaces" }).session).toBeNull()
    expect(requestedBy({}).session).toBeNull()
    expect(requestedBy({}).device).not.toContain(".")
    expect(requestedBy({}).device.length).toBeGreaterThan(0)
  })

  test("requestedBy names the machine as enrolled in the workspace when the slot records it, else the short host name", () => {
    expect(requestedBy({ MEHEN_SESSION: "pi-4f2a" }, "tom-laptop")).toEqual({ device: "tom-laptop", session: "pi-4f2a" })
    expect(requestedBy({}, null).device).toBe(requestedBy({}).device)
    expect(requestedBy({}, null).device).not.toContain(".")
  })
})

describe("askText", () => {
  test("open: is always the second line and the check sentence always starts with the page", () => {
    for (const ask of EVERY_KIND) {
      const lines = askLines(ask, clock).map(plainText)
      expect(lines[0]).toStartWith("Human needed: ")
      expect(lines[1]).toBe(`  open:    ${ask.url}`)
      const check = lines.find((l) => l.includes("check:"))
      if (ask.check) expect(check).toMatch(/^ {2}check: {3}the page /)
      else expect(check).toBeUndefined()
    }
  })

  test("renders the approval mockup from 2.2", () => {
    expect(askText(approval, clock)).toBe(
      [
        "Human needed: approve a request",
        "  open:    https://app.mehen.dev/w/personal/a/apr_7Hq2",
        "  what:    Send an email to sam@example.com, from gmail-alex (alexrae@example.com)",
        "  check:   the page shows code K7Q2MX",
        "  expires: in 58 min (17:12)",
        "  then:    mehen wait apr_7Hq2 --timeout 60 --json",
      ].join("\n"),
    )
  })

  test("renders the intake, enrol and connect checks", () => {
    expect(askText(intake, clock)).toContain("  check:   the page says it was asked by sam-mac-mini, session pi-4f2a")
    expect(askText(intake, clock)).toContain("  expires: in 24 h (tomorrow 16:20)")
    expect(askText(enrol, clock)).toContain("  check:   the page shows fingerprint  ZLSQ 8ZY0 FNHK WLS5")
    expect(askText(connect, clock)).toContain("  check:   the page shows account alex@example.com; sign in as that account")
    expect(askText(unfreeze, clock)).not.toContain("expires:")
    expect(askText(unfreeze, clock)).not.toContain("then:")
  })

  test("then: can be replaced or dropped, and the expires line can carry a note", () => {
    expect(askText(approval, { ...clock, then: 'vault_wait { "id": "apr_7Hq2" }' })).toContain('  then:    vault_wait { "id": "apr_7Hq2" }')
    expect(askText(approval, { ...clock, then: null })).not.toContain("then:")
    expect(askText(enrol, { ...clock, expiresNote: "mehen keeps the key and issues a fresh link if it lapses" })).toContain("  expires: in 15 min (16:29); mehen keeps the key and issues a fresh link if it lapses")
  })

  test("on a TTY the check value is bold, the labels dim, and the words are unchanged", () => {
    const styled = askLines(approval, { ...clock, style: styler(true) }).map(terminalText).join("\n")
    expect(styled).toContain("\u001b[1mK7Q2MX\u001b[0m")
    expect(styled).toContain("\u001b[2mopen:   \u001b[0m")
    expect(stripStyle(styled)).toBe(askText(approval, clock))
  })

  test("text from the vault or an agent cannot steer the terminal: controls and hidden characters are spelled out", () => {
    const hostile = approvalAsk({
      id: "apr_1",
      url: link("https://vault.example/w/space/a/apr_1", { vaultUrl: "https://vault.example", workspaceSlug: "space" }),
      summary: "Send\u001b[2K\u001b[1;32mallowed\u001b[0m an email to pay\u202eexe.fdp \uFFFE[31mred",
      bindingCode: "K7\u200bQ2",
      expiresAt: null,
      requestedBy: by,
    })
    const text = askText(hostile, { ...clock, then: "mehen wait apr_1\u001b[A" })
    expect(text).not.toContain("\u001b")
    expect(text).not.toContain("\u202e")
    expect(text).not.toContain("\uFFFE")
    expect(text).toContain("Send\\u001B[2K\\u001B[1;32mallowed\\u001B[0m an email to pay[RLO U+202E]exe.fdp [NONCHAR U+FFFE][31mred")
    // At the terminal, with colour on, only the styler's own segments are styled.
    const styled = askLines(hostile, { ...clock, style: styler(true) }).map(terminalText).join("\n")
    expect(styled.match(/\u001b\[[0-9;]*m/g)?.filter((e) => e !== "\u001b[0m")).toEqual(["\u001b[36m", "\u001b[2m", "\u001b[2m", "\u001b[2m", "\u001b[1m", "\u001b[2m", "\u001b[2m"])
    expect(styled).toContain("[NONCHAR U+FFFE][31mred")
    expect(text).toContain("the page shows code K7[ZWSP U+200B]Q2")
    expect(text).toContain("then:    mehen wait apr_1\\u001B[A")
  })

  test("a QR code goes between open: and what:, two module rows per line", () => {
    const lines = askLines(approval, { ...clock, qr: { scheme: "dark" } }).map(plainText)
    const open = lines.findIndex((l) => l.includes("open:"))
    const what = lines.findIndex((l) => l.includes("what:"))
    const rows = what - open - 1
    expect(rows).toBe(Math.ceil(qrWidth(approval.url) / 2))
    for (const row of lines.slice(open + 1, what)) {
      expect(row.startsWith("  ")).toBe(true)
      expect(row.length).toBe(2 + qrWidth(approval.url))
      expect(row.slice(2)).toMatch(/^[\u2580\u2584\u2588 ]+$/)
    }
    expect(askText(approval, clock)).not.toMatch(/[\u2580\u2584\u2588]/)
  })
})

describe("expiry wording", () => {
  test("relative: minutes round up, hours and days round", () => {
    expect(relativeExpiry("2026-10-24T17:12:00Z", now)).toBe("in 58 min")
    expect(relativeExpiry("2026-10-24T17:11:40Z", now)).toBe("in 58 min")
    expect(relativeExpiry("2026-10-24T16:14:30Z", now)).toBe("in under a minute")
    expect(relativeExpiry("2026-10-25T16:20:00Z", now)).toBe("in 24 h")
    expect(relativeExpiry("2026-10-27T16:14:00Z", now)).toBe("in 3 days")
    expect(relativeExpiry("2026-10-24T16:13:00Z", now)).toBe("expired")
    expect(relativeExpiry("not a date", now)).toBeNull()
  })

  test("clock: today is a time, the next day says tomorrow, later gives the date", () => {
    expect(clockText("2026-10-24T17:12:00Z", clock)).toBe("17:12")
    expect(clockText("2026-10-25T16:20:00Z", clock)).toBe("tomorrow 16:20")
    expect(clockText("2026-10-27T09:05:00Z", clock)).toBe("27 Oct 09:05")
  })

  test("expires: unknown names the documented lifetime, and never pretends to know", () => {
    expect(expiryText({ kind: "approval", expiresAt: null }, clock)).toBe("unknown (about an hour)")
    expect(expiryText({ kind: "intake", expiresAt: null }, clock)).toBe("unknown (about 24 hours)")
    // An enrolment link is renewed in place while mehen waits: no fixed lifetime to name.
    expect(expiryText({ kind: "enrol", expiresAt: null }, clock)).toBe("unknown")
    expect(expiryText({ kind: "unfreeze", expiresAt: null }, clock)).toBe("unknown")
    expect(expiryText({ kind: "approval", expiresAt: "2026-10-24T16:00:00Z" }, clock)).toBe("expired")
  })
})

describe("askSay and askNext", () => {
  test("one sentence per kind, with the link, the check and the expiry", () => {
    expect(askSay(approval, clock)).toBe("Approve the request at https://app.mehen.dev/w/personal/a/apr_7Hq2: Send an email to sam@example.com, from gmail-alex (alexrae@example.com); the page should show code K7Q2MX; it expires in 58 min.")
    expect(askSay(intake, clock)).toBe(
      "Open https://app.mehen.dev/w/personal/i/int_3kQ9vXyZ7 to add openai-new (OpenAI API key, goes to api.openai.com) so the agent can summarise the support inbox; it goes into the vault, never to the agent; it expires in 24 h.",
    )
    expect(askSay(enrol, clock)).toBe("Approve this machine at https://app.mehen.dev/w/personal/e/K7Q2MXAB; the page should show fingerprint ZLSQ 8ZY0 FNHK WLS5; it expires in 15 min.")
    expect(askSay(connect, clock)).toBe("Open https://app.mehen.dev/w/personal/c/con_1 to connect gmail-alex to Gmail as alex@example.com so the agent can read and draft replies; sign in as alex@example.com; it expires in 15 min.")
    expect(askSay(reconnect, clock)).toBe("Open https://app.mehen.dev/w/personal/c/con_9Kp to reconnect gmail-alex to Gmail as alex@example.com; sign in as alex@example.com; the link lasts about 15 minutes.")
    expect(askSay(unfreeze, clock)).toBe("Unfreeze the vault at https://app.mehen.dev/w/personal/ with your passkey after reviewing the audit log.")
  })

  test("askNext keeps the { url, command, say } shape", () => {
    expect(askNext(approval, clock)).toEqual({ url: approval.url, command: "mehen wait apr_7Hq2 --timeout 60 --json", say: askSay(approval, clock) })
    expect(askNext(unfreeze, clock)).toEqual({ url: unfreeze.url, say: askSay(unfreeze, clock) })
    expect(askNext(intake, { ...clock, command: "mehen request --wait" }).command).toBe("mehen request --wait")
  })

  test("askResourceLink names the title and the check", () => {
    expect(askResourceLink(approval)).toEqual({ type: "resource_link", uri: approval.url, name: "Approve a request (code K7Q2MX)", description: approval.what, mimeType: "text/html" })
    expect(askResourceLink(unfreeze).name).toBe("Unfreeze the vault")
  })
})

describe("workspace-prefixed links and own-call provenance (design 15.6, threat T1)", () => {
  const origin = "https://vault.example"
  const own = { vaultUrl: origin, workspaceSlug: "northwind" }

  test("a /w/<slug>/ link is accepted only under the context's own canonical slug; an alias, a foreign slug or a slug-less check refuses it", () => {
    expect(askUrl(`${origin}/w/northwind/a/apr_1`, own) as unknown).toEqual({ url: `${origin}/w/northwind/a/apr_1`, route: { prefix: "a", id: "apr_1" }, workspace: "northwind" })
    expect(askUrl(`${origin}/w/northwind/e/ABCD2345`, own)?.route).toEqual({ prefix: "e", id: "ABCD2345" })
    expect(askUrl(`${origin}/w/northwind/items/openai`, own)?.route).toEqual({ prefix: "items", id: "openai" })
    expect(askUrl(`${origin}/w/northwind/devices`, own)?.route).toEqual({ prefix: "devices", id: "" })
    expect(askUrl(`${origin}/w/northwind/`, own)?.route).toBeNull()
    // Unprefixed routes are nobody's workspace: untrusted everywhere.
    expect(askUrl(`${origin}/a/apr_1`, own)).toBeNull()
    expect(askUrl("https://other.example/a/apr_1", own)).toBeNull()
    for (const bad of [`${origin}/w/personal/a/apr_1`, `${origin}/w/old-alias/a/apr_1`, `${origin}/w/Northwind/a/apr_1`, `${origin}/w/legacy-x/a/apr_1`, `${origin}/w/northwind/w/northwind/a/apr_1`, `${origin}/w//a/apr_1`, `${origin}/w/northwind`]) {
      expect(askUrl(bad, own)).toBeNull()
    }
    // The origin alone (no slug known) admits no prefixed link at all.
    expect(askUrl(`${origin}/w/northwind/a/apr_1`, origin)).toBeNull()
    expect(askUrl(`${origin}/w/northwind/a/apr_1`, { vaultUrl: origin, workspaceSlug: null })).toBeNull()
    // The same slug at another origin is foreign.
    expect(askUrl(`https://other.example/w/northwind/a/apr_1`, own)).toBeNull()
  })

  test("a rebuilt link is under the canonical authenticated slug only; with no slug known there is no link and no trusted ask", () => {
    expect(askUrlFor(own, "approval", "apr_1")?.url as string).toBe(`${origin}/w/northwind/a/apr_1`)
    expect(askUrlFor(origin, "approval", "apr_1")).toBeNull()
    expect(askUrlFor({ vaultUrl: origin, workspaceSlug: null }, "approval", "apr_1")).toBeNull()
    // A missing, foreign-slug or alias link is rebuilt under the context's own slug, with the warning.
    const missing = askFromError("approval_required", { message: "m", approval: "apr_1" }, { requestedBy: by, vaultUrl: own })
    expect(missing.ask?.url).toBe(`${origin}/w/northwind/a/apr_1`)
    const refused = askFromError("approval_required", { message: "m", next: { url: `${origin}/w/personal/a/apr_1`, say: "x" }, approval: "apr_1" }, { requestedBy: by, vaultUrl: own })
    expect(refused.refusedLink).toBe(true)
    expect(refused.ask?.url).toBe(`${origin}/w/northwind/a/apr_1`)
    const unprefixed = askFromError("approval_required", { message: "m", next: { url: `${origin}/a/apr_1`, say: "x" }, approval: "apr_1" }, { requestedBy: by, vaultUrl: own })
    expect(unprefixed.refusedLink).toBe(true)
    expect(unprefixed.ask?.url).toBe(`${origin}/w/northwind/a/apr_1`)
    // No slug or provenance known: no trusted card at all.
    for (const vault of [origin, { vaultUrl: origin, workspaceSlug: null }, null]) {
      const none = askFromError("approval_required", { message: "m", next: { url: `${origin}/w/northwind/a/apr_1`, say: "x" }, approval: "apr_1" }, { requestedBy: by, vaultUrl: vault })
      expect(none.ask).toBeNull()
      const frozen = askFromError("frozen", { message: "m" }, { requestedBy: by, vaultUrl: vault })
      expect(frozen.ask).toBeNull()
    }
    const accepted = askFromError("approval_required", { message: "m", next: { url: `${origin}/w/northwind/a/apr_1`, say: "x" }, approval: "apr_1" }, { requestedBy: by, vaultUrl: own })
    expect(accepted).toMatchObject({ refusedLink: false, ask: { url: `${origin}/w/northwind/a/apr_1`, id: "apr_1" } })
  })

  test("withContext attaches the authenticated call's origin, workspace and device, and nothing to a missing ask", () => {
    const ask = approvalAsk({ id: "apr_1", url: (askUrl(`${origin}/w/northwind/a/apr_1`, own) as { url: AskUrl }).url, summary: "s", bindingCode: null, expiresAt: null, requestedBy: by })
    const context = { origin, workspace: { id: "tn_12345678", slug: "northwind", name: "Northwind" }, device: "dev_12345678" }
    expect(withContext(ask, context)).toEqual({ ...ask, context })
    expect(withContext(ask, null)).toBe(ask)
    expect(withContext(null, context)).toBeNull()
    expect("context" in ask).toBe(false)
  })
})

describe("askUrl: the one way a link gets onto an Ask", () => {
  const vault: AskVault = { vaultUrl: "https://vault.example", workspaceSlug: "space" }
  const checked = (raw: unknown, v: AskVault | null = vault): string | null => askUrl(raw, v)?.url ?? null
  const built = (...args: Parameters<typeof askUrlFor>): string | null => askUrlFor(...args)?.url ?? null

  test("accepts the vault's own ask routes and canonicalises them", () => {
    expect(checked("https://vault.example/w/space/a/apr_7Hq2")).toBe("https://vault.example/w/space/a/apr_7Hq2")
    expect(checked("https://vault.example/w/space/e/ABCD2345")).toBe("https://vault.example/w/space/e/ABCD2345")
    expect(checked("https://vault.example/w/space/i/int_1")).toBe("https://vault.example/w/space/i/int_1")
    expect(checked("https://vault.example/w/space/c/con_1")).toBe("https://vault.example/w/space/c/con_1")
    expect(checked("https://vault.example/w/space/")).toBe("https://vault.example/w/space/")
    // The vault root and the bare origin are nobody's workspace.
    expect(checked("https://vault.example/")).toBeNull()
    expect(checked("https://vault.example")).toBeNull()
    expect(checked("https://VAULT.example:443/w/space/a/apr_1")).toBe("https://vault.example/w/space/a/apr_1")
    expect(checked("http://127.0.0.1:4567/w/space/a/apr_1", { vaultUrl: "http://127.0.0.1:4567", workspaceSlug: "space" })).toBe("http://127.0.0.1:4567/w/space/a/apr_1")
    expect(built(vault, "approval", "apr_9")).toBe("https://vault.example/w/space/a/apr_9")
    expect(built(vault, "enrol", "ABCD2345")).toBe("https://vault.example/w/space/e/ABCD2345")
    expect(built(vault, "intake", "int_1")).toBe("https://vault.example/w/space/i/int_1")
    expect(built(vault, "connect", "con_1")).toBe("https://vault.example/w/space/c/con_1")
    expect(built(vault, "reconnect", "con_1")).toBe("https://vault.example/w/space/c/con_1")
  })

  test("refuses a foreign origin, a lookalike host, userinfo, another port, http for https and a hidden character", () => {
    expect(checked("https://evil.example/a/apr_1")).toBeNull()
    expect(checked("https://vault.example.evil.example/a/apr_1")).toBeNull()
    expect(checked("https://vault-example.com/a/apr_1")).toBeNull()
    expect(checked("https://xn--vult-example.com/a/apr_1")).toBeNull()
    expect(checked("https://evil.example@vault.example/a/apr_1")).toBeNull()
    expect(checked("https://vault.example@evil.example/a/apr_1")).toBeNull()
    expect(checked("https://user:pw@vault.example/a/apr_1")).toBeNull()
    expect(checked("https://vault.example:8443/a/apr_1")).toBeNull()
    expect(checked("http://vault.example/a/apr_1")).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr_1\u200b")).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr\u202e_1")).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr_1\u001b[2K")).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr_1%E2%80%8B")).toBeNull()
  })

  test("refuses anything off the ask routes, a query, a fragment, a backslash or a path trick", () => {
    expect(checked("https://vault.example/login")).toBeNull()
    expect(checked("https://vault.example/w/space/a/")).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr_1/")).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr_1/x")).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr_1?x=1")).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr_1#x")).toBeNull()
    expect(checked("https://vault.example/w/space/a/..%2Fx")).toBeNull()
    expect(checked("https://vault.example\\@evil.example/a/apr_1")).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr_1 ")).toBeNull()
    expect(checked(`https://vault.example/w/space/a/${"x".repeat(65)}`)).toBeNull()
    expect(checked("javascript:alert(1)")).toBeNull()
    expect(checked("")).toBeNull()
    expect(checked(42)).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr_1", null)).toBeNull()
    expect(checked("https://vault.example/w/space/a/apr_1", "not a url")).toBeNull()
  })

  test("a vault under a path accepts only links under that path, and parses the route relative to it", () => {
    const under: AskVault = { vaultUrl: "https://host.example/vault", workspaceSlug: "space" }
    expect(checked("https://host.example/vault/w/space/a/apr_1", under)).toBe("https://host.example/vault/w/space/a/apr_1")
    expect(askUrl("https://host.example/vault/w/space/a/apr_1", under)?.route).toEqual({ prefix: "a", id: "apr_1" })
    expect(askUrl("https://host.example/vault/w/space/", under)?.route).toBeNull()
    expect(checked("https://host.example/w/space/a/apr_1", under)).toBeNull()
    expect(checked("https://host.example/vaultx/w/space/a/apr_1", under)).toBeNull()
  })

  test("a rebuilt link takes only an id with the kind's prefix and alphabet; anything else gives no link at all", () => {
    expect(isAskId("approval", "apr_7Hq2")).toBe(true)
    expect(isAskId("intake", "int_3kQ9vXyZ7")).toBe(true)
    expect(isAskId("connect", "con_1")).toBe(true)
    expect(isAskId("reconnect", "con_1")).toBe(true)
    expect(isAskId("enrol", "ABCD2345")).toBe(true)
    for (const kind of ["approval", "intake", "connect", "reconnect", "enrol"] as const) {
      const prefix = kind === "enrol" ? "" : kind === "approval" ? "apr_" : kind === "intake" ? "int_" : "con_"
      for (const tail of ["x/y", "../x", "x?y=1", "x%2fy", "x%2Fy", "x#y", "x y", "x\u200b", "", "x\\y"]) {
        expect(isAskId(kind, `${prefix}${tail}`)).toBe(false)
        expect(built(vault, kind, `${prefix}${tail}`)).toBeNull()
      }
      expect(built(vault, kind, kind === "enrol" ? "ab" : `${prefix}${"x".repeat(61)}`)).toBeNull()
    }
    // The wrong prefix for the kind is refused too, even with a clean alphabet.
    expect(built(vault, "approval", "int_1")).toBeNull()
    expect(built(vault, "intake", "apr_1")).toBeNull()
    expect(built(vault, "connect", "apr_1")).toBeNull()
    expect(built(vault, "enrol", "enr_1")).toBeNull()
    expect(isAskId("approval", 42)).toBe(false)
    // So a refused link plus a hostile id leaves nothing to hand over.
    const synthesis = askFromError("approval_required", { message: "m", next: { url: "https://evil.example/a/x", say: "x" }, approval: "apr_1/../../admin" }, { requestedBy: by, vaultUrl: vault })
    expect(synthesis).toEqual({ ask: null, refusedLink: true })
  })

  test("a mandate proposal's sign page is the one link with a query: exactly ?proposal=<mdp_ id> on /sign-mandate under the own slug", () => {
    const page = "https://vault.example/w/space/sign-mandate?proposal=mdp_7Hq2"
    expect(askUrl(page, vault) as unknown).toEqual({ url: page, route: { prefix: "sign-mandate", id: "mdp_7Hq2" }, workspace: "space" })
    expect(mandateProposalUrlFor(vault, "mdp_7Hq2")?.url as string | undefined).toBe(page)
    for (const raw of [
      "https://vault.example/w/other/sign-mandate?proposal=mdp_7Hq2",
      "https://evil.example/w/space/sign-mandate?proposal=mdp_7Hq2",
      "https://vault.example/w/space/mandates/edit?proposal=mdp_7Hq2",
      "https://vault.example/w/space/sign-mandate?proposal=mdt_7Hq2",
      "https://vault.example/w/space/sign-mandate?proposal=mdp_7Hq2&next=x",
      "https://vault.example/w/space/sign-mandate?proposal=mdp_7Hq2?",
      "https://vault.example/w/space/sign-mandate?proposal=mdp_7Hq2#x",
      "https://vault.example/w/space/sign-mandate?next=mdp_7Hq2",
      "https://vault.example/w/space/sign-mandate?proposal=mdp_a%2Fb",
      "https://vault.example/w/space/a/apr_1?proposal=mdp_7Hq2",
      "https://vault.example/w/space/sign-mandate",
    ]) expect(checked(raw), raw).toBeNull()
    for (const id of ["mdp_", "mdp_a/b", "mdp_a&x=1", "mdt_live", `mdp_${"x".repeat(61)}`]) expect(mandateProposalUrlFor(vault, id), id).toBeNull()
    expect(mandateProposalUrlFor({ vaultUrl: "https://vault.example", workspaceSlug: null }, "mdp_7Hq2")).toBeNull()
  })

  test("a mandate's own page is /mandates/<mdt_ id> under the own slug, with no query, and the builder takes only an mdt_ id", () => {
    const page = "https://vault.example/w/space/mandates/mdt_7Hq2"
    expect(askUrl(page, vault) as unknown).toEqual({ url: page, route: { prefix: "mandates", id: "mdt_7Hq2" }, workspace: "space" })
    expect(mandatePageUrlFor(vault, "mdt_7Hq2")?.url as string | undefined).toBe(page)
    for (const url of [
      "https://vault.example/w/other/mandates/mdt_7Hq2",
      "https://evil.example/w/space/mandates/mdt_7Hq2",
      "https://vault.example/mandates/mdt_7Hq2",
      "https://vault.example/w/space/mandates/mdt_7Hq2?proposal=mdp_1",
      "https://vault.example/w/space/mandates/mdt_7Hq2#x",
      "https://vault.example/w/space/mandates/mdp_7Hq2",
      "https://vault.example/w/space/mandates/mdt_7Hq2/uses",
      "https://vault.example/w/space/mandates/",
      "https://vault.example/w/space/mandates/mdt_a%2Fb",
      "https://vault.example/w/space/mandates/mdt%5F7Hq2",
      "https://vault.example/w/space/mandates/mdt_7Hq2%5F",
      "https://vault.example/w/space/mandates/mdt_7Hq2/",
      "https://vault.example/w/space/mandates/mdt_7Hq2?",
      "https://vault.example/w/space/mandates/mdt_7Hq2?x=1",
    ]) expect(askUrl(url, vault), url).toBeNull()
    for (const id of ["mdt_", "mdt_a/b", "mdp_7Hq2", `mdt_${"x".repeat(61)}`]) expect(mandatePageUrlFor(vault, id), id).toBeNull()
    expect(mandatePageUrlFor({ vaultUrl: "https://vault.example", workspaceSlug: null }, "mdt_7Hq2")).toBeNull()
    expect(askFromError("approval_required", { message: "m", next: { url: page, say: "x" }, approval: "apr_1" }, { requestedBy: by, vaultUrl: vault })).toEqual({ ask: null, refusedLink: true })
  })

  test("a mandate ask carries the sign page and its wait, and says nothing changes until the person signs", () => {
    const input = { id: "mdp_7Hq2", url: "https://vault.example/w/space/sign-mandate?proposal=mdp_7Hq2" as AskUrl, what: "Let test-machine read without asking you", expiresAt: null, requestedBy: by }
    const ask = mandateAsk(input)
    expect(ask).toMatchObject({ kind: "mandate", title: "Trust this machine", wait: "mehen wait mdp_7Hq2 --timeout 60 --json", account: null })
    expect(askSay(ask)).toContain("Nothing changes until you sign it with your passkey.")
    expect(askSay(mandateAsk({ ...input, what: "Let test-machine read without asking you: Nightly triage." }))).toBe("Review what this machine asks to do without asking you at https://vault.example/w/space/sign-mandate?proposal=mdp_7Hq2: Let test-machine read without asking you: Nightly triage. Nothing changes until you sign it with your passkey.")
    expect(() => mandateAsk({ ...input, id: "mdp_a/b" })).toThrow()
  })

  test("the parsed route comes back with the url, so nobody reparses the pathname", () => {
    expect(askUrl("https://vault.example/w/space/a/apr_1", vault) as unknown).toEqual({ url: "https://vault.example/w/space/a/apr_1", route: { prefix: "a", id: "apr_1" }, workspace: "space" })
    expect(askUrl("https://vault.example/w/space/e/ABCD2345", vault)?.route).toEqual({ prefix: "e", id: "ABCD2345" })
    expect(askUrl("https://vault.example/w/space/i/int_1", vault)?.route).toEqual({ prefix: "i", id: "int_1" })
    expect(askUrl("https://vault.example/w/space/c/con_1", vault)?.route).toEqual({ prefix: "c", id: "con_1" })
    expect(askUrl("https://vault.example/w/space/", vault) as unknown).toEqual({ url: "https://vault.example/w/space/", route: null, workspace: "space" })
    expect(askUrlFor(vault, "reconnect", "con_9")?.route).toEqual({ prefix: "c", id: "con_9" })
  })

  test("the QR is drawn from the printed string only, and never for a url that would print differently", () => {
    const fine = askLines(approval, { ...clock, qr: { scheme: "dark" } }).map(plainText)
    expect(fine.some((l) => /[\u2580\u2584\u2588]/.test(l))).toBe(true)
    const forged = { ...approval, url: "https://app.mehen.dev/w/personal/a/apr_7Hq2\u200b" }
    const lines = askLines(forged, { ...clock, qr: { scheme: "dark" } }).map(terminalText)
    expect(lines[1]).toBe("  open:    https://app.mehen.dev/w/personal/a/apr_7Hq2[ZWSP U+200B]")
    expect(lines.some((l) => /[\u2580\u2584\u2588]/.test(l))).toBe(false)
  })
})

describe("synthesis from a vault error", () => {
  const vaultUrl: AskVault = { vaultUrl: "https://vault.example", workspaceSlug: "space" }
  const context = { requestedBy: by, vaultUrl }
  const unknownVault = { requestedBy: by, vaultUrl: null }

  test("approval_required with a binding code becomes an approval ask with a code check", () => {
    const { ask, refusedLink } = askFromError(
      "approval_required",
      { message: "Send an email: this needs a human's approval first.", next: { url: "https://vault.example/w/space/a/apr_7Hq2", command: "mehen wait apr_7Hq2", say: "x" }, approval: "apr_7Hq2", bindingCode: "K7Q2MX" },
      context,
    )
    expect(refusedLink).toBe(false)
    expect(ask).toEqual({
      kind: "approval",
      id: "apr_7Hq2",
      url: "https://vault.example/w/space/a/apr_7Hq2",
      title: "Approve a request",
      what: "Send an email: this needs a human's approval first",
      check: { label: "code", value: "K7Q2MX" },
      expiresAt: null,
      account: null,
      requestedBy: by,
      wait: "mehen wait apr_7Hq2 --timeout 60 --json",
    })
  })

  test("without a binding code there is no check: a code is never invented", () => {
    const { ask } = askFromError("approval_required", { message: "Needs approval.", next: { url: "https://vault.example/w/space/a/apr_1", say: "x" }, approval: "apr_1" }, context)
    expect(ask?.check).toBeNull()
    expect(ask?.id).toBe("apr_1")
  })

  test("expiresAt is copied only when the vault sent it", () => {
    const sent = askFromError("approval_required", { message: "m", next: { url: "https://vault.example/w/space/a/apr_1", say: "x" }, approval: "apr_1", expiresAt: "2026-10-24T17:00:00Z" }, context)
    expect(sent.ask?.expiresAt).toBe("2026-10-24T17:00:00Z")
    const unsent = askFromError("approval_required", { message: "m", next: { url: "https://vault.example/w/space/a/apr_1", say: "x" }, approval: "apr_1" }, context)
    expect(unsent.ask?.expiresAt).toBeNull()
  })

  test("an approval id comes from the body or the link, and a missing link is built from the vault URL", () => {
    expect(askFromError("approval_required", { message: "m", next: { url: "https://vault.example/w/space/a/apr_9", say: "x" } }, context).ask?.id).toBe("apr_9")
    expect(askFromError("approval_required", { message: "m", approval: "apr_9" }, context).ask?.url).toBe("https://vault.example/w/space/a/apr_9")
    expect(askFromError("approval_required", { message: "m", approval: "apr_9" }, unknownVault)).toEqual({ ask: null, refusedLink: false })
  })

  test("a link that is not on the vault is refused: never on the ask, and flagged so the caller warns", () => {
    for (const url of [
      "https://evil.example/a/apr_1",
      "https://vault.example.evil.example/a/apr_1",
      "https://evil.example@vault.example/a/apr_1",
      "https://vault.example:8443/a/apr_1",
      "http://vault.example/a/apr_1",
      "https://vault.example/w/space/a/apr_1\u200b",
    ]) {
      // With an approval id the ask is rebuilt on the vault's own link.
      const rebuilt = askFromError("approval_required", { message: "m", next: { url, say: "x" }, approval: "apr_1", bindingCode: "K7" }, context)
      expect(rebuilt.refusedLink).toBe(true)
      expect(rebuilt.ask?.url).toBe("https://vault.example/w/space/a/apr_1")
      // Without one there is nothing safe to hand over.
      expect(askFromError("approval_required", { message: "m", next: { url, say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
      expect(askFromError("needs_reauth", { message: "m", next: { url, say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
      expect(askFromError("intake_required", { message: "m", next: { url, say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
      expect(askFromError("device_pending", { message: "m", next: { url, say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
      const frozen = askFromError("frozen", { message: "m", next: { url, say: "x" } }, context)
      expect(frozen.refusedLink).toBe(true)
      expect(frozen.ask?.url).toBe("https://vault.example/w/space/")
    }
  })

  test("under a vault sub-path the id and wait command still come from the link", () => {
    const sub = { requestedBy: by, vaultUrl: { vaultUrl: "https://host.example/vault", workspaceSlug: "space" } }
    const reauth = askFromError("needs_reauth", { message: "m", next: { url: "https://host.example/vault/w/space/c/con_9", say: "x" } }, sub)
    expect(reauth.ask).toMatchObject({ id: "con_9", url: "https://host.example/vault/w/space/c/con_9", wait: "mehen wait con_9 --timeout 60 --json" })
    const approval = askFromError("approval_required", { message: "m", next: { url: "https://host.example/vault/w/space/a/apr_1", say: "x" } }, sub)
    expect(approval.ask).toMatchObject({ id: "apr_1", url: "https://host.example/vault/w/space/a/apr_1", wait: "mehen wait apr_1 --timeout 60 --json" })
    const intake = askFromError("intake_required", { message: "m", next: { url: "https://host.example/vault/w/space/i/int_5", say: "x" } }, sub)
    expect(intake.ask).toMatchObject({ id: "int_5", wait: "mehen wait int_5 --timeout 60 --json" })
    const rebuilt = askFromError("approval_required", { message: "m", approval: "apr_2" }, sub)
    expect(rebuilt.ask?.url).toBe("https://host.example/vault/w/space/a/apr_2")
    const frozen = askFromError("frozen", { message: "m" }, sub)
    expect(frozen.ask?.url).toBe("https://host.example/vault/w/space/")
  })

  test("a malformed id with an otherwise valid link, or a body id that does not match the route, refuses the ask as a bad link", () => {
    const good = "https://vault.example/w/space/a/apr_1"
    for (const approval of ["apr_1/../../admin", "apr_1?x=1", "apr_1%2Fx", "int_1", "APR_1", "apr_", "x".repeat(70)]) {
      expect(askFromError("approval_required", { message: "m", next: { url: good, say: "x" }, approval, bindingCode: "K7" }, context)).toEqual({ ask: null, refusedLink: true })
      expect(askFromError("approval_required", { message: "m", approval, bindingCode: "K7" }, context)).toEqual({ ask: null, refusedLink: true })
    }
    // A well-formed body id that is not the route's id.
    expect(askFromError("approval_required", { message: "m", next: { url: good, say: "x" }, approval: "apr_2" }, context)).toEqual({ ask: null, refusedLink: true })
    // The route's own id wins when the body has none; when both agree the ask is built.
    expect(askFromError("approval_required", { message: "m", next: { url: good, say: "x" } }, context).ask).toMatchObject({ id: "apr_1", wait: "mehen wait apr_1 --timeout 60 --json" })
    expect(askFromError("approval_required", { message: "m", next: { url: good, say: "x" }, approval: "apr_1" }, context).ask).toMatchObject({ id: "apr_1" })
    // A link whose route is another kind's, or whose id lacks the prefix, is a bad link for this kind.
    expect(askFromError("needs_reauth", { message: "m", next: { url: good, say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
    expect(askFromError("needs_reauth", { message: "m", next: { url: "https://vault.example/w/space/c/nope", say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
    expect(askFromError("intake_required", { message: "m", next: { url: "https://vault.example/w/space/c/con_1", say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
    expect(askFromError("device_pending", { message: "m", next: { url: "https://vault.example/w/space/a/apr_1", say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
    expect(askFromError("frozen", { message: "m", next: { url: good, say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
  })

  test("a builder refuses an id the vault could not have issued, so it never reaches an Ask or a wait command", () => {
    expect(() => approvalAsk({ id: "apr_1/../x", url: link("https://app.mehen.dev/w/personal/a/apr_1"), summary: "s", bindingCode: null, expiresAt: null, requestedBy: by })).toThrow("does not recognise")
    expect(() => intakeAsk({ id: "int_1\u200b", url: link("https://app.mehen.dev/w/personal/i/int_1"), name: "n", kind: "api-key", provider: null, reason: null, expiresAt: null, requestedBy: by })).toThrow("does not recognise")
    expect(() => connectAsk({ id: "apr_1", url: link("https://app.mehen.dev/w/personal/c/con_1"), name: "n", provider: "google-gmail", account: null, reason: null, expiresAt: null, requestedBy: by })).toThrow("does not recognise")
    expect(() => enrolAsk({ id: "ABCD2345", url: link("https://app.mehen.dev/w/personal/e/ABCD2345"), name: "n", backend: "software", fingerprint: "f", expiresAt: null, requestedBy: by })).toThrow("does not recognise")
    expect(isWaitId("enrol", "enr_9m2kQ")).toBe(true)
    expect(isWaitId("approval", "apr_1")).toBe(true)
    expect(isWaitId("approval", "apr_1 ")).toBe(false)
    // An empty id is allowed (no wait command) and never becomes a command.
    expect(approvalAsk({ id: "", url: link("https://app.mehen.dev/w/personal/a/apr_1"), summary: "s", bindingCode: null, expiresAt: null, requestedBy: by }).wait).toBeNull()
  })

  test("with no known vault URL nothing can be checked, so no link is handed over", () => {
    const result = askFromError("approval_required", { message: "m", next: { url: "https://vault.example/w/space/a/apr_1", say: "x" }, approval: "apr_1" }, unknownVault)
    expect(result).toEqual({ ask: null, refusedLink: true })
  })

  test("needs_reauth becomes a reconnect ask with no check and no account", () => {
    const { ask } = askFromError("needs_reauth", { message: '"gmail-alex" must be reconnected.', next: { url: "https://vault.example/w/space/c/con_9Kp", command: "mehen wait con_9Kp", say: "x" } }, context)
    expect(ask).toMatchObject({ kind: "reconnect", id: "con_9Kp", check: null, account: null, wait: "mehen wait con_9Kp --timeout 60 --json", what: '"gmail-alex" must be reconnected' })
    expect(askFromError("needs_reauth", { message: "m" }, context)).toEqual({ ask: null, refusedLink: false })
  })

  test("needs_reauth on a credential's own page (an API key, or a rejected OAuth client) becomes a reconnect ask with nothing to wait on", () => {
    const url = "https://vault.example/w/space/items/openai-personal"
    const { ask, refusedLink } = askFromError("needs_reauth", { message: '"openai-personal" needs to be set up again by a human.', next: { url, say: "x" } }, context)
    expect(refusedLink).toBe(false)
    expect(ask).toMatchObject({ kind: "reconnect", id: "", url, wait: null, check: null, what: '"openai-personal" needs to be set up again by a human' })
    const sub = askFromError("needs_reauth", { message: "m", next: { url: "https://host.example/vault/w/space/items/google-oauth-client", say: "x" } }, { requestedBy: by, vaultUrl: { vaultUrl: "https://host.example/vault", workspaceSlug: "space" } })
    expect(sub.ask).toMatchObject({ url: "https://host.example/vault/w/space/items/google-oauth-client", wait: null })
    // Only needs_reauth may send a human to a credential's page.
    for (const code of ["approval_required", "intake_required", "device_pending", "frozen"] as const) {
      expect(askFromError(code, { message: "m", next: { url, say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
    }
  })

  test("a credential page link is a slug and nothing else", () => {
    expect(askUrl("https://vault.example/w/space/items/gmail-alex", vaultUrl)).toMatchObject({ url: "https://vault.example/w/space/items/gmail-alex", route: { prefix: "items", id: "gmail-alex" } })
    for (const bad of ["/items/", "/items/Gmail", "/items/a", "/items/a--b", "/items/ab-", "/items/1ab", "/items/ab/c", "/items/ab%2Fc", "/items/ab_c", "/items/ab?x=1", "/item/ab", `/items/a${"b".repeat(64)}`]) {
      expect(askUrl(`https://vault.example/w/space${bad}`, vaultUrl)).toBeNull()
    }
    expect(askUrl("https://evil.example/items/gmail-alex", "https://vault.example")).toBeNull()
  })

  test("the machines page and a project's page pass, so a refusal that names them shows the link, and never become an ask", () => {
    expect(askUrl("https://vault.example/w/space/devices", vaultUrl) as unknown).toEqual({ url: "https://vault.example/w/space/devices", route: { prefix: "devices", id: "" }, workspace: "space" })
    expect(askUrl("https://host.example/vault/w/space/projects/prj_bkjSUcvKNZ", { vaultUrl: "https://host.example/vault", workspaceSlug: "space" }) as unknown).toEqual({ url: "https://host.example/vault/w/space/projects/prj_bkjSUcvKNZ", route: { prefix: "projects", id: "prj_bkjSUcvKNZ" }, workspace: "space" })
    for (const bad of ["/devices/", "/devices/dev_1", "/projects", "/projects/", "/projects/sweep-app", "/projects/prj_1/x", "/projects/prj_1?env=prod", "/projects/prj_a.b", `/projects/prj_${"a".repeat(65)}`]) {
      expect(askUrl(`https://vault.example/w/space${bad}`, vaultUrl)).toBeNull()
    }
    expect(askUrl("https://evil.example/devices", "https://vault.example")).toBeNull()
    for (const url of ["https://vault.example/w/space/devices", "https://vault.example/w/space/projects/prj_1"]) {
      for (const code of ["approval_required", "needs_reauth", "intake_required", "device_pending", "frozen"] as const) {
        expect(askFromError(code, { message: "m", next: { url, say: "x" } }, context)).toEqual({ ask: null, refusedLink: true })
      }
    }
  })

  test("frozen becomes an unfreeze ask on the vault's link", () => {
    const { ask } = askFromError("frozen", { message: "The vault is frozen.", next: { url: "https://vault.example/w/space/", say: "x" } }, context)
    expect(ask).toMatchObject({ kind: "unfreeze", id: "", url: "https://vault.example/w/space/", check: null, wait: null })
    expect(askFromError("frozen", { message: "m" }, context).ask?.url).toBe("https://vault.example/w/space/")
    expect(askFromError("frozen", { message: "m" }, unknownVault)).toEqual({ ask: null, refusedLink: false })
  })

  test("intake_required and device_pending take their kind from the link", () => {
    const intakeAskFromError = askFromError("intake_required", { message: "No such item yet.", next: { url: "https://vault.example/w/space/i/int_5", say: "x" } }, context).ask
    expect(intakeAskFromError).toMatchObject({ kind: "intake", id: "int_5", check: { label: "asked by", value: "sam-mac-mini, session pi-4f2a" }, wait: "mehen wait int_5 --timeout 60 --json" })
    const pending = askFromError("device_pending", { message: "Not approved yet.", next: { url: "https://vault.example/w/space/e/ABCD2345", say: "x" } }, context).ask
    expect(pending).toMatchObject({ kind: "enrol", id: "", check: null, wait: null })
  })

  test("other codes, even with a link, get no ask and no warning", () => {
    for (const code of ["binding_refused", "policy_denied", "rate_limited", "usage", "timeout"] as const) {
      expect(askFromError(code, { message: "m", next: { url: "https://evil.example/a/apr_1", say: "x" }, approval: "apr_1", bindingCode: "K7" }, context)).toEqual({ ask: null, refusedLink: false })
    }
  })

  test("askForError prefers an attached ask and otherwise synthesises from the CliError", () => {
    const attached = new CliError("approval_required", "m", null, { ask: approval })
    expect(askForError(attached, {}, vaultUrl)).toEqual({ ask: approval, refusedLink: false })
    const synthesised = askForError(new CliError("approval_required", "m", { url: "https://vault.example/w/space/a/apr_1", say: "x" }, { approval: "apr_1", bindingCode: "Q7", expiresAt: "2026-10-24T17:00:00Z" }), { MEHEN_SESSION: "s1" }, vaultUrl)
    expect(synthesised.ask).toMatchObject({ kind: "approval", id: "apr_1", check: { label: "code", value: "Q7" }, expiresAt: "2026-10-24T17:00:00Z", requestedBy: { session: "s1" } })
    expect(askForError(new CliError("usage", "m"), {}, vaultUrl)).toEqual({ ask: null, refusedLink: false })
  })
})


describe("security notice links", () => {
  test("accepts only the exact security anchor, and only for notice delivery", () => {
    const url = `${VAULT.vaultUrl}/settings#security`
    expect(String(askUrl(url, VAULT, { purpose: "security-notice" })?.url)).toBe(url)
    expect(askUrl(url, VAULT)).toBeNull()
    expect(String(askUrl("https://vault.test/base/settings#security", "https://vault.test/base", { purpose: "security-notice" })?.url)).toBe("https://vault.test/base/settings#security")
  })

  test.each([
    `${VAULT.vaultUrl}/settings#other`, `${VAULT.vaultUrl}/settings?x=1#security`,
    "https://evil.example/settings#security", `${VAULT.vaultUrl}/settingsx#security`,
    `${VAULT.vaultUrl}/w/personal/a/apr_1#security`, `${VAULT.vaultUrl}/settings`, `${VAULT.vaultUrl}/settings#`,
    `${VAULT.vaultUrl}/settings#security#other`, `${VAULT.vaultUrl}/settings#%73ecurity`,
    `${VAULT.vaultUrl}/x/../settings#security`, `${VAULT.vaultUrl}/settings#security\u200b`,
    "https://user@app.mehen.dev/settings#security",
    "https://app.mehen.dev:8443/settings#security",
    "http://app.mehen.dev/settings#security",
  ])("refuses a non-notice link: %s", (url) => {
    expect(askUrl(url, VAULT, { purpose: "security-notice" })).toBeNull()
    expect(askUrl(url, VAULT)).toBeNull()
  })
})

describe("policy asks", () => {
  const id = "pol_A-b_9"
  const input = { id, url: link(`${VAULT.vaultUrl}/w/personal/p/${id}`), summary: "Relax this route", bindingCode: "K7Q2MX", expiresAt: null, requestedBy: by }

  test("uses the policy route, title, lifetime and checked wait id", () => {
    const ask = policyAsk(input)
    expect(ask).toMatchObject({ kind: "policy", id, title: "Allow from now on", wait: `mehen wait ${id} --timeout 60 --json`, check: { label: "code", value: "K7Q2MX" } })
    expect(String(askUrlFor(VAULT, "policy", id)?.url)).toBe(`${VAULT.vaultUrl}/w/personal/p/${id}`)
    expect(expiryText(ask, clock)).toBe("unknown (about an hour)")
    expect(askNext(ask).say).toContain("No access has changed yet.")
  })

  test("refuses malformed policy ids and mismatched routes", () => {
    for (const bad of ["", "pol_", "apr_x", "pol_x/next", "pol_x?query", "pol_x#fragment", "pol_x\n", "pol_%2f", `pol_${"x".repeat(61)}`]) {
      expect(isWaitId("policy", bad)).toBe(false)
      expect(isAskId("policy", bad)).toBe(false)
      expect(askUrlFor(VAULT, "policy", bad)).toBeNull()
      expect(() => policyAsk({ ...input, id: bad })).toThrow("The vault returned an invalid policy proposal id.")
    }
    expect(() => policyAsk({ ...input, url: link(`${VAULT.vaultUrl}/w/personal/p/pol_other`) })).toThrow(CliError)
    expect(() => policyAsk({ ...input, url: link(`${VAULT.vaultUrl}/w/personal/a/apr_x`) })).toThrow(CliError)
  })

  test("refuses foreign/lookalike origins, userinfo, encoded separators, queries, controls and fragments", () => {
    for (const bad of [
      `https://evil.example/p/${id}`, `https://app.mehen.dev.evil.example/p/${id}`, `http://app.mehen.dev/p/${id}`,
      `https://app.mehen.dev:8443/p/${id}`, `https://user@app.mehen.dev/p/${id}`,
      `${VAULT.vaultUrl}/w/personal/p/${id}%2fmore`, `${VAULT.vaultUrl}/w/personal/p/${id}%5cmore`, `${VAULT.vaultUrl}/w/personal/p/${id}?x=1`, `${VAULT.vaultUrl}/w/personal/p/${id}#security`,
      `${VAULT.vaultUrl}/w/personal/p/${id}#`, `${VAULT.vaultUrl}/w/personal/p/${id}?`, `${VAULT.vaultUrl}/w/personal/p/pol_x\n`, `${VAULT.vaultUrl}/w/personal/p/apr_x`,
    ]) expect(askUrl(bad, VAULT)).toBeNull()
  })
})

describe("adoption asks", () => {
  const id = "adp_A-b_9"

  test("live under /b/ with the adoption's own wait id, and say the values never reach the agent", () => {
    const url = askUrlFor(VAULT, "adoption", id)
    expect(String(url?.url)).toBe(`${VAULT.vaultUrl}/w/personal/b/${id}`)
    expect(url?.route).toEqual({ prefix: "b", id })
    const ask = adoptionAsk({ id, url: url?.url as AskUrl, items: 212, machine: "sam-mac-mini", expiresAt: null, requestedBy: by })
    expect(ask).toMatchObject({ kind: "adoption", id, title: "Review adopted credentials", wait: `mehen wait ${id} --timeout 60 --json`, check: { label: "asked by" } })
    expect(ask.what).toBe("Review and approve 212 credentials adopted from sam-mac-mini; they go into the vault, never to the agent")
    expect(expiryText(ask, clock)).toBe("unknown (about 24 hours)")
  })

  test("refuse another kind's id on the /b/ route and a malformed adoption id", () => {
    for (const bad of ["", "adp_", "int_x", "adp_x/next", `adp_${"x".repeat(61)}`]) {
      expect(isWaitId("adoption", bad)).toBe(false)
      expect(askUrlFor(VAULT, "adoption", bad)).toBeNull()
    }
    expect(askUrl(`${VAULT.vaultUrl}/w/personal/b/int_x`, VAULT)).toBeNull()
    expect(() => adoptionAsk({ id: "int_x", url: link(`${VAULT.vaultUrl}/w/personal/b/adp_x`), items: 1, machine: "m", expiresAt: null, requestedBy: by })).toThrow(CliError)
  })
})

describe("Review together links", () => {
  test("a bundle lives under /g/ with its own wait id; a review group's page is a /g/ link too", () => {
    const id = "bnd_A-b_9"
    const url = askUrlFor(VAULT, "bundle", id)
    expect(String(url?.url)).toBe(`${VAULT.vaultUrl}/w/personal/g/${id}`)
    expect(url?.route).toEqual({ prefix: "g", id })
    expect(isWaitId("bundle", id)).toBe(true)
    expect(askUrl(`${VAULT.vaultUrl}/w/personal/g/grp_Q2mX9`, VAULT)?.route).toEqual({ prefix: "g", id: "grp_Q2mX9" })
  })

  test("refuse another kind's id on the /g/ route, and a group id as a bundle", () => {
    for (const bad of ["apr_x", "adp_x", "int_x", "grp_", "bnd_"]) expect(askUrl(`${VAULT.vaultUrl}/w/personal/g/${bad}`, VAULT)).toBeNull()
    for (const bad of ["", "bnd_", "grp_x", "bnd_x/next", `bnd_${"x".repeat(61)}`]) {
      expect(isWaitId("bundle", bad)).toBe(false)
      expect(askUrlFor(VAULT, "bundle", bad)).toBeNull()
    }
  })

  test("an ask carries its group beside its own link, and the codes check reads as a sentence", () => {
    const grouped: Ask = { ...approval, group: { id: "grp_Q2mX9", url: `${VAULT.vaultUrl}/w/personal/g/grp_Q2mX9`, open: 3 } }
    expect(JSON.parse(JSON.stringify(grouped)).group).toEqual({ id: "grp_Q2mX9", url: `${VAULT.vaultUrl}/w/personal/g/grp_Q2mX9`, open: 3 })
    const bundle: Ask = { kind: "bundle", id: "bnd_1", url: link(`${VAULT.vaultUrl}/w/personal/g/bnd_1`), title: "Approve requests together", what: "Approve 2 requests", check: { label: "codes", value: "K7Q2MX, 9PZ4QA (2)" }, expiresAt: null, account: null, requestedBy: by, wait: "mehen wait bnd_1 --timeout 60 --json" }
    expect(askSay(bundle, clock)).toContain("the page should show codes K7Q2MX, 9PZ4QA (2)")
    expect(expiryText(bundle, clock)).toBe("unknown (about an hour)")
  })

  test("bundleAsk: every code in the agent's order with the count, its /g/ link and mehen wait bnd_; no codes, no check", () => {
    const url = link(`${VAULT.vaultUrl}/w/personal/g/bnd_7Hq2`)
    const ask = bundleAsk({ id: "bnd_7Hq2", url, codes: ["K7Q2MX", "9PZ4QA", "M3R8TW"], asks: 3, reason: "Set up Contoso", expiresAt: "2026-10-24T17:14:00Z", requestedBy: by })
    expect(ask).toEqual({ kind: "bundle", id: "bnd_7Hq2", url, title: "Approve requests together", what: "Approve 3 requests together: Set up Contoso", check: { label: "codes", value: "K7Q2MX, 9PZ4QA, M3R8TW (3)" }, expiresAt: "2026-10-24T17:14:00Z", account: null, requestedBy: by, wait: "mehen wait bnd_7Hq2 --timeout 60 --json" })
    expect(askSay(ask, clock)).toContain("the page should show codes K7Q2MX, 9PZ4QA, M3R8TW (3)")
    expect(bundleAsk({ id: "bnd_7Hq2", url, codes: null, asks: 1, reason: null, expiresAt: null, requestedBy: by })).toMatchObject({ what: "Approve 1 request together", check: null })
    expect(() => bundleAsk({ id: "grp_7Hq2", url, codes: null, asks: 1, reason: null, expiresAt: null, requestedBy: by })).toThrow(CliError)
  })

  test("approval_required's group goes onto the ask beside its own /a/ link, checked against this vault", () => {
    const next = { url: `${VAULT.vaultUrl}/w/personal/a/apr_1`, say: "x" }
    const group = { id: "grp_Q2mX9", url: `${VAULT.vaultUrl}/w/personal/g/grp_Q2mX9`, open: 3 }
    const grouped = askFromError("approval_required", { message: "m", next, approval: "apr_1", group }, { requestedBy: by, vaultUrl: VAULT })
    expect(grouped).toEqual({ ask: expect.objectContaining({ kind: "approval", id: "apr_1", url: next.url, group }), refusedLink: false })
    expect(askFromError("approval_required", { message: "m", next, approval: "apr_1" }, { requestedBy: by, vaultUrl: VAULT }).ask).not.toHaveProperty("group")
    // Only approval_required carries one.
    expect(askFromError("needs_reauth", { message: "m", next: { url: `${VAULT.vaultUrl}/w/personal/c/con_1`, say: "x" }, group }, { requestedBy: by, vaultUrl: VAULT }).ask).not.toHaveProperty("group")
  })

  test("a group whose link is off this vault, on another route or another id, or whose count is not a count, never reaches the ask", () => {
    const next = { url: `${VAULT.vaultUrl}/w/personal/a/apr_1`, say: "x" }
    const good = { id: "grp_Q2mX9", url: `${VAULT.vaultUrl}/w/personal/g/grp_Q2mX9`, open: 3 }
    const foreign = [
      { ...good, url: "https://evil.example/w/personal/g/grp_Q2mX9" },
      { ...good, url: `${VAULT.vaultUrl}/w/other/g/grp_Q2mX9` },
      { ...good, url: `${VAULT.vaultUrl}/w/personal/a/apr_1` },
      { ...good, url: `${VAULT.vaultUrl}/w/personal/g/grp_other` },
    ]
    for (const group of foreign) {
      const synthesis = askFromError("approval_required", { message: "m", next, approval: "apr_1", group }, { requestedBy: by, vaultUrl: VAULT })
      expect(synthesis.refusedLink).toBe(true)
      expect(synthesis.ask).toMatchObject({ id: "apr_1", url: next.url })
      expect(synthesis.ask).not.toHaveProperty("group")
    }
    for (const group of [{ ...good, id: "apr_1" }, { ...good, open: -1 }, { ...good, open: 1.5 }, { ...good, open: "3" }, "grp_Q2mX9", null]) {
      const synthesis = askFromError("approval_required", { message: "m", next, approval: "apr_1", group }, { requestedBy: by, vaultUrl: VAULT })
      expect(synthesis.ask).not.toHaveProperty("group")
    }
  })
})
