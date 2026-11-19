// Approvals bind and show every forwarded header, agent-proposed
// injections stay out of reserved headers and header maps, a stored header
// map naming a reserved header is refused, and every string a card renders
// is checked for hidden text, shows its control characters and marks the
// characters that hide or reorder text.

import { afterEach, describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import type { ApprovalSubject, RelayRequestInput } from "@mehen/protocol/api"
import { OAUTH_PROVIDERS, base64UrlEncode, bodyHash, connectionPolicy, parseDestination, utf8 } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import type { RelayMaterial } from "../src/relay/forward.ts"
import { CONTROL_WARNING, DECEPTIVE_WARNING, MAX_APPROVAL_HEADER_BYTES, presentRequest } from "../src/relay/presentation.ts"
import { setRelayServices } from "../src/relay/services.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { items } from "../src/vault/areas/items.ts"
import { authoriseRelay } from "../src/vault/areas/relay.ts"
import type { VaultContext } from "../src/vault/core.ts"
import type { ApprovalPresentation, ItemRecord, NewItem } from "../src/vault/services.ts"
import { freshTenant, testDevice as fabricatedDevice } from "./helpers.ts"

import { POLICY_DEVICE, registerPolicyDevice } from "./policy-fixtures.ts"
const testDevice = (overrides: Parameters<typeof fabricatedDevice>[0] = {}) => fabricatedDevice({ device: POLICY_DEVICE, ...overrides })

const SYSTEM = { kind: "system", reason: "test" } as const
const SECRET = "sk-live-0123456789abcdefghij"

afterEach(() => setRelayServices({}))

function item(overrides: Partial<NewItem> = {}): NewItem {
  return {
    slug: "acme",
    kind: "api-key",
    provider: null,
    account: null,
    accountVerified: false,
    tags: [],
    ceiling: "placeholder",
    binding: { hosts: ["api.acme.test"] },
    policy: { default: "approve", rules: [] },
    injection: { in: "header", name: "Authorization", format: "Bearer {key}" },
    publicFields: {},
    secretFields: { key: SECRET },
    description: null,
    ...overrides,
  }
}

function relay(headers: [string, string][], overrides: Partial<RelayRequestInput> = {}): RelayRequestInput {
  return { item: "acme", method: "POST", url: "https://api.acme.test/v1/action", headers, body: base64UrlEncode(utf8('{"id":1}')), ...overrides }
}

function authorise(ctx: VaultContext, input: RelayRequestInput): Promise<RelayMaterial> {
  return authoriseRelay(ctx, testDevice(), input) as Promise<RelayMaterial>
}

async function refusal(promise: Promise<unknown>): Promise<VaultError> {
  try {
    await promise
  } catch (error) {
    if (error instanceof VaultError) return error
    throw error
  }
  throw new Error("expected a refusal")
}

async function inVault(fn: (ctx: VaultContext) => Promise<void>): Promise<void> {
  await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => { await registerPolicyDevice(instance.context, testDevice()); await fn(instance.context) })
}

type Seen = { subject: ApprovalSubject; presentation: ApprovalPresentation }

function captureApprovals(): Seen[] {
  const seen: Seen[] = []
  setRelayServices({
    reviewRequest: async (_ctx, _principal, subject, presentation) => {
      seen.push({ subject, presentation })
      throw new VaultError("approval_required", "Approve it.", { approval: "apr_1", next: { url: "https://vault.test/a/apr_1", say: "approve" } })
    },
  })
  return seen
}

// The agent's headers: some application-significant, one the injection
// overwrites, some the relay strips, and a repeated one.
const AGENT_HEADERS: [string, string][] = [
  ["X-Api-Action", "archive"],
  ["Prefer", "respond-async"],
  ["Authorization", "Bearer agent-junk"],
  ["Cookie", "session=1"],
  ["Mehen-Session", "s"],
  ["CF-Connecting-IP", "1.2.3.4"],
  ["Content-Type", "application/json"],
  ["X-Dup", "b"],
  ["x-dup", "a"],
]
// The relay always asks for the compressions it can scan, so that header is
// on every approved list too.
const RELAY_ADDED: [string, string] = ["accept-encoding", "gzip, br"]
const FORWARDED: [string, string][] = [
  RELAY_ADDED,
  ["content-type", "application/json"],
  ["prefer", "respond-async"],
  ["x-api-action", "archive"],
  ["x-dup", "b, a"],
]

describe("an approval binds and shows every header the relay forwards", () => {
  it("the subject's headersSha256 and the card cover the forwarded headers as sent, without the ones the injection overwrites", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, item(), SYSTEM)
      expect((await refusal(authorise(ctx, relay(AGENT_HEADERS)))).code).toBe("approval_required")
      expect(seen).toHaveLength(1)
      const { subject, presentation } = seen[0] as Seen
      expect(presentation.headers).toEqual(FORWARDED)
      expect(subject.headersSha256).toBe(digestOf(FORWARDED))

      // Basic credentials overwrite Authorization the same way.
      await items.putItem(ctx, item({ slug: "acme-basic", kind: "basic-auth", injection: { in: "basic", username: "username", password: "password" }, publicFields: { username: "u" }, secretFields: { password: SECRET } }), SYSTEM)
      await refusal(authorise(ctx, relay(AGENT_HEADERS, { item: "acme-basic" })))
      expect(seen[1]?.presentation.headers).toEqual(FORWARDED)

      // An injection into another header leaves the agent's Authorization on the card.
      await items.putItem(ctx, item({ slug: "acme-x", injection: { in: "header", name: "X-Api-Key", format: "{key}" } }), SYSTEM)
      await refusal(authorise(ctx, relay([...AGENT_HEADERS, ["X-API-KEY", "agent-copy"]], { item: "acme-x" })))
      const withAuth: [string, string][] = [RELAY_ADDED, ["authorization", "Bearer agent-junk"], ...FORWARDED.slice(1)]
      expect(seen[2]?.presentation.headers).toEqual(withAuth)
      expect(seen[2]?.subject.headersSha256).toBe(digestOf(withAuth))
    })
  })

  it("refuses to ask for approval of more than 16 KiB of headers, and only for approval", async () => {
    const big: [string, string][] = [
      ["X-Big-One", "a".repeat(9000)],
      ["X-Big-Two", "b".repeat(9000)],
    ]
    await inVault(async (ctx) => {
      await items.putItem(ctx, item(), SYSTEM)
      const error = await refusal(authorise(ctx, relay(big)))
      expect(error.code).toBe("mode_refused")
      expect(error.message).toContain(`${MAX_APPROVAL_HEADER_BYTES} bytes`)
      await items.putItem(ctx, item({ slug: "acme-free", policy: { default: "allow", rules: [] } }), SYSTEM)
      const material = await authorise(ctx, relay(big, { item: "acme-free" }))
      expect(material.headers).toContainEqual(["x-big-one", "a".repeat(9000)])
    })
  })
})

describe("reserved headers and header maps", () => {

  it("the relay refuses a stored header map that names a reserved header before anything is sent, and sends an ordinary one", async () => {
    await inVault(async (ctx) => {
      const headersItem = (slug: string, map: Record<string, string>) =>
        item({ slug, kind: "custom-headers", ceiling: "relay", policy: { default: "allow", rules: [] }, injection: { in: "headers", field: "headers" }, secretFields: { headers: JSON.stringify(map) } })
      for (const name of ["Host", "X-Forwarded-Host", "Cookie", "Proxy-Authorization", "cf-connecting-ip", "Forwarded", "Content-Length", "X-Method-Override"]) {
        const slug = `bad-${name.toLowerCase()}`
        await items.putItem(ctx, headersItem(slug, { "X-Api-Key": SECRET, [name]: "victim.internal" }), SYSTEM)
        const error = await refusal(authorise(ctx, relay([], { item: slug, method: "GET", body: undefined })))
        expect({ name, code: error.code }).toEqual({ name, code: "mode_refused" })
        expect(error.message).not.toContain(SECRET)
      }
      await items.putItem(ctx, headersItem("good", { "X-Api-Key": SECRET, "X-Team": "t1" }), SYSTEM)
      const material = await authorise(ctx, relay([], { item: "good", method: "GET", body: undefined }))
      expect(material.headers).toEqual(expect.arrayContaining([["x-api-key", SECRET], ["x-team", "t1"]]))
    })
  })
})

// ---------------------------------------------------------------- what a card renders

const GMAIL = OAUTH_PROVIDERS["google-gmail"]
if (!GMAIL) throw new Error("google-gmail")

const GMAIL_RECORD = {
  id: "itm_g",
  slug: "gmail-alex",
  kind: "oauth-connection",
  provider: "google-gmail",
  account: "alex@example.com",
  accountVerified: true,
  tags: [],
  ceiling: "placeholder",
  binding: GMAIL.upstream.binding,
  policy: connectionPolicy(GMAIL),
  injection: GMAIL.upstream.injection,
  publicFields: {},
  status: "active",
  version: 1,
  description: null,
  createdAt: 0,
  updatedAt: 0,
} as unknown as ItemRecord

const GENERIC_RECORD = { ...GMAIL_RECORD, slug: "acme", provider: null, account: null, binding: { hosts: ["api.acme.test"] } } as unknown as ItemRecord

function b64(text: string): string {
  let binary = ""
  for (const b of utf8(text)) binary += String.fromCharCode(b)
  return btoa(binary)
}

function gmailCard(message: string): Promise<ApprovalPresentation> {
  const url = new URL("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
  const parsed = parseDestination("POST", url.href)
  if (!parsed.ok) throw new Error("bad destination")
  const body = utf8(JSON.stringify({ raw: base64UrlEncode(utf8(message)) }))
  return presentRequest(GMAIL_RECORD, parsed.destination, url, body, "application/json", [["content-type", "application/json"]])
}

function genericCard(text: string, headers: [string, string][] = [], contentType = "text/plain"): Promise<ApprovalPresentation> {
  const url = new URL("https://api.acme.test/v1/notes")
  const parsed = parseDestination("POST", url.href)
  if (!parsed.ok) throw new Error("bad destination")
  return presentRequest(GENERIC_RECORD, parsed.destination, url, utf8(text), contentType, headers)
}

function mail(...lines: string[]): string {
  return lines.join("\r\n")
}

const MULTIPART_HEAD = ["From: alex@example.com", "To: bob@example.com", "MIME-Version: 1.0", 'Content-Type: multipart/mixed; boundary="b1"', ""]

describe("every string a card renders is checked, control characters are shown and hidden ones marked", () => {
  it("marks and warns on hidden text in a base64 text part, which the whole message only holds encoded", async () => {
    const shown = await gmailCard(mail(...MULTIPART_HEAD, "--b1", "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: base64", "", b64("Pay \u202Eexe.fdp now"), "--b1--", ""))
    expect(shown.email?.sections.map((s) => s.text)).toContain("Pay [RLO U+202E]exe.fdp now")
    expect(JSON.stringify(shown)).not.toContain("\u202E")
    expect(shown.warnings).toEqual([DECEPTIVE_WARNING])
  })

  it("marks and warns on hidden text in an attachment's text", async () => {
    const shown = await gmailCard(
      mail(...MULTIPART_HEAD, "--b1", "Content-Type: text/plain", "", "Hello", "--b1", "Content-Type: text/plain", 'Content-Disposition: attachment; filename="notes.txt"', "Content-Transfer-Encoding: base64", "", b64("zero\u200Bwidth"), "--b1--", ""),
    )
    expect(shown.email?.attachments[0]?.text).toBe("zero[ZWSP U+200B]width")
    expect(shown.warnings).toEqual([DECEPTIVE_WARNING])
  })

  it("marks and warns on hidden text in an encoded email header", async () => {
    const shown = await gmailCard(mail("From: alex@example.com", "To: bob@example.com", `Subject: =?utf-8?B?${b64("Invoice \u2066paid")}?=`, "", "Hello"))
    expect(shown.email?.headers.find((h) => h.name === "Subject")?.value).toBe("Invoice [LRI U+2066]paid")
    expect(shown.warnings).toEqual([DECEPTIVE_WARNING])
  })

  it("warns on hidden text in a forwarded header and keeps the header as sent", async () => {
    const shown = await genericCard("hello", [["x-note", "a\u200Bb"]])
    expect(shown.warnings).toEqual([DECEPTIVE_WARNING])
    expect(shown.headers).toEqual([["x-note", "a\u200Bb"]])
    expect((await genericCard("hello", [["x-note", "ab"]])).warnings ?? []).toEqual([])
  })

  it("spells out control characters in a generic body, keeps tab and CRLF, warns, and the digest still covers the real bytes", async () => {
    const raw = "a\u0000b\u001Bc\u007Fd\re\r\nf\tg\u0008"
    const shown = await genericCard(raw)
    expect(shown.body).toBe("a\\u0000b\\u001Bc\\u007Fd\\u000De\r\nf\tg\\u0008")
    expect(shown.warnings).toContain(CONTROL_WARNING)

    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, item(), SYSTEM)
      await refusal(authorise(ctx, relay([["Content-Type", "text/plain"]], { body: base64UrlEncode(utf8(raw)) })))
      expect(seen[0]?.subject.bodySha256).toBe(await bodyHash(utf8(raw)))
      expect(seen[0]?.presentation.body).toBe("a\\u0000b\\u001Bc\\u007Fd\\u000De\r\nf\tg\\u0008")
    })
  })

  it("warns on a control character in a forwarded header, keeps the header as sent, and spells one out in a decoded email section", async () => {
    const header = await genericCard("hello", [["x-note", "a\u0001b"]])
    expect(header.headers).toEqual([["x-note", "a\u0001b"]])
    expect(header.warnings).toContain(CONTROL_WARNING)

    const section = await gmailCard(mail(...MULTIPART_HEAD, "--b1", "Content-Type: text/plain", "Content-Transfer-Encoding: quoted-printable", "", "bell=07 and escape=1B[2J", "--b1--", ""))
    expect(section.email?.sections[0]?.text).toBe("bell\\u0007 and escape\\u001B[2J")
    expect(section.warnings).toContain(CONTROL_WARNING)
  })

  it("adds nothing for ordinary text with tabs and line breaks", async () => {
    const shown = await genericCard("line one\r\nline two\n\tindented, café", [["x-note", "plain"]])
    expect(shown.warnings ?? []).toEqual([])
    expect(shown.body).toBe("line one\r\nline two\n\tindented, café")
  })
})

describe("forwarded header follow-ups", () => {
  it("the relay's own accept-encoding is on the approved list, replacing whatever the agent sent", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, item(), SYSTEM)
      await refusal(authorise(ctx, relay([["Accept-Encoding", "identity"], ["Content-Type", "application/json"]])))
      expect(seen[0]?.presentation.headers).toEqual([RELAY_ADDED, ["content-type", "application/json"]])
    })
  })

  it("a stored single-header injection into a reserved header is refused at use, before anything is sent", async () => {
    await inVault(async (ctx) => {
      for (const name of ["Cookie", "X-Forwarded-Host", "Host"]) {
        const slug = `legacy-${name.toLowerCase()}`
        await items.putItem(ctx, item({ slug, policy: { default: "allow", rules: [] }, injection: { in: "header", name, format: "session={key}" } }), SYSTEM)
        const refused = await refusal(authorise(ctx, relay([], { item: slug, method: "GET", body: undefined })))
        expect(refused.code).toBe("mode_refused")
        expect(refused.message).toContain(name)
        expect(refused.message).not.toContain(SECRET)
      }
    })
  })
})
