// The human approves exactly
// what is sent. MIME delimiters only at line starts, anything ambiguous is
// unreadable and said in red at the top, the whole decoded message is
// always on the card, every header is listed, HTML is shown as text and
// as escaped source, attachments are shown or hashed, and recipients are
// counted and checked against the account's domain.

import { describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import type { ApprovalSubject, RelayRequestInput } from "@mehen/protocol/api"
import { OAUTH_PROVIDERS, base64UrlEncode, connectionPolicy, utf8 } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { UNREADABLE_WARNING, describeEmail } from "../src/relay/presentation.ts"
import { setRelayServices } from "../src/relay/services.ts"
import { workspaceApprovalPage } from "../src/ui/pages/workspace-asks.ts"
import { galleryEmailApproval } from "../src/ui/workspace-asks-gallery.ts"
import { VIEWERS, galleryShell } from "../src/ui/workspace-projects-gallery.ts"
import { items } from "../src/vault/areas/items.ts"
import { authoriseRelay } from "../src/vault/areas/relay.ts"
import type { VaultContext } from "../src/vault/core.ts"
import type { ApprovalPresentation, NewItem } from "../src/vault/services.ts"
import { freshTenant, testDevice as fabricatedDevice } from "./helpers.ts"

import { POLICY_DEVICE, registerPolicyDevice } from "./policy-fixtures.ts"
const testDevice = (overrides: Parameters<typeof fabricatedDevice>[0] = {}) => fabricatedDevice({ device: POLICY_DEVICE, ...overrides })

const SECRET = "sk-live-0123456789abcdef"
const ACCOUNT = "alex@example.com"
const SYSTEM = { kind: "system", reason: "test" } as const

function mail(...lines: string[]): string {
  return lines.join("\r\n")
}

// Everything the card shows a human, summary and whole body together.
function everything(p: ApprovalPresentation): string {
  const email = p.email
  return [
    ...(p.warnings ?? []),
    ...p.details.map((d) => `${d.label}: ${d.value}`),
    ...(email?.headers.map((h) => `${h.name}: ${h.value}`) ?? []),
    ...(email?.sections.map((s) => s.text) ?? []),
    ...(email?.attachments.map((a) => a.text ?? a.sha256 ?? "") ?? []),
    p.body ?? "",
  ].join("\n")
}

function summary(p: ApprovalPresentation): string {
  return [...(p.email?.headers.map((h) => `${h.name}: ${h.value}`) ?? []), ...(p.email?.sections.map((s) => s.text) ?? []), ...(p.email?.attachments.map((a) => a.text ?? "") ?? [])].join("\n")
}

function expectUnreadable(p: ApprovalPresentation, problem: string): void {
  expect(p.warnings?.[0]).toBe(UNREADABLE_WARNING)
  expect(p.warnings?.slice(1).join("\n")).toContain(problem)
  expect(p.email?.sections).toEqual([])
  expect(p.email?.attachments).toEqual([])
}

function nested(depth: number): string {
  const lines: string[] = ["To: bob@example.com"]
  for (let i = 0; i < depth; i++) lines.push(`Content-Type: multipart/mixed; boundary="b${i}x"`, "", `--b${i}x`)
  lines.push("Content-Type: text/plain", "", SECRET)
  for (let i = depth - 1; i >= 0; i--) lines.push(`--b${i}x--`)
  return mail(...lines)
}

describe("rule 1: MIME is read strictly, and anything unreadable is said in red", () => {
  it("attacker story: a fake end marker in the middle of a line does not hide the next part", async () => {
    const message = mail(
      "To: bob@example.com",
      "Subject: Lunch",
      'Content-Type: multipart/mixed; boundary="B"',
      "",
      "--B",
      "Content-Type: text/plain",
      "",
      "See you tomorrow. x--B--",
      "--B",
      "Content-Type: text/plain",
      "",
      SECRET,
      "--B--",
    )
    const p = await describeEmail(message, ACCOUNT)
    expect(p.warnings).toEqual([])
    expect(p.email?.sections.map((s) => s.text)).toEqual(["See you tomorrow. x--B--", SECRET])
    expect(p.body).toBe(message)
  })

  it("accepts delimiters with trailing spaces and bare LF line ends", async () => {
    const message = ["To: bob@example.com", 'Content-Type: multipart/alternative; boundary="B"', "", "--B \t", "", "one", "--B--  ", ""].join("\n")
    const p = await describeEmail(message, ACCOUNT)
    expect(p.warnings).toEqual([])
    expect(p.email?.sections.map((s) => s.text)).toEqual(["one"])
  })

  it("attacker story: two boundary parameters make the message unreadable, and the hidden part is still on the card", async () => {
    const message = mail(
      "To: bob@example.com",
      'Content-Type: multipart/mixed; boundary="A"; boundary="B"',
      "",
      "--A",
      "Content-Type: text/plain",
      "",
      "harmless",
      "--B",
      "Content-Type: text/plain",
      "",
      SECRET,
      "--B--",
      "--A--",
    )
    const p = await describeEmail(message, ACCOUNT)
    expectUnreadable(p, 'has the "boundary" parameter twice')
    expect(p.body).toContain(SECRET)
  })

  it("two Content-Type headers make the message unreadable", async () => {
    const message = mail("To: bob@example.com", 'Content-Type: multipart/mixed; boundary="A"', 'Content-Type: multipart/mixed; boundary="B"', "", "--A", "", "x", "--A--")
    expectUnreadable(await describeEmail(message, ACCOUNT), "has 2 content-type headers")
  })

  it("two Content-Type headers inside a part make the message unreadable", async () => {
    const message = mail("To: bob@example.com", 'Content-Type: multipart/mixed; boundary="A"', "", "--A", "Content-Type: text/plain", "Content-Type: text/html", "", "x", "--A--")
    expectUnreadable(await describeEmail(message, ACCOUNT), "Part 1 has 2 content-type headers")
  })

  it("multiparts nested more than 5 deep are unreadable; 5 deep is read", async () => {
    const five = await describeEmail(nested(5), ACCOUNT)
    expect(five.warnings).toEqual([])
    expect(five.email?.sections.map((s) => s.text)).toEqual([SECRET])
    const six = await describeEmail(nested(6), ACCOUNT)
    expectUnreadable(six, "nests multiparts more than 5 deep")
    expect(six.body).toContain(SECRET)
  })

  it("a missing end marker is unreadable", async () => {
    const message = mail("To: bob@example.com", 'Content-Type: multipart/mixed; boundary="B"', "", "--B", "", "visible", "--B", "", SECRET)
    const p = await describeEmail(message, ACCOUNT)
    expectUnreadable(p, 'has no end marker (a line "--B--")')
    expect(p.body).toContain(SECRET)
  })

  it("a line that starts like the boundary but is not one is unreadable", async () => {
    const message = mail("To: bob@example.com", 'Content-Type: multipart/mixed; boundary="B"', "", "--B", "", "one", "--Bx", "", SECRET, "--B--")
    expectUnreadable(await describeEmail(message, ACCOUNT), "starts like its boundary")
  })

  it("a part the parser cannot classify is unreadable", async () => {
    const cases: [string, string][] = [
      [mail("To: bob@example.com", 'Content-Type: multipart/mixed; boundary="B"', "", "--B", "not a header line", "", SECRET, "--B--"), "Part 1 has a line that is not a header"],
      [mail("To: bob@example.com", "Content-Type: multipart/mixed", "", SECRET), "multipart without a boundary"],
      [mail("To: bob@example.com", "Content-Type: text/plain", "Content-Transfer-Encoding: base64", "", "!!not base64!!"), "is not valid base64"],
      [mail("To: bob@example.com", "Content-Type: text/plain", "Content-Transfer-Encoding: x-uuencode", "", SECRET), "transfer encoding the vault does not read"],
      [mail("To: bob@example.com", "Content-Type: text/plain (comment); charset=utf-8", "", SECRET), "Content-Type has text the vault cannot read"],
      [mail("To: bob@example.com", "Content-Type: text/plain; charset*0=utf; charset*1=-8", "", SECRET), "split or encoded"],
      [mail("To: bob@example.com", "To: eve@evil.example", "", SECRET), "has 2 to headers"],
      [mail("To: bob@example.com", "From x@y Sat Jan 1", "", SECRET), "line that is not a header"],
      [mail("To: bob@example.com", "   ", "X-Hidden: data", "", SECRET), "header line of only spaces"],
    ]
    for (const [message, problem] of cases) {
      const p = await describeEmail(message, ACCOUNT)
      expectUnreadable(p, problem)
      expect(p.body).toBe(message)
    }
  })

  it("shows text before the first part and after the last, which mail apps hide", async () => {
    const message = mail("To: bob@example.com", 'Content-Type: multipart/mixed; boundary="B"', "", `preamble ${SECRET}`, "--B", "", "body", "--B--", "epilogue data")
    const p = await describeEmail(message, ACCOUNT)
    expect(p.warnings).toEqual([])
    expect(p.email?.sections.map((s) => [s.heading, s.text])).toEqual([
      ["Text before the first part", `preamble ${SECRET}`],
      ["Text, part 1", "body"],
      ["Text after the last part", "epilogue data"],
    ])
  })
})

describe("rule 2: the whole decoded message is always on the card", () => {
  it("is the decoded raw of a Gmail messages.send, with the request's other fields shown too", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, GMAIL_ITEM, SYSTEM)
      const mime = mail("To: bob@example.com", "Subject: Hi", "", "Hello")
      const json = { raw: base64UrlEncode(utf8(mime)), threadId: SECRET }
      await expect(authorise(ctx, gmailSend(JSON.stringify(json)))).rejects.toMatchObject({ code: "approval_required" })
      const p = seen[0]?.presentation
      expect(p?.body).toBe(mime)
      expect(p?.email?.sections.at(-1)).toEqual({ heading: "Other fields in the request", note: "Sent to Gmail with the message.", text: JSON.stringify({ threadId: SECRET }, null, 2) })
    })
    setRelayServices({})
  })

  it("shows a Gmail messages.send request exactly as sent when formatting would change a number in its other fields", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, GMAIL_ITEM, SYSTEM)
      const mime = mail("To: bob@example.com", "Subject: Hi", "", "Hello")
      const json = `{"raw":"${base64UrlEncode(utf8(mime))}","labelCount":9007199254740993}`
      await expect(authorise(ctx, gmailSend(json))).rejects.toMatchObject({ code: "approval_required" })
      const p = seen[0]?.presentation
      expect(p?.body).toBe(mime)
      expect(p?.email?.sections.at(-1)).toEqual({
        heading: "Other fields in the request",
        note: "Sent to Gmail with the message. One has a number that formatting would change, so the whole request is shown exactly as sent.",
        text: json,
      })
    })
    setRelayServices({})
  })

  it("warns, and shows the request as sent, when raw is not clean base64url", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, GMAIL_ITEM, SYSTEM)
      const json = JSON.stringify({ raw: `${base64UrlEncode(utf8("To: bob@example.com\r\n\r\nhi"))}!${SECRET}` })
      await expect(authorise(ctx, gmailSend(json))).rejects.toMatchObject({ code: "approval_required" })
      const p = seen[0]?.presentation
      expect(p?.warnings?.[0]).toContain("not clean base64url")
      expect(p?.body).toContain(SECRET)
    })
    setRelayServices({})
  })

  it("puts the whole message on the page as the exact request, escaped, before who asked", async () => {
    const message = mail("To: bob@example.com", "Content-Type: text/html", "", `<p>Hi</p><!-- ${SECRET} -->`)
    const page = pageOf(await describeEmail(message, ACCOUNT))
    const exact = page.indexOf('data-region="exact-request"')
    expect(exact).toBeGreaterThan(-1)
    expect(page.indexOf(SECRET, exact)).toBeGreaterThan(exact)
    expect(page.indexOf(SECRET, exact)).toBeLessThan(page.indexOf("<h2>Who asked</h2>"))
    expect(page).not.toContain("<!--")
    expect(page).not.toContain("<p>Hi")
  })

  it("keeps the whole body for a request that is not an email", async () => {
    const page = pageOf({ title: "POST api.example.com/x", details: [], body: `{"a":"${SECRET}"}` })
    expect(page).toContain(`<pre class="request-body" tabindex="0">{&quot;a&quot;:&quot;${SECRET}&quot;}</pre>`)
    expect(page).not.toContain("<h2>Recipients</h2>")
  })
})

describe("rule 3: every header is listed, the address headers highlighted", () => {
  it("attacker story: a hidden X- header carrying data is on the card", async () => {
    const message = mail(
      "From: Alex <alex@example.com>",
      "Sender: alex@example.com",
      "To: bob@example.com",
      "Reply-To: eve@evil.example",
      "Subject: =?utf-8?B?SGVsbG8=?=",
      `X-Exfil: ${SECRET}`,
      " continued",
      "",
      "Hi",
    )
    const p = await describeEmail(message, ACCOUNT)
    expect(p.warnings).toEqual([])
    expect(p.email?.headers).toEqual([
      { name: "From", value: "Alex <alex@example.com>", highlight: true },
      { name: "Sender", value: "alex@example.com", highlight: false },
      { name: "To", value: "bob@example.com", highlight: true },
      { name: "Reply-To", value: "eve@evil.example", highlight: true },
      { name: "Subject", value: "Hello", highlight: false },
      { name: "X-Exfil", value: `${SECRET} continued`, highlight: false },
    ])
    const page = pageOf(p)
    expect(page).toContain(`<dt>X-Exfil</dt><dd>${SECRET} continued</dd>`)
    expect(page).toContain('<dt class="hl">Reply-To</dt><dd class="hl">eve@evil.example</dd>')
  })
})

describe("rule 4: HTML is shown as text and as escaped source", () => {
  it("attacker story: an HTML comment, script, style or attribute carrying data is on the card", async () => {
    const html = `<p title="${SECRET}-attr">Hello</p><!-- ${SECRET}-comment --><script>var x="${SECRET}-script"</script><style>p{background:url(${SECRET}-style)}</style>`
    const message = mail("To: bob@example.com", "Content-Type: text/html; charset=utf-8", "", html)
    const p = await describeEmail(message, ACCOUNT)
    const [text, source] = p.email?.sections ?? []
    expect(text?.heading).toBe("HTML, as text")
    expect(text?.text).toBe("Hello")
    expect(source?.heading).toBe("HTML, source")
    expect(source?.text).toBe(html)
    for (const where of ["attr", "comment", "script", "style"]) expect(summary(p)).toContain(`${SECRET}-${where}`)
    const page = pageOf(p)
    expect(page).toContain(`&lt;!-- ${SECRET}-comment --&gt;`)
    expect(page).not.toContain("<script>")
    expect(page).not.toContain("<style>")
  })

  it("shows an HTML part as text and source alongside the text part", async () => {
    const message = mail(
      "To: bob@example.com",
      'Content-Type: multipart/alternative; boundary="B"',
      "",
      "--B",
      "Content-Type: text/plain",
      "",
      "plain",
      "--B",
      "Content-Type: text/html",
      "Content-Transfer-Encoding: quoted-printable",
      "",
      "<b>bo=",
      "ld</b>",
      "--B--",
    )
    const p = await describeEmail(message, ACCOUNT)
    expect(p.email?.sections.map((s) => [s.heading, s.text])).toEqual([
      ["Text, part 1", "plain"],
      ["HTML, part 2, as text", "bold"],
      ["HTML, part 2, source", "<b>bold</b>"],
    ])
  })
})

describe("rule 5: attachments are named, typed, sized, and shown or hashed", () => {
  it("attacker story: a text attachment carrying data is shown inline", async () => {
    const message = mail(
      "To: bob@example.com",
      'Content-Type: multipart/mixed; boundary="B"',
      "",
      "--B",
      "",
      "See attached.",
      "--B",
      'Content-Type: text/csv; name="notes.csv"',
      'Content-Disposition: attachment; filename="notes.csv"',
      "Content-Transfer-Encoding: base64",
      "",
      btoa(`key,${SECRET}`),
      "--B--",
    )
    const p = await describeEmail(message, ACCOUNT)
    expect(p.email?.attachments).toEqual([{ name: "notes.csv", type: "text/csv", bytes: SECRET.length + 4, text: `key,${SECRET}`, sha256: null }])
    expect(detail(p, "Attachment")).toEqual([`notes.csv (text/csv, ${SECRET.length + 4} bytes)`])
    const page = pageOf(p)
    expect(page).toContain(`<pre class="request-body" tabindex="0">key,${SECRET}</pre>`)
  })

  it("shows JSON, XML and small UTF-8 attachments inline, and hashes the rest", async () => {
    const bigText = "a".repeat(64 * 1024)
    const parts: [string, string, string][] = [
      ["a.json", "application/json", '{"k":1}'],
      ["a.xml", "application/xml", "<k/>"],
      ["a.bin", "application/octet-stream", `utf-8 ${SECRET}`],
      ["big.bin", "application/octet-stream", bigText],
      ["a.png", "image/png", "\u0089PNG\u0000\u00ff"],
    ]
    const lines = ["To: bob@example.com", 'Content-Type: multipart/mixed; boundary="B"', ""]
    for (const [name, type, content] of parts) {
      const bytes = Uint8Array.from(content, (c) => c.charCodeAt(0))
      lines.push("--B", `Content-Type: ${type}`, `Content-Disposition: attachment; filename="${name}"`, "Content-Transfer-Encoding: base64", "", base64(bytes))
    }
    lines.push("--B--")
    const p = await describeEmail(mail(...lines), ACCOUNT)
    expect(p.warnings).toEqual([])
    const shown = Object.fromEntries((p.email?.attachments ?? []).map((a) => [a.name, a]))
    expect(shown["a.json"]?.text).toBe('{"k":1}')
    expect(shown["a.xml"]?.text).toBe("<k/>")
    expect(shown["a.bin"]?.text).toBe(`utf-8 ${SECRET}`)
    expect(shown["big.bin"]).toMatchObject({ text: null, bytes: 64 * 1024, sha256: await hexSha256(utf8(bigText)) })
    expect(shown["a.png"]).toMatchObject({ text: null, bytes: 6, sha256: await hexSha256(Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0, 0xff])) })
    const page = pageOf(p)
    expect(page).toContain(`<dt>SHA-256</dt><dd><code>${shown["a.png"]?.sha256}</code></dd>`)
  })
})

describe("rule 6: recipients are counted and checked against the account's domain", () => {
  it("counts every address across To, Cc and Bcc and flags other domains as external", async () => {
    const message = mail(
      'To: "Bob, the builder" <bob@example.com>, eve@evil.example',
      "Cc: team: carol@Example.com, dan@sub.example.com;",
      "Bcc: =?utf-8?Q?Mallory?= <m@evil.example> (hidden)",
      "Reply-To: x@evil.example",
      "",
      "Hi",
    )
    const p = await describeEmail(message, ACCOUNT)
    expect(p.warnings).toEqual([])
    expect(p.email?.accountDomain).toBe("example.com")
    expect(p.email?.recipients).toEqual([
      { header: "To", address: "bob@example.com", external: false },
      { header: "To", address: "eve@evil.example", external: true },
      { header: "Cc", address: "carol@Example.com", external: false },
      { header: "Cc", address: "dan@sub.example.com", external: true },
      { header: "Bcc", address: "m@evil.example", external: true },
    ])
    const page = pageOf(p)
    expect(page).toContain('<b class="count-big">5</b> <span class="muted">recipients across To, Cc and Bcc,</span> <span class="refused">3 outside example.com</span>')
    expect(page).toContain('<span class="hdr">Bcc</span><code>m@evil.example</code><span class="pill danger">external</span>')
    // The decision card flags the same recipients, with the domain they are outside of.
    expect(page).toContain('<span class="addr">eve@evil.example</span> <span class="pill danger">outside example.com</span>')
  })

  it("counts everyone as external when the account's domain is unknown, and an unreadable address is unreadable", async () => {
    const unknown = await describeEmail(mail("To: bob@example.com", "", "Hi"), null)
    expect(unknown.email?.recipients).toEqual([{ header: "To", address: "bob@example.com", external: true }])
    const broken = await describeEmail(mail('To: "unclosed <bob@example.com>', "", "Hi"), ACCOUNT)
    expectUnreadable(broken, "cannot be read as a list of addresses")
    expect(broken.email?.recipients[0]?.external).toBe(true)
    const two = await describeEmail(mail("To: <bob@example.com> <eve@evil.example>", "", "Hi"), ACCOUNT)
    expectUnreadable(two, "has a recipient the vault cannot read")
    expect(two.email?.recipients).toEqual([{ header: "To", address: "<bob@example.com> <eve@evil.example>", external: true }])
  })
})

describe("the card as stored and served", () => {

  it("never lets the summary drop what the whole message holds", async () => {
    const message = mail("To: bob@example.com", `X-A: ${SECRET}`, "", "x")
    const p = await describeEmail(message, ACCOUNT)
    expect(everything(p).split(SECRET).length).toBeGreaterThan(2)
  })
})

const GMAIL_PROVIDER = OAUTH_PROVIDERS["google-gmail"]
if (!GMAIL_PROVIDER) throw new Error("google-gmail provider missing")

const GMAIL_ITEM: NewItem = {
  slug: "gmail-alex",
  kind: "api-key",
  provider: "google-gmail",
  account: ACCOUNT,
  accountVerified: false,
  tags: [],
  ceiling: "placeholder",
  binding: GMAIL_PROVIDER.upstream.binding,
  policy: connectionPolicy(GMAIL_PROVIDER),
  injection: { in: "header", name: "Authorization", format: "Bearer {key}" },
  publicFields: {},
  secretFields: { key: "ya29.token" },
  description: null,
}

const SUBJECT: ApprovalSubject = {
  item: "gmail-alex",
  method: "POST",
  url: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
  contentType: "application/json",
  contentEncoding: null,
  headersSha256: "headers",
  bodySha256: "body",
  constraints: { uses: 1, ttlSeconds: 600 },
}

function gmailSend(json: string): RelayRequestInput {
  return { item: "gmail-alex", method: "POST", url: SUBJECT.url, headers: [["Content-Type", "application/json"]], body: base64UrlEncode(utf8(json)) }
}

function captureApprovals(): { presentation: ApprovalPresentation }[] {
  const seen: { presentation: ApprovalPresentation }[] = []
  setRelayServices({
    reviewRequest: async (_ctx, _principal, _subject, presentation) => {
      seen.push({ presentation })
      throw new VaultError("approval_required", "Approve it.", { approval: "apr_1", next: { url: "https://vault.test/a/apr_1", say: "approve" } })
    },
  })
  return seen
}

function authorise(ctx: VaultContext, input: RelayRequestInput): Promise<unknown> {
  return authoriseRelay(ctx, testDevice(), input) as Promise<unknown>
}

async function inVault(fn: (ctx: VaultContext) => Promise<void>): Promise<void> {
  await runInDurableObject(env.TENANT_VAULT.getByName(freshTenant()), async (instance) => { await registerPolicyDevice(instance.context, testDevice()); await fn(instance.context) })
}

function detail(p: ApprovalPresentation, label: string): string[] {
  return p.details.filter((d) => d.label === label).map((d) => d.value)
}

// The workspace approval page's body for an approval the vault stored
// with this presentation.
function pageOf(p: ApprovalPresentation): string {
  const view = galleryEmailApproval()
  if (view.view !== "detail") throw new Error("Expected a detail fixture")
  const approval = { ...view.approval, title: p.title, details: p.details, warnings: p.warnings ?? [], email: p.email ?? null, request: { ...view.approval.request, headers: p.headers ?? null, body: p.body } }
  return workspaceApprovalPage(galleryShell(VIEWERS.owner), { viewer: VIEWERS.owner, view: { ...view, approval }, project: null, items: [] }).body.value
}

function base64(bytes: Uint8Array): string {
  let binary = ""
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}

async function hexSha256(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)))
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("")
}
