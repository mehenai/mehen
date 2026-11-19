// Template bypasses through the relay,
// approval cards that show the whole request, content headers in the
// approval digest, response codings the redactor cannot read, the upstream
// reason phrase, and echoes flagging the item for review.

import { afterEach, describe, expect, it } from "vitest"
import { runInDurableObject } from "cloudflare:test"
import { env } from "cloudflare:workers"
import type { ApprovalSubject, RelayRequestInput } from "@mehen/protocol/api"
import { OAUTH_PROVIDERS, base64UrlEncode, connectionPolicy, getTemplate, utf8 } from "@mehen/protocol"
import { VaultError } from "../src/http.ts"
import { type RelayMaterial, forwardRelay } from "../src/relay/forward.ts"
import { MAX_APPROVAL_BODY_BYTES, describeEmail, htmlToText } from "../src/relay/presentation.ts"
import { setRelayServices } from "../src/relay/services.ts"
import { setUpstreamFetch } from "../src/relay/upstream.ts"
import { digestOf } from "../src/vault/areas/approvals.ts"
import { items } from "../src/vault/areas/items.ts"
import { authoriseRelay } from "../src/vault/areas/relay.ts"
import type { DevicePrincipal, VaultContext } from "../src/vault/core.ts"
import type { ApprovalPresentation, NewItem } from "../src/vault/services.ts"
import { freshTenant, testDevice as fabricatedDevice } from "./helpers.ts"

import { POLICY_DEVICE, registerPolicyDevice } from "./policy-fixtures.ts"
const testDevice = (overrides: Partial<DevicePrincipal> = {}) => fabricatedDevice({ device: POLICY_DEVICE, ...overrides })

const SYSTEM = { kind: "system", reason: "test" } as const
const TOKEN = "gho_0123456789abcdefghijklmnopqrstuvwxyz"

function provider(id: string) {
  const p = OAUTH_PROVIDERS[id]
  if (!p) throw new Error(id)
  return p
}

function item(overrides: Partial<NewItem>): NewItem {
  return {
    slug: "github-alex",
    kind: "api-key",
    provider: "github-pat",
    account: "alex@example.com",
    accountVerified: false,
    tags: [],
    ceiling: "placeholder",
    binding: { hosts: ["api.github.com"] },
    policy: getTemplate("github-pat")?.policy ?? { default: "deny", rules: [] },
    injection: { in: "header", name: "Authorization", format: "Bearer {key}" },
    publicFields: {},
    secretFields: { key: TOKEN },
    description: null,
    ...overrides,
  }
}

const GRAPH_ITEM = item({ slug: "graph-alex", provider: "microsoft-graph", binding: provider("microsoft-graph").upstream.binding, policy: connectionPolicy(provider("microsoft-graph")) })
const GMAIL_ITEM = item({ slug: "gmail-alex", provider: "google-gmail", binding: provider("google-gmail").upstream.binding, policy: connectionPolicy(provider("google-gmail")) })
const SLACK_ITEM = item({ slug: "slack-bot", provider: "slack-bot", binding: { hosts: ["slack.com"], paths: ["/api/**"] }, policy: getTemplate("slack-bot")?.policy ?? { default: "deny", rules: [] } })

type Seen = { subject: ApprovalSubject; presentation: ApprovalPresentation }

// Records every approval asked for and refuses it, as a pending approval would.
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

function relay(overrides: Partial<RelayRequestInput> & { json?: unknown; text?: string }): RelayRequestInput {
  const { json, text, ...rest } = overrides
  const body = json !== undefined ? JSON.stringify(json) : text
  return {
    item: "github-alex",
    method: "POST",
    url: "https://api.github.com/graphql",
    headers: json !== undefined ? [["Content-Type", "application/json"]] : [],
    ...(body !== undefined ? { body: base64UrlEncode(utf8(body)) } : {}),
    ...rest,
  }
}

function authorise(ctx: VaultContext, input: unknown, principal: DevicePrincipal = testDevice()): Promise<RelayMaterial> {
  return authoriseRelay(ctx, principal, input) as Promise<RelayMaterial>
}

async function inVault(fn: (ctx: VaultContext, sql: SqlStorage) => Promise<void>): Promise<void> {
  const stub = env.TENANT_VAULT.getByName(freshTenant())
  await runInDurableObject(stub, async (instance, state) => { await registerPolicyDevice(instance.context, testDevice()); await fn(instance.context, state.storage.sql) })
}

function detail(p: ApprovalPresentation | undefined, label: string): string[] {
  return (p?.details ?? []).filter((d) => d.label === label).map((d) => d.value)
}

afterEach(() => {
  setUpstreamFetch(null)
  setRelayServices({})
})

describe("template bypasses, through the relay", () => {
  it("a GitHub GraphQL mutation needs an approval, a query goes straight through", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, item({}), SYSTEM)
      const query = await authorise(ctx, relay({ json: { query: "query { viewer { login } }" } }))
      expect(query.url).toBe("https://api.github.com/graphql")
      await expect(authorise(ctx, relay({ json: { query: "mutation { deleteRef(input: {refId: \"r\"}) { clientMutationId } }" } }))).rejects.toMatchObject({ code: "approval_required" })
      await expect(authorise(ctx, relay({ text: "mutation { deleteRef }" }))).rejects.toMatchObject({ code: "approval_required" })
      expect(seen).toHaveLength(2)
    })
  })

  it("adding a collaborator or an org invitation is refused", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, item({}), SYSTEM)
      await expect(authorise(ctx, relay({ method: "PUT", url: "https://api.github.com/repos/a/b/collaborators/mallory", json: { permission: "admin" } }))).rejects.toMatchObject({ code: "policy_denied" })
      await expect(authorise(ctx, relay({ url: "https://api.github.com/orgs/acme/invitations", json: { email: "m@evil.example" } }))).rejects.toMatchObject({ code: "policy_denied" })
    })
  })

  it("a Graph $batch is refused with a message that says to send the requests one by one", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, GRAPH_ITEM, SYSTEM)
      const batch = { requests: [{ id: "1", method: "POST", url: "/me/sendMail", body: {} }, { id: "2", method: "POST", url: "/me/mailFolders/inbox/messageRules", body: {} }] }
      const refused = await authorise(ctx, relay({ item: "graph-alex", url: "https://graph.microsoft.com/v1.0/$batch", json: batch })).catch((e: unknown) => e)
      expect(refused).toMatchObject({ code: "policy_denied" })
      expect((refused as VaultError).message).toContain("one by one")
    })
  })

  // Sending or forwarding a stored message by id is
  // now refused, pointing at sendMail; sendMail under /users still needs an
  // approval.
  it("a Graph send by id under /users or a mail folder is refused, and sendMail under /users needs an approval", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, GRAPH_ITEM, SYSTEM)
      for (const path of ["/users/0f3e/messages/AAMk/send", "/me/mailFolders/inbox/messages/AAMk/forward"]) {
        const refused = await authorise(ctx, relay({ item: "graph-alex", url: `https://graph.microsoft.com/v1.0${path}`, json: {} })).catch((e: unknown) => e)
        expect(refused, path).toMatchObject({ code: "policy_denied" })
        expect((refused as VaultError).message).toContain("sendMail")
      }
      await expect(authorise(ctx, relay({ item: "graph-alex", url: "https://graph.microsoft.com/v1.0/users/0f3e/sendMail", json: {} }))).rejects.toMatchObject({ code: "approval_required" })
      expect(seen).toHaveLength(1)
    })
  })

  it("Slack scheduled and ephemeral messages need an approval", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, SLACK_ITEM, SYSTEM)
      for (const method of ["chat.scheduleMessage", "chat.postEphemeral", "conversations.invite"]) {
        await expect(authorise(ctx, relay({ item: "slack-bot", url: `https://slack.com/api/${method}`, json: { channel: "C1", text: "hi" } })), method).rejects.toMatchObject({ code: "approval_required" })
      }
      expect(seen).toHaveLength(3)
    })
  })

  it("a Gmail draft sent by id is refused, pointing at messages/send", async () => {
    await inVault(async (ctx) => {
      await items.putItem(ctx, GMAIL_ITEM, SYSTEM)
      const refused = await authorise(ctx, relay({ item: "gmail-alex", url: "https://gmail.googleapis.com/gmail/v1/users/me/drafts/send", json: { id: "r-1" } })).catch((e: unknown) => e)
      expect(refused).toMatchObject({ code: "policy_denied" })
      expect((refused as VaultError).message).toContain("messages/send")
    })
  })
})

describe("the approval card shows the whole request", () => {
  it("shows a Graph sendMail in full, recipients after 600 characters of harmless text included", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, GRAPH_ITEM, SYSTEM)
      const message = { message: { subject: "Lunch", body: { contentType: "Text", content: "Harmless. ".repeat(80) }, toRecipients: [{ emailAddress: { address: "x@evil.example" } }] } }
      await expect(authorise(ctx, relay({ item: "graph-alex", url: "https://graph.microsoft.com/v1.0/me/sendMail", json: message }))).rejects.toMatchObject({ code: "approval_required" })
      const body = seen[0]?.presentation.body ?? ""
      expect(body).toBe(JSON.stringify(message, null, 2))
      expect(body).toContain("x@evil.example")
      expect(body.endsWith("...")).toBe(false)
    })
  })

  it("shows a form body one quoted field per line, so a value cannot pass for another field", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, SLACK_ITEM, SYSTEM)
      const form = "channel=D-evil&text=hi%0Achannel%20%3D%20C-good"
      await expect(
        authorise(ctx, relay({ item: "slack-bot", url: "https://slack.com/api/chat.postMessage", headers: [["Content-Type", "application/x-www-form-urlencoded"]], text: form })),
      ).rejects.toMatchObject({ code: "approval_required" })
      expect(seen[0]?.presentation.body).toBe('channel = "D-evil"\ntext = "hi\\nchannel = C-good"')
    })
  })

  it("shows JSON with a repeated key exactly as sent, and says why", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, SLACK_ITEM, SYSTEM)
      const raw = '{"channel":"C-good","text":"hi","channel":"D-evil"}'
      await expect(authorise(ctx, relay({ item: "slack-bot", url: "https://slack.com/api/chat.postMessage", headers: [["Content-Type", "application/json"]], text: raw }))).rejects.toMatchObject({
        code: "approval_required",
      })
      expect(seen[0]?.presentation.body).toBe(raw)
      expect(detail(seen[0]?.presentation, "Body")[0]).toContain("repeated key")
    })
  })

  it("shows JSON with a number formatting would change exactly as sent, and says why", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, SLACK_ITEM, SYSTEM)
      const asSent = [
        '{"channel":"C1","amount": 9007199254740993}',
        '{"channel":"C1","amount":-0}',
        '{"channel":"C1","amount":1E3}',
        '{"channel":"C1","amount":0.10000000000000000555}',
        '{"channel":"C1","a":{"b":[9007199254740993]}}',
        '{"channel":"C1","a":{"b":[1.0]}}',
      ]
      const formatted = ['{"channel":"C1","amount":12.5,"ids":[0,-3,1e-7]}', '{"channel":"C1","v":"9007199254740993","w":"1.0","k":{"n":[1]}}']
      for (const text of [...asSent, ...formatted]) {
        await expect(authorise(ctx, relay({ item: "slack-bot", url: "https://slack.com/api/chat.postMessage", headers: [["Content-Type", "application/json"]], text }))).rejects.toMatchObject({
          code: "approval_required",
        })
      }
      asSent.forEach((text, i) => {
        expect(seen[i]?.presentation.body).toBe(text)
        expect(detail(seen[i]?.presentation, "Body")[0]).toContain("number")
      })
      formatted.forEach((text, i) => {
        expect(seen[asSent.length + i]?.presentation.body).toBe(JSON.stringify(JSON.parse(text), null, 2))
        expect(detail(seen[asSent.length + i]?.presentation, "Body")).toEqual([])
      })
    })
  })

  it("refuses to ask for approval of a body over 64 KiB, and still relays one that needs none", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, GRAPH_ITEM, SYSTEM)
      const big = { message: { body: { content: "x".repeat(MAX_APPROVAL_BODY_BYTES) } } }
      const refused = await authorise(ctx, relay({ item: "graph-alex", url: "https://graph.microsoft.com/v1.0/me/sendMail", json: big })).catch((e: unknown) => e)
      expect(refused).toMatchObject({ code: "mode_refused" })
      expect((refused as VaultError).message).toContain("65536 bytes")
      expect(seen).toHaveLength(0)
      // Every GitHub and Graph write now needs an approval, so the large
      // request that needs none is a read-only GraphQL query.
      await items.putItem(ctx, item({}), SYSTEM)
      const query = { query: "query($x: String!) { viewer { login } }", variables: { x: big.message.body.content } }
      await expect(authorise(ctx, relay({ url: "https://api.github.com/graphql", json: query }))).resolves.toMatchObject({ method: "POST" })
    })
  })

  it("shows an HTML-only email as text, with its links, images and attachments, never as 'No body.'", async () => {
    const message = [
      "To: bob@example.com",
      "Subject: Report",
      'Content-Type: multipart/mixed; boundary="m1"',
      "",
      "--m1",
      "Content-Type: text/html; charset=utf-8",
      "",
      '<html><head><style>p{color:red}</style><script>alert(1)</script></head><body><p>Secret plans &amp; <b>numbers</b></p><a href="https://evil.example/?d=1">click</a><img src="https://evil.example/p.gif?d=2"><!-- hidden --></body></html>',
      "--m1",
      'Content-Type: application/pdf; name="report.pdf"',
      'Content-Disposition: attachment; filename="report.pdf"',
      "Content-Transfer-Encoding: base64",
      "",
      btoa("x".repeat(3000)),
      "--m1",
      "Content-Type: text/plain",
      "Content-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9.txt",
      "",
      "cv",
      "--m1--",
    ].join("\r\n")
    const p = await describeEmail(message, "alex@example.com")
    expect(p.email?.sections.map((s) => s.heading)).toEqual(["HTML, part 1, as text", "HTML, part 1, source"])
    expect(p.email?.sections[0]?.text).toBe("Secret plans & numbers\n[link to https://evil.example/?d=1] click[image https://evil.example/p.gif?d=2]")
    expect(p.body).toBe(message)
    expect(detail(p, "Attachment")).toEqual(["report.pdf (application/pdf, 2.9 KB)", "r\u00e9sum\u00e9.txt (text/plain, 2 bytes)"])
  })

  it("shows attachments without text, and the raw message when it cannot read the structure", async () => {
    const onlyFile = ["To: bob@example.com", 'Content-Type: multipart/mixed; boundary="m1"', "", "--m1", 'Content-Type: image/png; name="a.png"', "", "png", "--m1--"].join("\r\n")
    const files = await describeEmail(onlyFile, null)
    expect(detail(files, "Attachment")).toEqual(["a.png (image/png, 3 bytes)"])
    expect(files.body).toBe(onlyFile)
    const broken = ["To: bob@example.com", "Content-Type: multipart/mixed", "", "secret text the parser cannot place"].join("\r\n")
    expect((await describeEmail(broken, null)).body).toBe(broken)
  })

  it("strips tags from HTML as text and never keeps markup", () => {
    expect(htmlToText("a<br>b<p>c</p>&lt;script&gt;&#x41;&#66;<unclosed")).toBe("a\nb\nc\n<script>AB")
  })

  it("shows a Gmail messages.send by raw as the email, and a draft id is not shown as an email", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, GMAIL_ITEM, SYSTEM)
      const mime = ["To: bob@example.com", "Subject: Hi", "Content-Type: text/html", "", "<p>Hello <i>Bob</i></p>"].join("\r\n")
      await expect(
        authorise(ctx, relay({ item: "gmail-alex", url: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", json: { raw: base64UrlEncode(utf8(mime)) } })),
      ).rejects.toMatchObject({ code: "approval_required" })
      expect(seen[0]?.presentation.title).toBe("Send an email")
      expect(seen[0]?.presentation.body).toBe(mime)
      expect(seen[0]?.presentation.email?.sections[0]?.text).toBe("Hello Bob")
      await expect(
        authorise(ctx, relay({ item: "gmail-alex", method: "PUT", url: "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send?uploadType=resumable&upload_id=u1", text: mime })),
      ).rejects.toMatchObject({ code: "approval_required" })
      expect(seen[1]?.presentation.title).toBe("Send an email")
    })
  })
})

describe("content headers are part of what is approved", () => {
  it("puts content-type and content-encoding into the subject, so a form body cannot reuse a JSON approval", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, SLACK_ITEM, SYSTEM)
      const text = '{"x":"&channel=D-evil&text=hi"}'
      const url = "https://slack.com/api/chat.postMessage"
      await expect(authorise(ctx, relay({ item: "slack-bot", url, headers: [["Content-Type", "application/json"]], text }))).rejects.toMatchObject({ code: "approval_required" })
      await expect(authorise(ctx, relay({ item: "slack-bot", url, headers: [["content-type", "application/x-www-form-urlencoded"]], text }))).rejects.toMatchObject({ code: "approval_required" })
      const [json, form] = seen.map((s) => s.subject)
      expect(json).toMatchObject({ contentType: "application/json", contentEncoding: null })
      expect(form).toMatchObject({ contentType: "application/x-www-form-urlencoded", contentEncoding: null })
      expect(json?.bodySha256).toBe(form?.bodySha256)
      expect(digestOf(json)).not.toBe(digestOf(form))
      expect(seen[0]?.presentation.body).toBe('{\n  "x": "&channel=D-evil&text=hi"\n}')
      expect(seen[1]?.presentation.body?.split("\n").slice(1)).toEqual(['channel = "D-evil"', 'text = "hi\\"}"'])
    })
  })

  it("refuses a compressed body on a request that needs approval, and relays one that does not", async () => {
    const seen = captureApprovals()
    await inVault(async (ctx) => {
      await items.putItem(ctx, SLACK_ITEM, SYSTEM)
      const gzipped = base64UrlEncode(new Uint8Array(await new Response((new Response('{"channel":"C1"}').body as ReadableStream).pipeThrough(new CompressionStream("gzip"))).arrayBuffer()))
      const refused = await authorise(
        ctx,
        relay({ item: "slack-bot", url: "https://slack.com/api/chat.postMessage", headers: [["Content-Type", "application/json"], ["Content-Encoding", "gzip"]], body: gzipped }),
      ).catch((e: unknown) => e)
      expect(refused).toMatchObject({ code: "mode_refused" })
      expect((refused as VaultError).message).toContain("uncompressed")
      expect(seen).toHaveLength(0)
      await expect(
        authorise(ctx, relay({ item: "slack-bot", url: "https://slack.com/api/conversations.history", headers: [["Content-Encoding", "gzip"]], body: gzipped })),
      ).resolves.toMatchObject({ method: "POST" })
    })
  })
})

describe("what comes back from the upstream", () => {
  const SECRET = "sk-live-0123456789abcdef"
  const material: RelayMaterial = {
    method: "GET",
    url: "https://api.example.com/x",
    headers: [["authorization", `Bearer ${SECRET}`], ["Accept-Encoding", "zstd, deflate"]],
    scrub: [{ label: "echo-item", value: SECRET }],
    label: "echo-item",
    items: ["echo-item"],
  }

  it("asks for gzip or br only, whatever the agent asked for", async () => {
    let sent: string | null = null
    setUpstreamFetch(async (req) => {
      sent = req.headers.get("accept-encoding")
      return new Response("ok")
    })
    await (await forwardRelay(material, null)).text()
    expect(sent).toBe("gzip, br")
  })

  it("returns 502 for a response in a coding the Worker does not decode, and passes gzip, br and identity", async () => {
    for (const coding of ["zstd", "deflate", "compress", "gzip, zstd", "x-gzip"]) {
      setUpstreamFetch(async () => new Response(`echo ${SECRET}`, { headers: { "content-encoding": coding } }))
      await expect(forwardRelay(material, null), coding).rejects.toMatchObject({ code: "upstream_failed", status: 502 })
    }
    for (const coding of ["gzip", "br", "identity", "GZIP"]) {
      setUpstreamFetch(async () => new Response(`echo ${SECRET}`, { headers: { "content-encoding": coding } }))
      const res = await forwardRelay(material, null)
      expect(await res.text(), coding).toBe("echo [redacted:echo-item]")
      expect(res.headers.get("content-encoding")).toBeNull()
    }
  })

  it("drops the upstream reason phrase", async () => {
    setUpstreamFetch(async () => new Response("no", { status: 403, statusText: `Forbidden ${SECRET}` }))
    const res = await forwardRelay(material, null)
    expect(res.status).toBe(403)
    expect(res.statusText).not.toContain(SECRET)
    await res.text()
  })
})
