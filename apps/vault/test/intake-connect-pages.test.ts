// The intake and connect pages as a person reads them: who may use what is
// stored, what a closed link was for, which way to ask again actually
// works, the warning for a value without the expected start, and what the
// connect page says after an interrupted store or once its link runs out.
// The adoption page: custom hosts in the danger style, stale and refused
// rows unticked, each compare row's holder, result and affected list by name
// only, and nothing in the page or its boot but the view. The inventory of
// every name a person's adoptions touch.

import { describe, expect, it } from "vitest"
import type { ConnectView, IntakeView } from "@mehen/protocol/api"
import type { WorkspaceConnectView, WorkspaceIntakeView } from "@mehen/protocol/workspace"
import { getTemplate } from "@mehen/protocol/templates"
import { connectPage } from "../src/ui/pages/connect.ts"
import { intakePage } from "../src/ui/pages/intake.ts"
import { renderDocument } from "../src/ui/layout.ts"
import { ADOPTION_CLOSED_WORDS, ADOPTION_RENAME_WORDS, adoptionTexts, workspaceAdoptionPage } from "../src/ui/pages/workspace-adopt.ts"
import { workspaceAdoptInventoryPage } from "../src/ui/pages/workspace-adopt-inventory.ts"
import { workspaceConnectPage, workspaceIntakePage } from "../src/ui/pages/workspace-asks.ts"
import { GALLERY_ADOPT_INVENTORY, GALLERY_ADOPTION, GALLERY_COMPARE_FINGERPRINTS, GALLERY_CONFLICT_ADOPTION, GALLERY_FILL_INTAKE } from "../src/ui/workspace-asks-gallery.ts"
import { galleryProject, galleryShell, GALLERY_FIXTURES, VIEWERS } from "../src/ui/workspace-projects-gallery.ts"

const VIEWER = { name: "Alex", tenantName: "Home", role: "owner" } as const
const ORIGIN = "https://vault.example"
const NOW = Date.parse("2026-10-25T10:00:00Z")
const LATER = new Date(NOW + 20 * 60_000).toISOString()
const EARLIER = new Date(NOW - 20 * 60_000).toISOString()
const MAC = { device: "dev_mac", deviceName: "Mac mini", session: null }
const ME = { member: "mem_alex", self: true }
const SEAL_KEY = { jwk: { kty: "EC" as const, crv: "P-256" as const, x: "x", y: "y" }, kid: "seal_1" }

function intake(overrides: Partial<IntakeView> = {}): IntakeView {
  return {
    intake: "int_1",
    status: "open",
    kind: "api-key",
    slug: "openai-personal",
    provider: "openai",
    providerName: "OpenAI API key",
    reason: "Summaries",
    requestedBy: MAC,
    rotates: false,
    fields: [{ name: "key", label: "API key", secret: true, required: true, multiline: false, hint: null }],
    binding: { value: { hosts: ["api.openai.com"] }, verified: true },
    injection: { value: null, verified: true },
    tags: ["ai"],
    customPolicy: false,
    sealKey: SEAL_KEY,
    expiresAt: LATER,
    ...overrides,
  }
}

const PROPOSED: Partial<IntakeView> = {
  slug: "weather-api",
  provider: null,
  providerName: null,
  binding: { value: { hosts: ["api.weatherapi.com"], paths: ["/v1/**"] }, verified: false },
  injection: { value: { in: "query", name: "key", field: "key" }, verified: false },
  tags: ["home"],
  customPolicy: true,
}

const GOOGLE_CLIENT: Partial<IntakeView> = {
  kind: "oauth-client",
  slug: "google-client",
  provider: "google-oauth-client",
  providerName: "Google OAuth client",
  fields: [
    { name: "client_id", label: "Client ID", secret: false, required: true, multiline: false, hint: null },
    { name: "client_secret", label: "Client secret", secret: true, required: true, multiline: false, hint: null },
  ],
  binding: { value: { hosts: ["oauth2.googleapis.com"] }, verified: true },
  tags: ["google"],
}

function connect(overrides: Partial<ConnectView> = {}): ConnectView {
  return {
    connect: "con_1",
    status: "open",
    provider: "google-gmail",
    providerName: "Gmail",
    slug: "gmail-alex",
    scopes: ["https://www.googleapis.com/auth/gmail.modify"],
    expect: "alex@example.com",
    reason: "Triage",
    requestedBy: MAC,
    reconnect: false,
    currentScopes: null,
    account: null,
    message: null,
    expiresAt: LATER,
    ...overrides,
  }
}

const intakeBody = (view: IntakeView): string => intakePage(VIEWER, view, ORIGIN, NOW).body.value
const connectBody = (view: Parameters<typeof connectPage>[1]): string => connectPage(VIEWER, view, NOW).body.value
const h1s = (body: string): number => (body.match(/<h1>/g) ?? []).length

describe("the intake page says who may use the credential in one wording, and never claims the asker can", () => {
  it("in the head, the side card, the saved card and the completed card", () => {
    const open = intakeBody(intake())
    expect(open).toContain('Will be saved as <code class="slug-inline">openai-personal</code>. Only machines allowed the tag <code>ai</code>, or every credential, can use it.')
    expect(open).toContain('<p class="lead">Only machines allowed the tag <code>ai</code>, or every credential, can use it.</p>')
    expect(open).toContain("Tags are one limit on access. A machine must also reach it through the credential&#39;s home, its owner&#39;s current rights, its scope and the environment&#39;s protection; a matching tag alone grants nothing. The agent chose these tags.")
    expect(open).toContain("Only machines allowed the tag <code>ai</code>, or every credential, can use it now, and only at the destination shown. You can close this page.")
    expect(open).not.toContain("Saved as")
    const completed = intakeBody(intake({ status: "completed" }))
    expect(completed).toContain("This request has been completed. <code>openai-personal</code> is stored. Only machines allowed the tag <code>ai</code>, or every credential, can use it now.")
    for (const body of [open, completed]) {
      expect(body).not.toContain("An agent on Mac mini can use it")
      expect(body).not.toContain("and An agent")
    }
    expect(intakeBody(intake({ requestedBy: ME }))).toContain("a matching tag alone grants nothing. You chose these tags. If they look wrong, do not save; start again from Connect a service.")
  })

  it("with no tags", () => {
    expect(intakeBody(intake({ tags: [] }))).toContain("Will be saved as <code class=\"slug-inline\">openai-personal</code>. Only machines allowed every credential can use it.")
  })
})

describe("the connect page says who may use the connection in the intake page's one wording", () => {
  const lead = '<p class="lead">Only machines allowed the tag <code>ci</code>, or every credential, can use it.</p>'
  const limit = "Tags are one limit on access. A machine must also reach it through the credential&#39;s home, its owner&#39;s current rights, its scope and the environment&#39;s protection; a matching tag alone grants nothing."

  it("in the same sentences as the intake page", () => {
    for (const body of [intakeBody(intake({ tags: ["ci"] })), connectBody({ ...connect(), tags: ["ci"] })]) {
      expect(body).toContain(lead)
      expect(body).toContain(`${limit} The agent chose these tags. If they look wrong, do not `)
    }
  })

  it("says who chose the tags and what to do if they look wrong, and never that tags decide", () => {
    const agent = connectBody({ ...connect(), tags: ["ci"] })
    expect(agent).toContain(`${limit} The agent chose these tags. If they look wrong, do not sign in; ask for a new link instead.`)
    expect(agent).not.toContain("Tags decide")
    expect(connectBody({ ...connect(), tags: ["ci", "deploy"] })).toContain('<p class="lead">Only machines allowed the tags <code>ci</code> or <code>deploy</code>, or every credential, can use it.</p>')
    expect(connectBody({ ...connect({ requestedBy: ME }), tags: ["ci"] })).toContain(`${limit} You chose these tags. If they look wrong, do not sign in; start again from Connect a service.`)
  })
})

describe("the intake page after a save", () => {
  it("offers the credential when nothing follows, and goes on to step 2 when a connect does", () => {
    const done = /<div data-region="intake-done" hidden>([\s\S]*?)<\/div>\s*<\/div>/.exec(intakeBody(intake()))?.[1] ?? ""
    expect(done).toContain('<a class="btn secondary" href="/items/openai-personal">Open the credential</a>')
    expect(done).toContain("<h2>Saved</h2>")
    const chained = intakeBody(intake({ ...GOOGLE_CLIENT, then: { connect: "con_1", url: `${ORIGIN}/c/con_1` } }))
    expect(chained).toContain('href="/c/con_1"')
    expect(chained).not.toContain('data-region="intake-then"')
    expect(chained).not.toContain("the provider asks you to sign in")
  })

  it("has one h1 with its hidden saved and expired cards, and marks the advice the client drops once saved", () => {
    const body = intakeBody(intake())
    expect(h1s(body)).toBe(1)
    expect(body).toContain('data-region="intake-tags-advice"')
    expect(body).toContain('<span class="when">')
  })
})

describe("replacing a secret says the old value still works at the service", () => {
  it("in the head and in the saved card, with a link to the credential's page", () => {
    const body = intakeBody(intake({ slug: "github-pat", provider: "github-pat", providerName: "GitHub token", rotates: true }))
    expect(body).toContain("The vault stops using the old value as soon as you save. It still works at the service until you revoke it there.")
    expect(body).toContain("the vault no longer uses the old value. It still works at the service until you revoke it there.")
    expect(body).not.toContain("stops working for it")
    expect(body).toContain('do that from <a href="/items/github-pat">the credential\'s own page</a>.')
  })
})

describe("asking again from a closed intake offers only a command that works", () => {
  it("offers the mehen command for a template intake", () => {
    const body = intakeBody(intake({ status: "expired", expiresAt: EARLIER }))
    expect(body).toContain("Ask the agent on Mac mini for a new link, or run this on the machine that asked:")
    expect(body).toContain("mehen request api-key --name openai-personal --provider openai --tag ai --reason Summaries")
  })

  it("offers no command for a proposed destination, which mehen request cannot repeat", () => {
    for (const status of ["expired", "cancelled"] as const) {
      const body = intakeBody(intake({ ...PROPOSED, status, expiresAt: EARLIER }))
      expect(body).not.toContain("mehen request")
      expect(body).toContain("Ask the agent on Mac mini to request <code>weather-api</code> again; its proposed destination cannot be repeated from a command here.")
    }
    const ranOut = intakeBody(intake(PROPOSED))
    expect(ranOut).toContain('data-region="intake-expired"')
    expect(ranOut).not.toContain("mehen request")
  })

  it("offers no command for a client a connect was waiting on, which it would ask for alone", () => {
    const body = intakeBody(intake({ ...GOOGLE_CLIENT, status: "expired", expiresAt: EARLIER, then: { connect: "con_1", url: `${ORIGIN}/c/con_1` } }))
    expect(body).not.toContain("mehen request")
    expect(body).toContain("Ask the agent on Mac mini to start connecting the account again.")
  })

  it("points a superseded link at what needs you, not at asking again", () => {
    const body = intakeBody(intake({ status: "cancelled", superseded: true }))
    expect(body).toContain('<a class="btn primary" href="/#needs-you">')
    expect(body).toContain("Open what needs you")
    expect(body).not.toContain("for a new link")
    expect(body).not.toContain("mehen request")
  })
})

describe("a closed intake or connect says what it was for", () => {
  it("with the service's name as the one h1 above the state card", () => {
    const expired = intakeBody(intake({ ...GOOGLE_CLIENT, status: "expired", expiresAt: EARLIER }))
    expect(expired).toContain("<h1>Google OAuth client</h1>")
    expect(expired).toContain('<code class="slug-inline">google-client</code>')
    expect(h1s(expired)).toBe(1)
    expect(expired).toContain("<h2>This link ran out at")
    const failed = connectBody(connect({ status: "failed", message: null }))
    expect(failed).toContain("<h1>Connect Gmail</h1>")
    expect(h1s(failed)).toBe(1)
  })
})

describe("the intake form's hints", () => {
  it("drop the verified pill on a field that is not secret", () => {
    const body = intakeBody(intake(GOOGLE_CLIENT))
    expect(body).not.toContain('<span class="pill ok">verified</span>')
    expect(body).toContain('<span class="pill accent">sealed</span>')
  })

  it("say what turns the button on, the tick box included", () => {
    expect(intakeBody(intake())).toContain("Turns on when the field is filled in. Saving asks for your passkey.")
    expect(intakeBody(intake(GOOGLE_CLIENT))).toContain("Turns on when the fields are filled in. Saving asks for your passkey.")
    expect(intakeBody(intake(PROPOSED))).toContain("Turns on when the field is filled in and the box is ticked. Saving asks for your passkey.")
    const optional = intake({
      ...PROPOSED,
      kind: "ssh-key",
      fields: [
        { name: "private_key", label: "Private key", secret: true, required: true, multiline: true, hint: null },
        { name: "public_key", label: "Public key", secret: false, required: false, multiline: false, hint: null },
      ],
    })
    expect(intakeBody(optional)).toContain("Turns on when the required field is filled in and the box is ticked.")
  })

  it("carry a hidden warning for a value without the expected start, and never the value or a gate", () => {
    const body = intakeBody(intake())
    expect(body).toContain('data-field="key" data-expect-start="sk-"')
    expect(body).toContain('<span class="callout field-warn" data-region="field-warn" hidden role="status">')
    expect(body).toContain("This does not start with <code>sk-</code>. Check you copied the right value, and all of it; you can still save it.")
    const google = intakeBody(intake(GOOGLE_CLIENT))
    expect(google).toContain('data-field="client_id" data-expect-end=".apps.googleusercontent.com"')
    expect(google).toContain('data-field="client_secret" data-expect-start="GOCSPX-"')
    expect(google).toContain("This does not end in <code>.apps.googleusercontent.com</code>.")
    const github = intakeBody(intake({ slug: "gh", provider: "github-pat", providerName: "GitHub token" }))
    expect(github).toContain('data-expect-start="github_pat_ ghp_"')
    expect(github).toContain("This does not start with <code>github_pat_</code> or <code>ghp_</code>.")
  })

  it("carry no warning where no template names a shape", () => {
    const body = intakeBody(intake(PROPOSED))
    expect(body).not.toContain("data-expect-")
    expect(body).not.toContain('data-region="field-warn"')
  })
})

describe("the connect page", () => {
  it("says the sign-in was interrupted when the vault handed the link back open", () => {
    const message = "The sign-in was interrupted before the connection was stored. Start it again."
    const body = connectBody(connect({ message }))
    expect(body).toContain(`<p class="callout" data-region="connect-retry">`)
    expect(body).toContain(message)
    expect(body).toContain('data-action="start-connect"')
    expect(connectBody(connect())).not.toContain('data-region="connect-retry"')
  })

  it("does not repeat the stored message's ask-the-agent ending on a failed card", () => {
    const body = connectBody(connect({ status: "failed", message: "The sign-in was interrupted before the connection was stored. Ask the agent for a new link." }))
    expect(body).toContain("The sign-in was interrupted before the connection was stored. Nothing was saved.")
    expect(body).not.toContain("stored. Ask the agent for a new link.")
    const member = connectBody(connect({ status: "failed", requestedBy: ME, message: "The sign-in at Gmail was cancelled or refused. Ask the agent for a new link to try again." }))
    expect(member).toContain("The sign-in at Gmail was cancelled or refused. Nothing was saved.")
    expect(member).not.toContain("Ask the agent")
  })

  it("explains an expiry from what actually ran out", () => {
    expect(connectBody(connect({ status: "expired", expiresAt: EARLIER }))).toContain("Connect links last 15 minutes. This connection did not complete in Mehen and nothing was saved. If you already signed in at Gmail, you may have authorised the app there; check there if you want to withdraw that access.")
    const client = connectBody(connect({ status: "expired", expiresAt: EARLIER, awaiting: { intake: "int_1", url: `${ORIGIN}/i/int_1`, status: "expired" } }))
    expect(client).toContain("The Google OAuth client was not added in time, so this connection could not start. Nothing was saved.")
    expect(client).not.toContain("once the client is in place")
  })

  it("says the link no longer works when it runs out, and names no button", () => {
    const body = connectBody(connect())
    expect(body).toContain("Nothing was saved. This link no longer works; ask for a new link.")
    expect(body).not.toContain("The button no longer works")
    expect(connectBody(connect({ requestedBy: ME }))).toContain("This link no longer works; start again from Connect a service.")
  })

  it("names the client by its template, and the connection, not the account, on a reconnect", () => {
    const waiting = connectPage(VIEWER, connect({ awaiting: { intake: "int_1", url: `${ORIGIN}/i/int_1`, status: "open" } }), NOW)
    expect(waiting.boot).toEqual({ page: "connect-waiting", connect: "con_1" })
    expect(waiting.body.value).toContain(`First, add the ${getTemplate("google-oauth-client")?.displayName}`)
    expect(connectBody(connect({ awaiting: { intake: "int_1", url: `${ORIGIN}/i/int_1`, status: "completed" } }))).toContain("Step 1 done: the Google OAuth client is saved.")
    const reconnect = connectPage(VIEWER, connect({ reconnect: true, currentScopes: [] }), NOW)
    expect(reconnect.title).toBe("Reconnect gmail-alex")
    expect(reconnect.body.value).toContain('<h1>Reconnect <code class="slug-inline">gmail-alex</code></h1>')
    expect(reconnect.body.value).toContain(">Reconnect gmail-alex</button>")
    const done = connectBody(connect({ status: "completed", account: "alex@example.com" }))
    expect(done).toContain("Gmail is connected for <strong>alex@example.com</strong> and stored as <code>gmail-alex</code>. Only machines allowed its tags, or every credential, can use it, and only within its home, its owner's rights, each machine's scope and the rules for Gmail.")
    expect(done).not.toContain("can use it now")
  })

  it("shows every tag the passkey signs, as text", () => {
    const legacy = connectBody({ ...connect(), tags: ["ci"] })
    expect(legacy).toContain('data-region="connect-tags"')
    expect(legacy).toContain("<code>ci</code>")
    const view: WorkspaceConnectView = { ...connect(), tags: ["ci", "<b>x</b>"], home: { kind: "workspace" }, permittedHomes: [{ kind: "workspace" }], intent: "create", target: null, client: null, dependencyRevision: 0 }
    const wrapped = workspaceConnectPage(galleryShell(VIEWERS.owner), view, [], NOW).body.value
    expect(wrapped).toContain("<code>ci</code>")
    expect(wrapped).toContain("<code>&lt;b&gt;x&lt;/b&gt;</code>")
    expect(wrapped).not.toContain("<b>x</b>")
    const document = renderDocument(workspaceConnectPage(galleryShell(VIEWERS.owner), view, [], NOW)).value
    expect(document).toContain("&quot;tags&quot;:[&quot;ci&quot;,&quot;&lt;b&gt;x&lt;/b&gt;&quot;]")
    expect(document).not.toContain("<b>x</b>")
    expect(wrapped).toContain("a matching tag alone grants nothing")
    for (const body of [connectBody(connect()), workspaceConnectPage(galleryShell(VIEWERS.owner), { ...view, tags: [] }, [], NOW).body.value]) {
      expect(body).not.toContain('data-region="connect-tags"')
      expect(body).not.toContain("a matching tag alone grants nothing")
    }
  })

  it("says Will be saved as before the connection is made, and how to pass Google's unverified screen", () => {
    const body = connectBody(connect())
    expect(body).toContain('Will be saved as <code class="slug-inline">gmail-alex</code>.')
    expect(body).toContain("choose Advanced, then Go to Mehen, or the name you gave the app.")
    expect(getTemplate("google-oauth-client")?.setup?.steps.some((s) => s.body.includes("Name the app Mehen."))).toBe(true)
  })
})

describe("adoption page", () => {
  const shell = galleryShell(VIEWERS.owner)
  const projects = [galleryProject(GALLERY_FIXTURES.OWNER_ACCESS, false)]
  const adoption = (view = GALLERY_ADOPTION) => workspaceAdoptionPage(shell, view, projects, NOW)
  const text = (view = GALLERY_ADOPTION) => renderDocument(adoption(view)).value
  // One row, from its tick to the next row or the end of its folder.
  const row = (page: string, ref: string) => {
    const start = page.indexOf(`data-ref="${ref}"`)
    const ends = [page.indexOf('<li class="adopt-row', start), page.indexOf("</ul></section>", start)].filter((i) => i !== -1)
    return start === -1 ? "" : page.slice(start, Math.min(...ends))
  }

  it("renders custom hosts in the danger style, every one spelled out, and the row unticked", () => {
    const custom = row(text(), "a002")
    expect(custom).toContain('class="adopt-custom"')
    expect(custom).toContain("Proposed by the agent, not verified.")
    for (const host of ["api.weatherapi.com", "weather-proxy.example.net"]) expect(custom).toContain(`<code>${host}</code>`)
    expect(custom).not.toMatch(/data-input="include" checked/)
    expect(row(text(), "a001")).not.toContain("adopt-custom")
  })

  it("spells out every limit and the delivery a custom row's passkey signs, and warns on hidden characters in them", () => {
    const signed = { ...GALLERY_ADOPTION.items[1]!, binding: { value: { hosts: ["api.weatherapi.com"], schemes: ["http" as const], ports: [8080], paths: ["/v1/**"], methods: ["GET"] }, verified: false }, injection: { value: { in: "query" as const, name: "debug", field: "key" }, verified: false } }
    const custom = row(text({ ...GALLERY_ADOPTION, items: [GALLERY_ADOPTION.items[0]!, signed] }), "a002")
    for (const limit of ["Only over http", "Only on port 8080", "Only to anything under /v1/", "Only with GET requests"]) expect(custom).toContain(`<li>${limit}</li>`)
    expect(custom).toContain("In the <code>debug</code> query parameter of the URL, from the field <code>key</code>.")
    expect(row(text(), "a001")).not.toContain('data-region="adopt-injection"')
    const hidden = { ...signed, binding: { value: { ...signed.binding.value, paths: ["/v1\u200B/**"] }, verified: false } }
    expect(adoptionTexts({ ...GALLERY_ADOPTION, items: [hidden] })).toContain("/v1\u200B/**")
    expect(adoptionTexts({ ...GALLERY_ADOPTION, items: [signed] })).toContain("debug")
  })

  it("says a custom row with a method of * allows any method, never that it is a limit", () => {
    const anyMethod = { ...GALLERY_ADOPTION.items[1]!, binding: { value: { hosts: ["api.weatherapi.com"], methods: ["GET", "*"] }, verified: false } }
    const custom = row(text({ ...GALLERY_ADOPTION, items: [GALLERY_ADOPTION.items[0]!, anyMethod] }), "a002")
    expect(custom).toContain("<li>With any method</li>")
    expect(custom).not.toContain("Only with")
  })

  it("starts stale rows and refused rows unticked, the rest ticked, and counts them in the bar", () => {
    const page = text()
    expect(row(page, "a003")).toContain('<span class="pill warn">stale</span>')
    for (const ref of ["a002", "a003", "a005"]) expect(row(page, ref), ref).not.toMatch(/data-input="include" checked/)
    for (const ref of ["a001", "a004"]) expect(row(page, ref), ref).toMatch(/data-input="include" checked/)
    expect(row(page, "a005")).toContain("You cannot add credentials to this home; choose another.")
    expect(row(page, "a005")).toContain('<option value="" selected>Choose where it belongs</option>')
    expect(page).toContain('<span data-region="approve-label">Approve 2 credentials</span>')
    expect(page).toContain("1 to This project (platform), 1 to Only me")
    expect(row(page, "a001")).toContain("<dt>Same value as</dt><dd>a004</dd>")
    expect(page).toContain(ADOPTION_RENAME_WORDS.replace("'", "&#39;"))
  })

  it("carries nothing in its boot data but the view's rows and the homes offered", () => {
    const page = adoption()
    expect(page.boot).toEqual({ page: "ws-adoption", adoption: GALLERY_ADOPTION.adoption, items: GALLERY_ADOPTION.items, homes: [["workspace", "Whole workspace"], ["project:prj_platform01", "This project (platform)"], ["member:mem_alex0001", "Only me"]] })
    const fields = new Set(GALLERY_ADOPTION.items.flatMap((i) => i.secrets.flatMap((s) => Object.keys(s))))
    expect([...fields].sort()).toEqual(["box", "fingerprint", "length", "name", "prefix"])
  })

  it("shows each compare row's holder, the result per field in words, the hints and what a replace reaches, by name only", () => {
    const page = text(GALLERY_CONFLICT_ADOPTION)
    const same = row(page, "c001")
    expect(same).toContain('data-region="conflict"')
    expect(same).toContain('<code class="slug-inline">openai-platform</code> is already in the vault, version 4')
    expect(same).toMatch(/last rotated <time datetime="[^"]+"[^>]*>[^<]+<\/time>, last used <time/)
    expect(same).toContain('<span class="field-name">key</span> <span class="pill ok">same value</span>')
    expect(same).toContain("The vault's value: 164 characters, starts <code>sk-proj-</code>")
    expect(same).toMatch(/<code>\/home\/alex\/code\/platform\/\.env<\/code> as <code>OPENAI_API_KEY<\/code> on linuxbox, changed <time/)
    const differs = row(page, "c002")
    expect(differs).toContain('<span class="pill warn">different value</span>')
    expect(differs).toContain('data-region="affected"')
    for (const ref of ["platform / dev / ANTHROPIC_API_KEY", "platform / prod / ANTHROPIC_API_KEY"]) expect(differs).toContain(`<li><code>${ref}</code></li>`)
    expect(differs).toContain("Machines that use it: hel1 and mac-mini.")
    expect(differs).toContain("2 devices hold a lease of its current value.")
    const staged = row(page, "c003")
    expect(staged).toContain("A row waiting in batch <code>adp_7kq2mw4zx1</code> holds this name.")
    expect(staged).toContain("<code>/Users/alex/.config/gh/hosts.yml</code> at <code>/github.com/oauth_token</code> on mac-mini")
    expect(staged).not.toContain('data-region="affected"')
    expect(row(page, "c004")).toContain('<span class="pill muted">could not be compared</span>')
    expect(row(page, "c004")).toContain("last used never")
    expect(row(page, "c005")).toContain("What this row was compared with is gone or hidden from you; send it again or leave it out.")
    expect(row(page, "c006")).not.toContain('data-region="conflict"')
    // Nothing is said of what held the name: only that a copy may be kept.
    expect(row(page, "c005")).toContain('data-region="actions"')
    for (const said of ['data-region="affected"', "holds this name", "is already in the vault", "A row of another batch"]) expect(row(page, "c005"), said).not.toContain(said)
  })

  it("offers each compare row only the actions it may take, a same value keeping the vault's and every other undecided", () => {
    const page = text(GALLERY_CONFLICT_ADOPTION)
    const actions = (ref: string) => [...row(page, ref).matchAll(/<input type="radio" name="action-[a-z0-9]+" value="([a-z]+)" data-input="action"( checked)?/g)].map((m) => `${m[1]}${m[2] ? "*" : ""}`)
    expect(["c001", "c002", "c003", "c004", "c005", "c006"].map((ref) => [ref, actions(ref)])).toEqual([
      ["c001", ["map*", "replace", "rename"]],
      ["c002", ["map", "replace", "rename"]],
      ["c003", ["rename"]],
      ["c004", ["map", "rename"]],
      ["c005", ["rename"]],
      ["c006", []],
    ])
    expect(row(page, "c002")).toContain("Keep the vault&#39;s value. This machine still holds another value: check it, then revoke it at the provider.")
    expect(row(page, "c001")).not.toContain("This machine still holds another value")
    expect(row(page, "c002")).toMatch(/<div class="adopt-rename" data-region="rename" hidden>.*<input type="text" data-input="rename-slug" value="anthropic-platform-dev"/s)
    expect(row(page, "c003")).toContain("A row of another batch can only be kept beside this one until that batch is decided.")
  })

  it("offers a kept copy the holder's referencing variables to point at it, none ticked, and none against a staged holder", () => {
    const page = text(GALLERY_CONFLICT_ADOPTION)
    const repoints = (ref: string) => [...row(page, ref).matchAll(/<input type="checkbox" data-input="repoint" data-project="([^"]+)" data-env="([^"]+)" data-variable="([^"]+)"( checked)?>/g)].map((m) => `${m[1]}/${m[2]}/${m[3]}${m[4] ? "*" : ""}`)
    expect(repoints("c002")).toEqual(["platform/dev/ANTHROPIC_API_KEY", "platform/prod/ANTHROPIC_API_KEY"])
    expect(row(page, "c002")).toContain("Point <code>platform / prod / ANTHROPIC_API_KEY</code> at this one, for every machine")
    expect(row(page, "c002")).toContain("A variable you leave unticked stays on <code>anthropic-platform</code>.")
    expect(repoints("c003")).toEqual([])
    expect(repoints("c004")).toEqual([])
  })

  it("says how many ticked rows need a decision, offers to keep the vault's value for every remaining one, and starts with approve disabled", () => {
    const page = text(GALLERY_CONFLICT_ADOPTION)
    expect(page).toContain('<span data-region="undecided">3 rows need a decision before you approve.</span>')
    expect(page).toContain('<button type="button" class="btn secondary sm" data-action="keep-vault-all">Keep the vault&#39;s value for every remaining one</button>')
    expect(page).toMatch(/data-action="approve-adoption"[^>]* disabled/)
    const plain = text()
    expect(plain).toContain('<span data-region="undecided" hidden></span>')
    expect(plain).not.toContain('data-action="keep-vault-all"')
  })

  it("offers to keep the batch open 3 more days, or what is left before the longest it can stay open, with the expiry it shows, until it reaches that longest", () => {
    const page = text(GALLERY_CONFLICT_ADOPTION)
    expect(page).toMatch(new RegExp(`<div class="adopt-keep" data-region="keep-open"><p class="small">Open until <span data-region="expires"><time datetime="${GALLERY_CONFLICT_ADOPTION.expiresAt}"[^>]*>[^<]+</time></span>; it can be kept open until <time datetime="${GALLERY_CONFLICT_ADOPTION.maxExpiresAt}"`))
    expect(page).toContain(`<button type="button" class="btn secondary sm" data-action="keep-open" data-expires="${GALLERY_CONFLICT_ADOPTION.expiresAt}"><span data-region="keep-open-label">Keep open 3 more days</span></button>`)
    const nearLongest = new Date(Date.parse(GALLERY_CONFLICT_ADOPTION.maxExpiresAt!) - 86_400_000).toISOString()
    expect(text({ ...GALLERY_CONFLICT_ADOPTION, expiresAt: nearLongest })).toContain(`data-expires="${nearLongest}"><span data-region="keep-open-label">Keep open 1 more day</span></button>`)
    expect(text({ ...GALLERY_CONFLICT_ADOPTION, expiresAt: GALLERY_CONFLICT_ADOPTION.maxExpiresAt! })).not.toContain('data-action="keep-open"')
    expect(text()).not.toContain('data-region="keep-open"')
  })

  it("never renders a compare fingerprint, a value or a tag: the fingerprints stay in the signing data", () => {
    const doc = text(GALLERY_CONFLICT_ADOPTION)
    const shown = doc.replace(/ data-boot="[^"]*"/, "")
    expect(shown).not.toBe(doc)
    for (const sentinel of [...GALLERY_COMPARE_FINGERPRINTS, ...GALLERY_CONFLICT_ADOPTION.items.flatMap((i) => i.secrets.map((s) => s.box))]) {
      expect(shown, sentinel).not.toContain(sentinel)
      expect(doc, sentinel).toContain(sentinel)
    }
    expect(adoption(GALLERY_CONFLICT_ADOPTION).boot).toMatchObject({ items: GALLERY_CONFLICT_ADOPTION.items })
    expect(adoptionTexts(GALLERY_CONFLICT_ADOPTION)).toEqual(expect.arrayContaining(["/Users/alex/.config/gh/hosts.yml", "hel1", "ANTHROPIC_API_KEY"]))
    expect(adoptionTexts(GALLERY_CONFLICT_ADOPTION).join("\n")).not.toContain(GALLERY_COMPARE_FINGERPRINTS[0])
  })

  it("offers no decision once the batch is closed", () => {
    for (const status of ["approved", "cancelled", "expired"] as const) {
      const page = text({ ...GALLERY_ADOPTION, status })
      expect(page, status).toContain(ADOPTION_CLOSED_WORDS[status].replace("'", "&#39;"))
      expect(page, status).not.toContain('data-form="adoption"')
      expect(page, status).not.toContain('data-action="approve-adoption"')
    }
  })
})

describe("adoption inventory page", () => {
  const shell = galleryShell(VIEWERS.owner)
  const projects = [galleryProject(GALLERY_FIXTURES.OWNER_ACCESS, false)]
  const text = (inventory = GALLERY_ADOPT_INVENTORY) => renderDocument(workspaceAdoptInventoryPage(shell, inventory, projects)).value
  const row = (page: string, slug: string) => {
    const start = page.indexOf(`data-slug="${slug}"`)
    const ends = [page.indexOf('<li class="inventory-row', start + 1), page.indexOf("</ul></section>", start)].filter((i) => i !== -1)
    return start === -1 ? "" : page.slice(start, Math.min(...ends))
  }

  it("lists one row per name, the machines that have it, and the item stored under it where this person may read it", () => {
    const page = text()
    expect(page).toContain("<h1>Adopted credentials</h1>")
    expect(row(page, "anthropic-platform")).toContain("On linuxbox and mac-mini.")
    expect(row(page, "anthropic-platform")).toContain('<a href="/w/northwind/items/anthropic-platform">In the vault, version 7</a>')
    expect(row(page, "github-pat-gh")).toContain("Nothing under this name that you can see.")
    expect(row(page, "github-pat-gh")).not.toContain("/items/")
  })

  it("links each open batch to its review page, and gives a result only where the vault gives one", () => {
    const page = text()
    const anthropic = row(page, "anthropic-platform")
    expect(anthropic).toContain('linuxbox: waiting in batch <a href="/w/northwind/b/adp_9cf3mw4zr2"><code>adp_9cf3mw4zr2</code></a> <span class="pill warn">different value</span>')
    expect(anthropic).toContain("mac-mini: stored by batch <code>adp_3hd8sk2pq7</code>")
    expect(anthropic).toContain("linuxbox&#39;s plan: ticked, already in the vault, backs <code>platform / dev / ANTHROPIC_API_KEY</code>")
    const github = row(page, "github-pat-gh")
    expect(github).toContain('mac-mini: waiting in batch <a href="/w/northwind/b/adp_7kq2mw4zx1"><code>adp_7kq2mw4zx1</code></a></li>')
    expect(row(page, "stripe-test")).toContain("mac-mini: uses the vault&#39;s value, by batch <code>adp_3hd8sk2pq7</code>")
    expect(row(page, "sentry-platform")).toContain("linuxbox&#39;s plan: left out, store-only")
    expect(page.match(/class="pill /g)?.length).toBe(2)
  })

  it("says when each machine last sent its plan", () => {
    expect(text()).toMatch(/linuxbox sent its plan <time datetime="[^"]+"/)
  })

  it("shows an empty state to a person whose adoptions touch no name", () => {
    const page = text({ rows: [], indexes: [] })
    expect(page).toContain("Nothing adopted yet")
    expect(page).not.toContain("inventory-row")
  })
})

// "How may agents use it?" on a new password-login where typing into web
// pages is on; there is no Sign in for them yet. The person's
// choice is signed as the intake's ceiling (logic.ts buildIntakeSubmission).
describe("the password-login intake's fill choice", () => {
  const shell = galleryShell(VIEWERS.owner)
  const fillPage = (view: WorkspaceIntakeView, fill: boolean) => workspaceIntakePage(shell, view, [], NOW, fill)

  it("offers Type it into the sign-in page and Not at all, Not at all ticked, with the sign-in page and the https-only sentence", () => {
    const page = fillPage(GALLERY_FILL_INTAKE, true)
    const body = page.body.value
    expect(body).toContain('<fieldset class="field" data-region="fill-choice"><legend class="label">How may agents use it?</legend>')
    expect(body).toContain(`<input type="radio" name="fill-ceiling" data-input="fill-ceiling" value="fill"><span><strong>Type it into the sign-in page</strong> mehen types it in only after checking the page's address. A script on that page, including one the agent runs, can read it.</span>`)
    expect(body).toContain('<input type="radio" name="fill-ceiling" data-input="fill-ceiling" value="relay" checked><span><strong>Not at all</strong> Only you can use it.</span>')
    expect(body).not.toContain("Sign in for them")
    expect(body).toContain('<p class="hint" data-region="fill-signin-page">Sign-in page: https://github.com</p>')
    expect(body).toContain('<p class="hint" data-region="fill-https-only" hidden>Only https sign-in pages can be filled.</p>')
    expect(body.indexOf('data-region="fill-choice"')).toBeGreaterThan(body.indexOf('data-field="password"'))
    expect(page.boot).toMatchObject({ fillChoice: true })
  })

  it("hides the sign-in page line where the ask names no page yet", () => {
    const body = fillPage({ ...GALLERY_FILL_INTAKE, binding: { value: { hosts: ["*.github.com"] }, verified: false } }, true).body.value
    expect(body).toContain('<p class="hint" data-region="fill-signin-page" hidden></p>')
  })

  it("leaves the page exactly as it was with the switch off, on a rotation and for another kind", () => {
    const off = fillPage(GALLERY_FILL_INTAKE, false)
    expect(off.body.value).not.toContain('data-region="fill-choice"')
    expect(off.boot).not.toHaveProperty("fillChoice")
    const rotation: WorkspaceIntakeView = { ...GALLERY_FILL_INTAKE, rotates: true, intent: "rotate", fields: GALLERY_FILL_INTAKE.fields.filter((f) => f.secret) }
    const key: WorkspaceIntakeView = { ...GALLERY_FILL_INTAKE, kind: "api-key", fields: [{ name: "key", label: "API key", secret: true, required: true, multiline: false, hint: null }] }
    for (const view of [rotation, key]) expect(renderDocument(fillPage(view, true)).value).toBe(renderDocument(fillPage(view, false)).value)
    expect(renderDocument(workspaceIntakePage(shell, GALLERY_FILL_INTAKE, [], NOW)).value).toBe(renderDocument(off).value)
  })
})
