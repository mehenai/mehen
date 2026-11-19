// The people, team, machine and Connect an agent pages as rendered: what
// each viewer sees and what is never there. The enrolment page is tested in
// workspace-asks-gallery.test.ts, the account pages in
// account-gallery.test.ts.
import { describe, expect, it } from "vitest"
import { AccountSessionSchema, TeamViewSchema, WorkspaceDeviceViewSchema, WorkspaceMemberViewSchema } from "@mehen/protocol/workspace"
import { WorkspaceInviteViewSchema } from "../vault/areas/workspace-runtime.ts"
import { renderDocument } from "./layout.ts"
import { connectAgentPage } from "./pages/connect-agent.ts"
import { machinePage } from "./pages/machines.ts"
import { GUEST_PEOPLE_WORDS, LINK_ONLY_INVITE_WORDS, LINK_ONLY_NO_PROJECT_WORDS, peoplePage } from "./pages/people.ts"
import { HOSTILE_NAME, HOSTILE_WORKSPACE, INVITE_FORM_EMAIL, INVITE_MADE_URL, PEOPLE_DEVICE, PEOPLE_INVITES, PEOPLE_MEMBERS, PEOPLE_PROJECTS, PEOPLE_SESSION, PEOPLE_TEAMS, THUMBPRINT, peopleData, peopleGallery, peopleShell } from "./people-gallery.ts"

const GALLERY_SCRIPT = Object.values(import.meta.glob<string>("../../scripts/ui-gallery.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""

function page(id: string): string {
  const entry = peopleGallery().find((e) => e.id === id)
  if (!entry) throw new Error(`no gallery entry ${id}`)
  return renderDocument(entry.page).value
}

// The controls a person's row offers, by data-action, for one member id.
function actionsFor(body: string, member: string): string[] {
  const row = new RegExp(`<li class="person" data-person="${member}">([\\s\\S]*?)</li>`).exec(body)?.[1] ?? ""
  return [...row.matchAll(/data-action="(member-[a-z-]+)"/g)].map((x) => x[1] as string).filter((a) => a !== "member-confirm-sign")
}

function bootOf(body: string): Record<string, unknown> {
  const raw = /data-boot="([^"]*)"/.exec(body)?.[1]
  if (raw === undefined) throw new Error("no boot payload")
  return JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&#39;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&#96;", "`").replaceAll("&amp;", "&")) as Record<string, unknown>
}

// Every copy box's text, as the browser copies it.
function copied(body: string): string[] {
  return [...body.matchAll(/<div class="copybox"><code>([^<]*)<\/code>/g)].map((x) => x[1] as string)
}

describe("the people gallery", () => {
  it("is registered in the gallery script, each id once", () => {
    expect(GALLERY_SCRIPT).toContain('import { peopleGallery } from "../src/ui/people-gallery.ts"')
    expect(GALLERY_SCRIPT).toContain("...peopleGallery(),")
    const ids = peopleGallery().map((e) => e.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it("uses fixtures in the frozen protocol shapes, with duplicate and hostile names", () => {
    for (const x of PEOPLE_MEMBERS) expect(WorkspaceMemberViewSchema.parse(x)).toEqual(x)
    for (const x of PEOPLE_TEAMS) expect(TeamViewSchema.parse(x)).toEqual(x)
    for (const x of PEOPLE_INVITES) expect(WorkspaceInviteViewSchema.parse(x)).toEqual(x)
    expect(WorkspaceDeviceViewSchema.parse(PEOPLE_DEVICE)).toEqual(PEOPLE_DEVICE)
    expect(AccountSessionSchema.parse(PEOPLE_SESSION)).toEqual(PEOPLE_SESSION)
    expect(PEOPLE_MEMBERS.filter((m) => m.name === "Sam")).toHaveLength(3)
    expect(PEOPLE_TEAMS.filter((t) => t.name === "Platform")).toHaveLength(2)
  })
})

describe("people: visible and hidden controls", () => {
  it("an owner gets changes the evaluator allows, none on themself or for anyone while held back", () => {
    const body = page("people-owner")
    expect(actionsFor(body, "mem_alex01")).toEqual([])
    expect(actionsFor(body, "mem_tom01")).toEqual(["member-role", "member-suspend", "member-remove"])
    expect(actionsFor(body, "mem_sam02")).toEqual(["member-role", "member-reinstate", "member-remove"])
    expect(actionsFor(body, "mem_hostile01")).toEqual(["member-confirm"])
    expect(body).toContain('data-form="invite"')
    expect(body).toContain('<option value="owner">Owner</option>')
    const held = page("people-held")
    for (const m of PEOPLE_MEMBERS) expect(actionsFor(held, m.member)).toEqual([])
    expect(held).not.toContain('data-form="invite"')
    expect(held).toContain('data-region="people-held"')
  })

  it("an admin changes no owner and cannot invite one", () => {
    const body = page("people-admin")
    expect(actionsFor(body, "mem_alex01")).toEqual([])
    expect(actionsFor(body, "mem_tom01")).toEqual([])
    expect(actionsFor(body, "mem_sam01")).toEqual(["member-role", "member-suspend", "member-remove"])
    expect(body).not.toContain('<option value="owner">')
  })

  it("folds each person's changes under Manage: a role placeholder, the consequence once, Remove as the outline danger", () => {
    const body = page("people-owner")
    const fold = /<details class="fold manage" data-region="manage" data-member="mem_tom01">([\s\S]*?)<\/details>/.exec(body)?.[1] ?? ""
    expect(fold).toContain("<span>Manage</span>")
    expect(fold).toContain('<option value="" selected disabled>Change role to ...</option>')
    expect(fold).toContain('data-action="member-role" data-member="mem_tom01" aria-label="Change the role of Tom Barker" disabled>')
    expect(fold).toContain('class="btn danger-quiet sm" data-action="member-remove"')
    expect(fold.indexOf("Removing revokes their machines")).toBeLessThan(fold.indexOf('data-input="member-role"'))
    expect(body.match(/Removing revokes their machines/g)?.length).toBe(body.match(/data-action="member-remove"/g)?.length)
    // No option is selected but the placeholder, so nobody is promoted by one click.
    expect(body).not.toMatch(/data-input="member-role"[^>]*><option value="(owner|admin|member|guest)"/)
    expect(body).not.toMatch(/class="btn danger( sm)?"/)
  })

  it("anchors a confirmation for Needs you, and keeps Review and confirm out of the fold", () => {
    const body = page("people-owner")
    expect(body).toContain('<div class="confirm-panel" id="confirm-mem_hostile01" data-region="confirm-panel" data-member="mem_hostile01" hidden>')
    expect(body).not.toContain('data-region="manage" data-member="mem_hostile01"')
  })

  it("puts teams and projects in the invite form's Access fold, with the delegation line outside it", () => {
    const body = page("people-owner")
    const access = /<details class="fold" data-region="invite-access">([\s\S]*?)<\/details>/.exec(body)?.[1] ?? ""
    expect(access).toContain('data-region="invite-teams"')
    expect(access).toContain('data-region="invite-projects"')
    expect(access).not.toContain('data-region="invite-delegation"')
    expect(body.indexOf('data-region="invite-access"')).toBeLessThan(body.indexOf('data-input="invite-days"'))
    expect(body).toContain('<code data-region="invite-message"></code>')
  })

  it("offers Email the link to them, ticked, under the email, and shows each outcome of emailing the link with the link to copy", () => {
    const body = page("people-owner")
    expect(body).toContain('<input type="email" data-input="invite-email" autocomplete="off" maxlength="254"></label>\n      <label class="tick" data-region="invite-email-link"><input type="checkbox" data-input="invite-email-link" checked><span>Email the link to them</span></label>')
    const entry = (id: string) => peopleGallery().find((e) => e.id === id)!
    const form = entry("people-invite-form")
    expect(form.swap?.[0]?.[1]).toContain(`value="${INVITE_FORM_EMAIL}"`)
    expect(body).toContain(form.swap![0]![0])
    for (const [id, words] of [
      ["people-invite-sent", `Mehen emailed this link to ${INVITE_FORM_EMAIL}.`],
      ["people-invite-limited", "This link was not emailed: too many invitation emails have gone from your account or to this address lately. Send it to them yourself."],
      ["people-invite-failed", "This link could not be emailed. Send it to them yourself."],
    ] as const) {
      const made = entry(id)
      expect(made.reveal, id).toEqual(["invite-made"])
      expect(made.fill?.["invite-url"], id).toBe(INVITE_MADE_URL)
      for (const [from] of made.swap ?? []) expect(renderDocument(made.page).value, id).toContain(from)
      expect(made.swap?.[0]?.[1], id).toContain('data-form="invite" novalidate hidden')
      expect(made.swap?.[1]?.[1], id).toBe(`data-region="invite-made-lead">${words} It works once, and only for that email: they join straight away once they prove it.<`)
    }
  })

  it("on a vault that cannot verify an email address, offers only a guest by link, says why, and opens the projects to share", () => {
    const body = page("people-local-owner")
    const roles = [...(/<select data-input="invite-role">([\s\S]*?)<\/select>/.exec(body)?.[1] ?? "").matchAll(/<option value="([a-z]+)"( selected)?/g)].map((m) => [m[1], m[2] !== undefined])
    expect(roles).toEqual([["guest", true]])
    expect(body).toContain('<input type="radio" name="invite-binding" data-input="invite-binding" value="open" checked>')
    expect(body).not.toMatch(/value="email"|data-input="invite-email"|data-input="invite-email-link"|data-input="invite-confirm-myself"/)
    expect(body).toContain(`<p class="small muted" data-region="invite-link-only">${LINK_ONLY_INVITE_WORDS}</p>`)
    expect(body).toContain('<details class="fold" data-region="invite-access" open>')
    expect(body).not.toContain('data-region="invite-teams"')
    expect(body).toContain("<span>Access: projects</span>")
    expect(page("people-local-no-project")).toContain(`${LINK_ONLY_INVITE_WORDS} ${LINK_ONLY_NO_PROJECT_WORDS}</p>`)
    // A vault that can verify one keeps today's form, the email first.
    const hosted = page("people-owner")
    expect(hosted).toContain('value="email" checked')
    expect(hosted).not.toContain('data-region="invite-link-only"')
    expect(renderDocument(peoplePage(peopleShell("owner"), { ...peopleData("owner"), emailInvites: true })).value).toBe(hosted)
  })

  it("offers Confirm them myself, unticked, and each invitation says what happens when they join", () => {
    const body = page("people-owner")
    expect(body).toContain('<label class="tick" data-region="invite-confirm-myself"><input type="checkbox" data-input="invite-confirm-myself"><span>Confirm them myself when they join</span></label>')
    const joins = (invite: string) => new RegExp(`data-invite="${invite}"[\\s\\S]*?data-region="invite-on-join">([^<]*)<`).exec(body)?.[1]
    expect(joins("inv_open01")).toBe("Joins straight away")
    expect(joins("inv_guest01")).toBe("You confirm them when they join")
    // Signed before onJoin existed: it waits, and says so.
    expect(joins("inv_used01")).toBe("You confirm them when they join")
  })

  it("a member reads people and changes nothing; no invitations", () => {
    const body = page("people-member")
    for (const m of PEOPLE_MEMBERS) expect(actionsFor(body, m.member)).toEqual([])
    expect(body).not.toContain('data-form="invite"')
    expect(body).not.toContain('data-region="invites"')
    expect(body).toContain("Noor Eddial")
  })

  it("a guest sees no other people, no invitations and no controls", () => {
    const body = page("people-guest")
    expect(body).toContain(GUEST_PEOPLE_WORDS)
    expect(body).not.toContain("data-person=")
    expect(body).not.toMatch(/data-action="member-|data-form="invite"|data-region="invites"|Noor|Tom Barker/)
    // Even given the full list, a guest's page shows none of it.
    const forced = renderDocument(peoplePage(peopleShell("guest"), { ...peopleData("owner"), viewer: { member: "mem_guest01", role: "guest", blocked: false } })).value
    expect(forced).not.toMatch(/Tom Barker|Noor Eddial|data-person=/)
  })

  it("teams: owners manage, members read, no maintainer anywhere, delete only without machines", () => {
    const owner = page("teams-owner")
    expect(owner).toContain('data-action="team-member-add" data-team="tm_platform01"')
    expect(owner).toContain('data-action="team-delete" data-team="tm_platform02"')
    expect(owner).not.toContain('data-action="team-delete" data-team="tm_platform01"')
    expect(owner).toContain("<code>platform</code>")
    expect(owner).toContain("<code>platform-ops</code>")
    expect(owner).toContain('class="btn danger-quiet sm" data-action="team-delete"')
    expect(owner).toMatch(/href="\/w\/northwind\/teams" aria-current="page"/)
    const member = page("teams-member")
    expect(member).not.toMatch(/data-action="team-|data-form="team-/)
    for (const body of [owner, member]) expect(body).not.toMatch(/data-[a-z-]*maintain|>Maintainer<|value="maintainer"/)
  })

  it("teams: a team with no shares points at where a project is shared, the project's Shared with card", () => {
    const owner = page("teams-owner")
    expect(owner).toContain("Share one with it under Shared with, on the project's page.")
    expect(owner).not.toContain("Access tab")
  })
})

describe("people: exact activation and hostile names", () => {
  it("confirmation shows the activation words and only the terms whose digest the vault returns", () => {
    const body = page("people-owner")
    expect(body).toContain("Confirming activates ")
    expect(body).toContain(" as Member with exactly these terms. Your passkey signs them; if any term changed since the invitation, the vault refuses and nothing is granted.")
    expect(body).toContain('data-terms-digest="dgst_hostile_terms" hidden')
    expect(body).not.toContain('data-terms-digest="dgst_open"')
    expect(body).toContain('data-action="member-confirm-sign" data-member="mem_hostile01" disabled')
  })

  it("renders a hostile name as text with markers, never markup or raw control characters", () => {
    for (const id of ["people-owner", "people-confirm", "connect-agent-hostile"]) {
      const body = page(id)
      expect(body, id).not.toContain("<b>x</b>")
      expect(body, id).not.toMatch(/[\u202e\u0007]/)
      expect(body, id).toContain('<mark class="marker">[RLO U+202E]</mark>')
    }
  })
})

describe("machines", () => {
  it("lists a machine's live workloads with the label marked as the machine's words, the scope in words and a passkey revoke", () => {
    const body = page("machine-workloads")
    const card = /<section class="card" data-region="workloads">([\s\S]*?)<\/section>/.exec(body)?.[1] ?? ""
    expect(card).toContain("<code>globex:grant-7f3k</code> <span class=\"muted small\">(as the machine named it)</span>")
    expect(card).toContain("Only openai-shared. Only these ways: through the vault only.")
    expect(card).toContain("All its machine may use.")
    expect(card).toContain('data-action="workload-revoke" data-workload="wl_task8kq2mw4z"')
    expect(card).toContain("seen never")
    expect(page("machine-review")).not.toContain('data-region="workloads"')
  })

  it("the notice's machine page leads with its owner and fingerprint and keeps revoke in a folded danger zone at the bottom", () => {
    const body = page("machine-review")
    expect(body).toContain("Acts for Tom Barker. Last seen 2 min ago.")
    expect(body.indexOf('class="fp-words"')).toBeLessThan(body.indexOf("<dt>Owner</dt>"))
    const zone = /<details class="card fold danger-zone" data-region="danger-zone">([\s\S]*?)<\/details>/.exec(body)?.[1] ?? ""
    expect(zone).toContain("Revoke this machine")
    expect(zone).toContain('class="btn danger-quiet" data-action="device-revoke"')
    expect(body.indexOf('data-region="danger-zone"')).toBeGreaterThan(body.indexOf("What it may use</h2>"))
    expect(body).not.toMatch(/class="btn danger"/)
    expect(body).toContain("How agents may use credentials through it</dt><dd>Through the vault only, signing, short-lived tokens and stand-in values</dd>")
    expect(body).not.toContain(">Ways<")
    expect(body).toContain('data-region="start"')
    expect(body).toContain("Amsterdam, NL")
    expect(body).toContain("mehen 0.2.0 on macOS")
    expect(body).toContain('class="fp-words"')
    expect(body).toContain("Private credentials</dt><dd>No</dd>")
    expect(page("machine-team")).not.toContain('data-input="scope-private"')
  })

  it("offers May run services in the scope form, and shows granting it as a wider scope waiting", () => {
    const body = page("machine-service-proposal")
    expect(body).toContain('<input type="checkbox" data-input="scope-service"><span>May run services: <code>mehen run --service</code> renews with no maximum life, in unprotected environments only</span>')
    const card = body.slice(body.indexOf('data-region="proposal"'))
    expect(card).toContain("A wider scope is waiting")
    expect(card).toMatch(/Services<\/[a-z]+>.*No.*Yes: it may start service runs \(mehen run --service\), which renew with no maximum life/s)
    expect(page("machine-team")).toContain('data-input="scope-service"')
  })

  it("owning acceptance of a wider scope says the machine will act as you", () => {
    const own = page("machine-own-proposal")
    expect(own).toContain("Accept this scope on my own machine")
    expect(own).toContain("This machine will act as you")
    expect(own).not.toContain("Admit ")
    // Plain text: no warning, accepting is the card's one primary.
    expect(own).toContain('<section class="card decision" data-region="proposal"')
    expect(own).toContain('class="btn primary" data-action="rescope-accept"')
    expect(own).not.toContain('data-region="warnings"')
    // Reject is the quiet second action, after Accept, and the owner sends no project.
    expect(own).toContain('<button type="button" class="btn quiet" data-action="rescope-reject" data-proposal="rsp_1">')
    expect(own.indexOf('data-action="rescope-accept"')).toBeLessThan(own.indexOf('data-action="rescope-reject"'))
    expect(own).not.toContain("data-project=")
    expect(own).toContain('<p class="eyebrow">A wider scope is waiting</p>')
  })

  it("a guest's machine: the designated admission signer gets Admit and a quiet Reject, for the guest's shared project", () => {
    const card = /<section class="card decision" data-region="proposal"[^>]*>[\s\S]*?<\/section>/.exec(page("machine-guest-admission"))?.[0] ?? ""
    expect(card).toContain('data-device="dev_tomlaptop01" data-thumbprint="' + THUMBPRINT + '" data-project="prj_site01"')
    expect(card).toContain('class="btn primary" data-action="rescope-admit" data-proposal="rsp_1"')
    expect(card).toContain('class="btn quiet" data-action="rescope-reject" data-proposal="rsp_1"')
    expect(card).not.toContain("rescope-accept")
  })

  it("Rescope, hostile proposer: the warning first, Reject emphasised, accepting quiet and still a passkey step", () => {
    const body = page("machine-rescope-hostile")
    const card = /<section class="card decision warned" data-region="proposal"[^>]*>([\s\S]*?)<\/section>/.exec(body)?.[1] ?? ""
    expect(card.trimStart().startsWith('<div data-region="warnings"><div class="notice error" role="alert">')).toBe(true)
    expect(card).toContain("hidden text-direction or invisible characters")
    expect(card).toContain("control characters")
    expect(card.indexOf('data-region="warnings"')).toBeLessThan(card.indexOf("A wider scope is waiting"))
    expect(card).toContain('<button type="button" class="btn danger" data-action="rescope-reject" data-proposal="rsp_1">')
    expect(card).toContain("<span>Reject this proposal</span>")
    expect(card.indexOf("rescope-reject")).toBeLessThan(card.indexOf("rescope-accept"))
    expect(card).toContain('class="btn quiet" data-action="rescope-accept"')
    expect(card).not.toContain('class="btn primary"')
    expect(card).toContain('data-region="rescope-rejected" role="status" hidden')
    expect(card).not.toMatch(/rescope-decline|Do not accept|nothing is sent/)
    expect(body).not.toMatch(/[\u202e\u0007]/)
    expect(card).toContain('<mark class="marker">[RLO U+202E]</mark>')
  })
})

describe("Connect an agent", () => {
  const PROMPT = "Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace northwind at https://app.mehen.dev. I will approve it in my browser; never ask me for a key, password or secret."

  it("copies the prompt and three commands with the slug and origin only, valid as printed", () => {
    expect(copied(page("connect-agent"))).toEqual([PROMPT, "curl -fsSL https://mehen.dev/install | sh", "mehen setup", "mehen enrol --workspace northwind"])
    for (const id of ["connect-agent", "connect-agent-code", "connect-agent-no-code", "connect-agent-hostile"]) {
      for (const text of copied(page(id))) expect(text, id).not.toMatch(/tn_|&lt;|&gt;|--name|&amp;/)
    }
  })

  it("as served, waits for the connect code on the two boxes it would change", () => {
    const body = page("connect-agent")
    expect(bootOf(body)).toMatchObject({ page: "connect-agent" })
    for (const box of ["prompt", "enrol"]) expect(body, box).toMatch(new RegExp(`data-box="${box}"><div class="copybox"><code>[^<]*</code><button type="button" class="btn secondary sm" data-copy disabled>`))
    for (const box of ["install", "setup"]) expect(body, box).toMatch(new RegExp(`data-box="${box}"><div class="copybox"><code>[^<]*</code><button type="button" class="btn secondary sm" data-copy>`))
    expect(body).toContain('data-region="connect-code-waiting" role="status">Getting your connect code</p>')
    expect(body).toMatch(/data-region="connect-code-note" hidden>/)
    expect(body).toContain('<details class="card fold" data-region="agent-commands">')
    expect(body).toContain("To name the machine, add <code>--name my-laptop</code>. It prints a link, the fingerprint and an <code>enr_</code> id. Approve here, then run <code>mehen wait enr_...</code> to finish.")
    expect(body).toContain("First time on this machine only; an installed Mehen keeps itself current.")
  })

  it("with a code, the prompt and the enrol box carry it, and the page says what it does and when it ends", () => {
    const body = page("connect-agent-code")
    expect(copied(body)).toEqual([
      "Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace northwind at https://app.mehen.dev with connect code 7XK2M9QP. I will approve it in my browser; never ask me for a key, password or secret.",
      "curl -fsSL https://mehen.dev/install | sh",
      "mehen setup",
      "mehen enrol --workspace northwind --connect 7XK2M9QP",
    ])
    expect(body).not.toContain("data-copy disabled")
    expect(body).toContain("The code sends this machine&#39;s approval to your own Needs you; it approves nothing by itself. It lasts a day, until")
    expect(body).toMatch(/data-region="connect-code-waiting" role="status" hidden>/)
  })

  it("without a code, the boxes are as served and enabled, with the vault's words", () => {
    const body = page("connect-agent-no-code")
    expect(copied(body)).toEqual(copied(page("connect-agent")))
    expect(body).not.toContain("data-copy disabled")
    expect(body).toContain('data-region="connect-code-refused">Wait a minute, then reload the page for a connect code.</p>')
    expect(body).toMatch(/data-region="connect-code-note" hidden>/)
  })

  it("never copies a display name, whatever it holds", () => {
    const texts = copied(page("connect-agent-hostile"))
    expect(texts).toHaveLength(4)
    for (const text of texts) {
      for (const piece of ["Tom", "rm -rf", "evil.example", "admin", "<b>", "\n", "\u202e", "\u0007"]) expect(text, piece).not.toContain(piece)
    }
    expect(texts[0]).toContain("workspace hostile-name at https://app.mehen.dev")
    expect(texts[3]).toBe("mehen enrol --workspace hostile-name")
    // The name is in the page around them, marked.
    expect(page("connect-agent-hostile")).toContain("Tom&quot;; rm -rf ~ &lt;b&gt;x&lt;/b&gt;")
    // A workspace whose slug fails the grammar offers nothing to copy.
    const broken = renderDocument(connectAgentPage(peopleShell("member", { workspace: { ...HOSTILE_WORKSPACE, slug: "Bad Slug" } }))).value
    expect(copied(broken)).toEqual([])
    expect(HOSTILE_NAME).toContain("\n")
  })
})

describe("Google verification slots", () => {
  it("leaves inactive, unlabelled slots for Google verification, no live control", () => {
    for (const id of ["people-owner"]) {
      const body = page(id)
      expect(body, id).toMatch(/class="oidc-slot" data-slot="oidc-[a-z-]+" hidden><\/div>/)
      expect(body, id).not.toMatch(/with Google|\/auth\/oidc/)
    }
  })
})

describe("people page render fixes", () => {
  it("two active people with one name have distinct visible and accessible labels at every control", () => {
    const body = page("people-owner")
    for (const id of ["mem_sam01", "mem_sam03"]) {
      expect(body).toContain(`<b>Sam</b> <code class="member-id">${id}</code>`)
      expect(body).toContain(`aria-label="Suspend Sam (${id})"`)
      expect(body).toContain(`<span class="sr">New role for Sam (${id})</span>`)
    }
    const teams = page("teams-owner")
    expect(teams).toContain('<option value="mem_sam03">Sam (mem_sam03)</option>')
    expect(teams).toContain('aria-label="Take Sam (mem_sam01) out of Platform (platform)"')
    // One Noor: no id needed.
    expect(body).toContain('aria-label="Suspend Noor Eddial"')
  })

  it("spells a hostile machine name in the tab title and marks it in the page", () => {
    const body = page("machine-hostile")
    const title = /<title>([^<]*)<\/title>/.exec(body)?.[1] ?? ""
    expect(title).toContain("[RLO U+202E]")
    expect(title).toContain("(northwind) · Mehen")
    expect(title).not.toMatch(/[\u202e\u0007]/)
    expect(body).not.toMatch(/[\u202e\u0007]/)
    expect(body).not.toContain("&lt;mark")
  })

  it("offers no rescope acceptance while the account is held back, and a guest only narrowing", () => {
    expect(page("machine-own-proposal")).toContain('data-action="rescope-accept"')
    expect(page("machine-own-proposal-held")).not.toContain('data-action="rescope-accept"')
    const guest = page("machine-guest")
    expect(guest).toContain("Narrow what it may use")
    expect(guest).toContain("&quot;propose&quot;:false")
    // Only the filter's own project is offered, so ticking can only narrow.
    expect(guest).toContain('data-input="scope-project" value="prj_site01" checked')
    expect(guest).not.toContain('value="prj_platform01"')
  })

  it("keeps the project filter when the editor cannot show it whole", () => {
    const shell = peopleShell("owner")
    const viewer = { member: "mem_alex01", role: "owner" as const, blocked: false }
    const filtered = { ...PEOPLE_DEVICE, scope: { ...PEOPLE_DEVICE.scope, projects: ["prj_hidden"] } }
    const unreadable = renderDocument(machinePage(shell, filtered, { viewer, projects: null, now: 0 })).value
    expect(unreadable).toContain("the project list could not be read")
    expect(unreadable).not.toContain('data-region="scope-projects"')
    const partial = renderDocument(machinePage(shell, filtered, { viewer, projects: [...PEOPLE_PROJECTS], now: 0 })).value
    expect(partial).toContain("includes projects you cannot see")
    expect(partial).not.toContain('data-region="scope-projects"')
    const whole = renderDocument(machinePage(shell, { ...filtered, scope: { ...filtered.scope, projects: ["prj_site01"] } }, { viewer, projects: [...PEOPLE_PROJECTS], now: 0 })).value
    expect(whole).toContain('data-region="scope-projects"')
  })

  it("names what a guest share delegates before the passkey, and withholds signing when it is unknown", () => {
    const body = page("people-owner")
    expect(body).toContain('data-share="prj_site01" data-delegates="openai-shared"')
    expect(body).toContain('data-share="prj_platform01" data-delegates=""')
    expect(body).not.toMatch(/data-delegates="[^"]*(unrelated-key|alex-own|site-deploy)/)
    expect(body).toContain('data-region="invite-delegation"')
    // Without the credentials read, every share row is unknown.
    const blind = renderDocument(peoplePage(peopleShell("owner"), { ...peopleData("owner"), credentials: null })).value
    expect(blind).toContain('data-share="prj_site01" data-delegates-unknown')
  })

  it("puts what an invitation delegates into the terms a confirmation signs", () => {
    const withShare = renderDocument(peoplePage(peopleShell("owner"), { ...peopleData("owner"), invites: PEOPLE_INVITES.map((i) => (i.id === "inv_used01" ? { ...i, terms: { ...i.terms, shares: [{ project: "prj_site01", level: "edit" as const, protected: false, expiresAt: null }] } } : i)) })).value
    const block = /data-terms-digest="dgst_hostile_terms" hidden>([\s\S]*?)<\/dl>/.exec(withShare)?.[1] ?? ""
    expect(block).toContain("Also lets them use")
    expect(block).toContain("<code>openai-shared</code>")
  })
})
