// The one Needs you row: each inbox kind maps to its verb, its check value
// and who asked from where; the hidden fingerprint group is dots, never a
// group; links are the vault's own paths or nothing; a private ask can only
// be stopped; a claimed machine offered to an owner says Reject; the
// countdown runs from the row's own start and expiry; and hostile text is
// spelled, never markup.

import { describe, expect, it } from "vitest"
import { fingerprintGroups, fingerprintOf, fingerprintWords } from "@mehen/protocol/fingerprint"
import type { InboxItem, InboxWorkspace } from "@mehen/protocol/inbox"
import type { MinimalStopView, WorkspaceRef } from "@mehen/protocol/workspace"
import { INBOX_ACTION_LABELS, inboxRow, inboxRowOf, rowCountdown } from "./inbox-row.ts"

const NOW = Date.parse("2026-10-27T18:30:00Z")
const ISO = (offset: number) => new Date(NOW + offset).toISOString()
const WS: WorkspaceRef = { id: "tn_8kQw2Lm4Zp7Rt5Vx", slug: "northwind", name: "Northwind" }
const SUMMARY: InboxWorkspace = { workspace: WS, role: "owner", state: "ok", reason: null, count: 1, truncated: false }
const THUMBPRINT = "ZlSQ8zyOFnhkWls5Qf2JrXm9cTbA7hLp0eNvK1sYdGw"

function draw(item: InboxItem): string {
  return inboxRow(inboxRowOf(item, SUMMARY), { now: NOW, showWorkspace: false }).value
}

function enrol(overrides: Partial<Extract<InboxItem, { kind: "enrol" }>["enrol"]> = {}, action: InboxItem["action"] = "accept"): Extract<InboxItem, { kind: "enrol" }> {
  const groups: [string | null, string | null, string | null, string | null] = [...fingerprintGroups(fingerprintOf(THUMBPRINT))]
  groups[1] = null
  return {
    kind: "enrol",
    workspace: WS,
    href: "/w/northwind/e/enr_4h8s2kd9pq",
    action,
    createdAt: ISO(-20 * 60_000),
    expiresAt: ISO(40 * 60_000),
    enrol: { enrolment: "enr_4h8s2kd9pq", name: "tom-laptop", host: "toms-mbp.local", backend: "secure-enclave", start: { at: ISO(-20 * 60_000), place: "Amsterdam, NL", clientLabel: "mehen 0.3.0 on macOS" }, session: "claude-code:7c21", requestedOwner: { kind: "self" }, owner: null, claimed: null, state: "pending_owner_acceptance", fingerprint: { groups, words: fingerprintWords(THUMBPRINT) }, actions: ["accept", "reject"], hardExpiresAt: ISO(23 * 3_600_000), ...overrides },
  }
}

function approval(overrides: { title?: string; deviceName?: string; session?: string | null; href?: string } = {}): InboxItem {
  return {
    kind: "ask",
    workspace: WS,
    href: overrides.href ?? "/w/northwind/a/apr_6t3vb9nx2w",
    action: "decide",
    createdAt: ISO(-10 * 60_000),
    expiresAt: ISO(50 * 60_000),
    ask: { workspace: WS, owner: { kind: "member", member: "mem_alex", name: "Alex" }, view: "detail", detail: { kind: "approval", id: "apr_6t3vb9nx2w", title: overrides.title ?? "Send an email", url: "https://app.mehen.dev/w/northwind/a/apr_6t3vb9nx2w", expiresAt: ISO(50 * 60_000), item: "gmail-alex", requestedBy: { device: "dev_mac", deviceName: overrides.deviceName ?? "sam-mac-mini", session: overrides.session ?? "native-app:fa987f" }, bindingCode: "MK7RQ4" } },
  }
}

function stop(id: string): InboxItem {
  const view: MinimalStopView = { view: "stop", id, workspace: WS, machine: { device: "dev_kim", name: "kim-laptop", owner: { kind: "member", member: "mem_kim", name: "Kim" } }, item: { slug: "github-kim" }, status: "pending", eligibility: { canApprove: false, canDeny: true, canReadAskDetail: false, deciders: [], reason: null } }
  return { kind: "ask", workspace: WS, href: id.startsWith("apr_") ? `/w/northwind/a/${id}` : "/w/northwind/pending", action: "stop", createdAt: ISO(-60_000), expiresAt: ISO(60_000), ask: { workspace: WS, owner: { kind: "member", member: "mem_kim", name: "Kim" }, view: "stop", stop: view } }
}

describe("an ask", () => {
  it("shows its verb, its code, who asked from which machine with the label marked unverified, and links its page", () => {
    const row = draw(approval())
    expect(row).toContain('<a class="row-main" href="/w/northwind/a/apr_6t3vb9nx2w">')
    expect(row).toContain('<a class="btn primary sm" href="/w/northwind/a/apr_6t3vb9nx2w">Decide</a>')
    expect(row).toContain('Code <code class="code-inline">MK7RQ4</code>')
    expect(row).toContain("An agent on sam-mac-mini, session <code>native-app:fa987f</code> (a label the agent chose, not verified)")
    expect(row).toContain('data-key="apr_6t3vb9nx2w"')
  })

  it("spells hostile text and never renders it as markup", () => {
    const row = draw(approval({ title: "Pay <b>now</b>\u202e", deviceName: "Mac\u200bOffice", session: "<script>x</script>" }))
    expect(row).not.toContain("<b>now</b>")
    expect(row).not.toContain("<script>")
    expect(row).not.toMatch(/[\u200b\u202e]/)
    expect(row).toContain('<mark class="marker">')
  })

  it("links nothing that is not a path on this vault", () => {
    for (const href of ["https://evil.example/a", "//evil.example", "javascript:alert(1)", "/\\evil"]) {
      const row = draw(approval({ href }))
      expect(row, href).not.toContain("evil")
      expect(row, href).not.toContain("javascript:")
      expect(row, href).not.toContain('class="row-main" href')
    }
  })

  it("draws a private ask as one it can only stop, with no detail and no link into it", () => {
    const approvalStop = draw(stop("apr_9pk2mw4zq1"))
    expect(approvalStop).toContain("A private request from kim-laptop")
    expect(approvalStop).toContain("You cannot see it; you can stop it.")
    expect(approvalStop).toContain('<span class="row-main">')
    expect(approvalStop).toContain('<a class="btn danger-quiet sm" href="/w/northwind/a/apr_9pk2mw4zq1">Stop</a>')
    expect(draw(stop("int_4hz8rq2nk1"))).toContain('<button type="button" class="btn danger-quiet sm" data-action="cancel-ask" data-kind="intake" data-id="int_4hz8rq2nk1">Stop</button>')
    expect(draw(stop("con_4hz8rq2nk1"))).toContain('data-kind="connect"')
    expect(draw(stop("pol_4hz8rq2nk1"))).toContain('href="/w/northwind/p/pol_4hz8rq2nk1">Stop</a>')
  })
})

describe("an enrolment", () => {
  it("shows three groups and the hidden one as dots, the words with their colours, and never a thumbprint", () => {
    const item = enrol()
    const row = draw(item)
    const shown = item.enrol.fingerprint.groups.filter((g): g is string => g !== null)
    expect(shown.length).toBe(3)
    for (const g of shown) expect(row).toContain(`<code>${g}</code>`)
    expect(row).toContain('<code class="row-fp-hidden" aria-label="hidden group">····</code>')
    const hidden = fingerprintGroups(fingerprintOf(THUMBPRINT))[1]
    expect(row).not.toContain(`<code>${hidden}</code>`)
    expect(row).not.toContain(THUMBPRINT)
    for (const w of item.enrol.fingerprint.words) expect(row).toContain(`<b>${w.word}</b><small>${w.colour.name}</small>`)
    expect(row).toContain("Asked from toms-mbp.local in Amsterdam, NL by mehen 0.3.0 on macOS")
  })

  it("offers Accept with Reject beside it, Admit for an admission, and only Reject for a machine claimed by someone else", () => {
    const accept = draw(enrol())
    expect(accept).toContain(">Accept</a>")
    expect(accept).toContain('<a class="more-link" href="/w/northwind/e/enr_4h8s2kd9pq">Reject</a>')
    const admit = draw(enrol({ state: "pending_admission", owner: { kind: "member", member: "mem_tom", name: "Tom" }, actions: ["admit", "reject"] }, "admit"))
    expect(admit).toContain(">Admit</a>")
    expect(admit).toContain("Accepted by Tom; waiting to be admitted")
    const claimed = draw(enrol({ claimed: { account: "acc_mia", name: "Mia" }, actions: ["reject"] }, "reject"))
    expect(claimed).toContain('<a class="btn secondary sm" href="/w/northwind/e/enr_4h8s2kd9pq">Reject</a>')
    expect(claimed).not.toContain("more-link")
    expect(claimed).toContain("Started for Mia")
  })

  it("keys the row by its enrolment, which a renewal keeps", () => {
    expect(draw(enrol())).toContain('data-key="enr_4h8s2kd9pq"')
    expect(draw({ ...enrol(), expiresAt: ISO(59 * 60_000) })).toContain('data-key="enr_4h8s2kd9pq"')
  })
})

describe("confirmations and scope proposals", () => {
  it("names the member to confirm, and the machine whose scope waits", () => {
    const confirmRow = draw({ kind: "confirm", workspace: WS, href: "/w/northwind/people#confirm-mem_tom", action: "confirm", createdAt: ISO(-60_000), expiresAt: ISO(86_400_000), confirm: { member: "mem_tom", name: "Tom <i>Davies</i>", role: "admin", invite: "inv_1", termsDigest: "d", boundEmail: "tom@northwind.example", joinedAt: ISO(-60_000) } })
    expect(confirmRow).toContain("Tom &lt;i&gt;Davies&lt;/i&gt; joined as admin")
    expect(confirmRow).toContain('href="/w/northwind/people#confirm-mem_tom">Confirm</a>')
    const rescope = draw({ kind: "rescope", workspace: WS, href: "/w/northwind/devices/dev_tom", action: "review", createdAt: null, expiresAt: ISO(3_600_000), rescope: { proposal: "rsp_1", device: "dev_tom", deviceName: "tom-laptop", owner: { kind: "member", member: "mem_tom", name: "Tom" }, proposer: { member: "mem_alex", name: "Alex" }, as: "owner_acceptance" } })
    expect(rescope).toContain("A wider scope is waiting for tom-laptop")
    expect(rescope).toContain(">Review</a>")
    // No start time: the time left in words, no ring.
    expect(rescope).not.toContain("data-ring")
    expect(rescope).toContain("1 h 0 min left")
  })

  it("has a label for every verb the vault sends", () => {
    expect(Object.keys(INBOX_ACTION_LABELS).sort()).toEqual(["accept", "admit", "confirm", "connect", "decide", "open", "reconnect", "reject", "review", "stop"])
  })
})

describe("a group", () => {
  type Group = Extract<InboxItem, { kind: "group" }>["group"]
  const group = (floor: number, ownPage: number, overrides: Partial<Group> = {}): InboxItem => ({ kind: "group", workspace: WS, href: `/w/northwind/g/${overrides.group ?? "grp_1"}`, action: "review", createdAt: ISO(-60_000), expiresAt: ISO(60_000), group: { group: "grp_1", kind: "machine", machine: { device: "dev_mac", name: "sam-mac-mini", workload: null }, owner: { kind: "member", member: "mem_alex", name: "Alex" }, item: { slug: "gmail-alex" }, count: 4, floor, ownPage, reason: null, ...overrides } })

  it("says how many need a closer look and decide on their own page, in the singular for one", () => {
    expect(draw(group(1, 1))).toContain("1 needs a closer look. 1 decides on its own page.")
    expect(draw(group(2, 3))).toContain("2 need a closer look. 3 decide on their own page.")
  })

  it("leaves out a part whose count is 0, and reads All routine. when both are", () => {
    expect(draw(group(0, 2))).toContain("2 decide on their own page.")
    expect(draw(group(0, 2))).not.toContain("closer look")
    expect(draw(group(3, 0))).toContain("3 need a closer look.")
    expect(draw(group(3, 0))).not.toContain("own page")
    expect(draw(group(0, 0))).toContain("All routine.")
    expect(draw(group(0, 0))).toContain('<span class="row-sub">All routine.</span>')
  })

  it("says how many the viewer may only deny, reading a row without the count as none", () => {
    expect(draw(group(0, 0, { denyOnly: 4 }))).toContain('<span class="row-sub">4 can only be denied.</span>')
    expect(draw(group(0, 0, { denyOnly: 4 }))).not.toContain("All routine.")
    expect(draw(group(0, 0, { denyOnly: 0 }))).toContain("All routine.")
  })

  it("names the machine, the count and the credential, and opens Review together with its countdown", () => {
    const row = draw(group(1, 0))
    expect(row).toContain("sam-mac-mini: 4 asks on <code>gmail-alex</code>")
    expect(row).toContain('<a class="btn primary sm" href="/w/northwind/g/grp_1">Review together</a>')
    expect(row).toContain(`data-expires="${ISO(60_000)}"`)
  })

  it("adds the task line for a workload, its label the machine's words", () => {
    const row = draw(group(0, 0, { machine: { device: "dev_mac", name: "sam-mac-mini", workload: { id: "wl_1", label: "<b>contoso</b>" } } }))
    expect(row).toContain("Task <code>&lt;b&gt;contoso&lt;/b&gt;</code> (as the machine named it).")
  })

  it("reads a bundle as requests to approve together, its reason quoted as the agent's words", () => {
    const row = draw(group(0, 0, { group: "bnd_1", kind: "bundle", item: null, count: 12, reason: "Set up <i>Contoso</i>" }))
    expect(row).toContain("sam-mac-mini: 12 requests to approve together")
    expect(row).toContain('"Set up &lt;i&gt;Contoso&lt;/i&gt;" (the agent\'s words, not verified).')
    expect(row).toContain('href="/w/northwind/g/bnd_1">Review together</a>')
  })
})

describe("the countdown", () => {
  it("runs from the row's own start and expiry, never a constant", () => {
    const ring = rowCountdown(ISO(-30 * 60_000), ISO(30 * 60_000), NOW).value
    expect(ring).toContain(`data-expires="${ISO(30 * 60_000)}"`)
    expect(ring).toContain('data-total="3600"')
    expect(ring).toContain("30 min left")
    expect(rowCountdown(ISO(-6 * 3_600_000), ISO(18 * 3_600_000), NOW).value).toContain('data-total="86400"')
    expect(rowCountdown(null, null, NOW).value).toBe("")
  })
})
