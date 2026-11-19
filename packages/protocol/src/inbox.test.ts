import { expect, test } from "bun:test"
import { fingerprintWords } from "./fingerprint.ts"
import type { InboxItem, InboxResponse, InboxWorkspace, WorkspaceInboxResponse } from "./index.ts"
import { WorkspaceNoticeSchema, type OwnerRef, type WorkspaceNotice, type WorkspaceRef } from "./workspace.ts"

const workspace: WorkspaceRef = { id: "tn_work0001", slug: "northwind", name: "Northwind" }
const owner: OwnerRef = { kind: "member", member: "mem_alex01", name: "Alex" }
const at = "2027-01-01T00:00:00.000Z"
const base = { workspace, createdAt: at, expiresAt: null }

const items: InboxItem[] = [
  { ...base, kind: "ask", href: "/w/northwind/a/apr_1", action: "decide", ask: { workspace, owner, view: "detail", detail: { kind: "approval", id: "apr_1", title: "Send an email", url: "https://app.mehen.dev/w/northwind/a/apr_1", expiresAt: at, requestedBy: null, item: "gmail-alex", createdAt: at } } },
  {
    ...base, kind: "enrol", href: "/w/northwind/e/enr_1", action: "accept",
    enrol: { enrolment: "enr_1", name: "tom-laptop", host: null, backend: "secure-enclave", start: { at, place: null, clientLabel: "mehen 0.3.0" }, session: null, requestedOwner: { kind: "self" }, owner: null, claimed: null, state: "pending_owner_acceptance", fingerprint: { groups: ["7KQ2", null, "M4TR", "X9PD"], words: fingerprintWords("A".repeat(43)) }, actions: ["accept", "reject"], hardExpiresAt: at },
  },
  { ...base, kind: "confirm", href: "/w/northwind/people#confirm-mem_sam01", action: "confirm", confirm: { member: "mem_sam01", name: "Sam", role: "member", invite: "inv_1", termsDigest: "d", boundEmail: null, joinedAt: at } },
  { ...base, kind: "rescope", href: "/w/northwind/devices/dev_1", action: "review", rescope: { proposal: "rsp_1", device: "dev_1", deviceName: "tom-laptop", owner, proposer: { member: "mem_alex01", name: "Alex" }, as: "owner_acceptance" } },
  { ...base, kind: "group", href: "/w/northwind/g/grp_1", action: "review", group: { group: "grp_1", kind: "machine", machine: { device: "dev_1", name: "tom-laptop", workload: null }, owner, item: { slug: "cloudflare-api-token" }, count: 12, floor: 3, ownPage: 1, reason: null } },
]

// Exhaustive over the five kinds: a sixth kind fails to compile here.
function subject(item: InboxItem): string {
  switch (item.kind) {
    case "ask": return item.ask.view === "detail" ? item.ask.detail.id : item.ask.stop.id
    case "enrol": return item.enrol.enrolment
    case "confirm": return item.confirm.member
    case "rescope": return item.rescope.proposal
    case "group": return item.group.group
    default: { const never: never = item; return never }
  }
}

test("every inbox item kind carries its own subject and survives a JSON round trip", () => {
  expect(items.map(subject)).toEqual(["apr_1", "enr_1", "mem_sam01", "rsp_1", "grp_1"])
  expect(JSON.parse(JSON.stringify(items))).toEqual(items)
})

test("inbox notices are the outbox envelope, carried unchanged", () => {
  const notice: WorkspaceNotice = WorkspaceNoticeSchema.parse({ id: "ntc_1", account: "acc_alex", payload: { kind: "machine_added", workspace, device: "dev_1", name: "tom-laptop", owner, place: null, at }, at: 1798761600000, url: "https://app.mehen.dev/w/northwind/devices/dev_1" })
  const row: InboxWorkspace = { workspace, role: "owner", state: "ok", reason: null, count: items.length, truncated: false }
  const all: InboxResponse = { workspaces: [row], items, notices: [notice], count: items.length, complete: true }
  const one: WorkspaceInboxResponse = { workspace: row, items, notices: [notice] }
  expect(WorkspaceNoticeSchema.parse(JSON.parse(JSON.stringify(all.notices[0])))).toEqual(notice)
  expect(one.notices).toEqual(all.notices)
  expect(WorkspaceNoticeSchema.safeParse({ ...notice, extra: true }).success).toBe(false)
})
