import { expect, it } from "vitest"
import { auditLine } from "../src/ui/wording.ts"

it("renders member.join_aborted as fixed words without private or hostile detail and no link", () => {
  const sentinel = 'private@example.test </main><script>alert(1)</script> https://hostile.test/'
  const result = auditLine({ actor: "system", action: "member.join_aborted", target: sentinel, detail: JSON.stringify({ member: sentinel, name: sentinel, email: sentinel, slug: sentinel }) }, { self: null, devices: new Map<string, string>() })
  expect(result.pieces).toEqual([{ text: " cancelled an incomplete invitation redemption" }])
  expect(result.link).toBeNull()
  expect(JSON.stringify(result)).not.toContain(sentinel)
})


it("renders member.promotion_cancelled without interpolating pending role or promoter detail", () => {
  const sentinel = 'private </main><script>alert(1)</script>'
  const result = auditLine({ actor: "system", action: "member.promotion_cancelled", target: sentinel, detail: JSON.stringify({ role: sentinel, promoter: sentinel, reason: sentinel }) }, { self: null, devices: new Map<string, string>() })
  expect(result.pieces).toEqual([{ text: " cancelled a pending role promotion" }])
  expect(result.link).toBeNull()
  expect(JSON.stringify(result)).not.toContain(sentinel)
})

it("renders device.enrol_expired without enrolment detail or invented links", () => {
  const result = auditLine({ actor: "system", action: "device.enrol_expired", target: "private-enrolment", detail: '{"name":"hostile </main>"}' }, { self: null, devices: new Map<string, string>() })
  expect(result.pieces).toEqual([{ text: " closed an expired machine enrolment" }])
  expect(result.link).toBeNull()
})

it("words the workspace's own and its people's events instead of recording the raw action", () => {
  const ctx = { self: "mem_alex", devices: new Map<string, string>(), members: new Map([["mem_alex", "Alex"], ["mem_tom", "Tom"]]) }
  const words = (action: string, target: string | null, detail: unknown = {}) => {
    const line = auditLine({ actor: "member:mem_alex", action, target, detail: JSON.stringify(detail) }, ctx)
    return line.actor + line.pieces.map((p) => p.text).join("")
  }
  expect(words("workspace.freeze", "tn_work")).toBe("You froze the workspace. Every machine use is refused until an owner unfreezes it")
  expect(words("workspace.unfreeze", "tn_work")).toBe("You unfroze the workspace")
  expect(words("workspace.update", "tn_work", { name: "Northwind", slug: "northwind" })).toBe("You renamed the workspace to Northwind, short name northwind")
  expect(words("member.confirm", "mem_tom")).toBe("You confirmed Tom")
  expect(words("member.suspend", "mem_tom")).toBe("You suspended Tom")
  expect(words("member.reinstate", "mem_gone")).toBe("You reinstated a member")
  expect(words("member.remove", "mem_tom", { devices: 2, privateItems: 1, exposedValues: 0 })).toBe("You removed Tom. 2 machines revoked, 1 private credential deleted")
  expect(words("member.join", "mem_alex")).toBe("You joined the workspace")
  expect(words("member.invite_revoked", "inv_1")).toBe("You revoked an invitation")
  expect(words("invite.emailed", "inv_1", { email: "ravi@northwind.example" })).toBe("You emailed an invitation's link to the invited address")
  expect(words("team.member_add", "tm_1", { member: "mem_tom" })).toBe("You added Tom to a team")
  expect(words("team.delete", "tm_1")).toBe("You deleted a team and its project shares")
  for (const action of ["workspace.freeze", "member.remove", "team.create", "team.member_remove", "member.leave"]) expect(words(action, "x"), action).not.toContain("recorded")
})

it("never takes a person's name from an event's own detail", () => {
  const sentinel = "Mallory </main>"
  const line = auditLine({ actor: "member:mem_alex", action: "member.remove", target: "mem_unknown", detail: JSON.stringify({ name: sentinel }) }, { self: null, devices: new Map<string, string>() })
  expect(JSON.stringify(line)).not.toContain("Mallory")
})

it("words a batch decision by its counts alone", () => {
  const words = (detail: unknown) => { const line = auditLine({ actor: "member:mem_alex", action: "approval.batch", target: "apb_test", detail: JSON.stringify(detail) }, { self: "mem_alex", devices: new Map<string, string>() }); return line.actor + line.pieces.map((p) => p.text).join("") }
  expect(words({ approved: 11, denied: 0, skipped: 1 })).toBe("You decided requests together: 11 approved, 1 left undecided")
  expect(words({ approved: 0, denied: 2, skipped: 0 })).toBe("You decided requests together: 2 denied")
})
