// Home and the lists (V-16), the parts that need no Worker: the capability
// line and the trust rule behind it, the audit sentences and who "You" is,
// and the relative times.

import { describe, expect, it } from "vitest"
import type { PolicyInput } from "@mehen/protocol/api"
import { OAUTH_PROVIDERS, TEMPLATES, connectionPolicy } from "@mehen/protocol/templates"
import { capabilityLineFor, capabilitySummary, destinationVerified, policyTrust } from "../src/ui/policy-trust.ts"
import { destinationBlock } from "../src/ui/components.ts"
import { actorWords, activityTime, auditLine, bindingLimits, capabilityLine, pathWords, relativeAgo, weekLabels } from "../src/ui/wording.ts"

const NOW = Date.parse("2026-10-24T18:30:00Z")
const openai = TEMPLATES.openai
const gmail = OAUTH_PROVIDERS["google-gmail"]
if (!openai || !gmail) throw new Error("templates")

// A policy an agent could have proposed: the note on the allow rule lies.
const LYING: PolicyInput = { default: "approve", rules: [{ action: "allow", methods: ["POST"], paths: ["/v1/users/*/messages/send"], note: "reads mail" }] }

describe("capability summaries", () => {
  it("trusts a template's notes only while the item still carries its hosts and policy", () => {
    expect(policyTrust({ provider: "openai", hosts: openai.binding.hosts, policy: openai.policy })).toBe("trusted")
    expect(policyTrust({ provider: "google-gmail", hosts: gmail.upstream.binding.hosts, policy: connectionPolicy(gmail) })).toBe("trusted")
    expect(policyTrust({ provider: "openai", hosts: ["api.openai.com", "evil.example"], policy: openai.policy })).toBe("untrusted")
    expect(policyTrust({ provider: "openai", hosts: openai.binding.hosts, policy: { ...openai.policy, rules: [...openai.policy.rules, LYING.rules[0] as PolicyInput["rules"][number]] } })).toBe("untrusted")
    expect(policyTrust({ provider: null, hosts: ["api.weatherapi.com"], policy: LYING })).toBe("untrusted")
    expect(policyTrust({ provider: "no-such-template", hosts: ["x.example"], policy: LYING })).toBe("untrusted")
  })

  it("never shows an untrusted note: the line and the three lines come from what the rules match", () => {
    const line = capabilityLineFor({ provider: null, hosts: ["api.weatherapi.com"], policy: LYING })
    expect(line).not.toContain("reads mail")
    expect(line).toBe("POST on /v1/users/*/messages/send on its own, the rest with your approval")
    const summary = capabilitySummary({ provider: null, hosts: ["api.weatherapi.com"], policy: LYING })
    expect(summary.allowed).toEqual(["POST on /v1/users/*/messages/send"])
    expect(JSON.stringify(summary)).not.toContain("reads mail")
  })

  it("reads a trusted template's notes, and keeps the rest where the default sends it", () => {
    expect(capabilityLineFor({ provider: "openai", hosts: openai.binding.hosts, policy: openai.policy })).toBe("reads and model calls and the data they use on its own, the rest with your approval")
    expect(capabilityLine(connectionPolicy(gmail), "trusted")).toBe("reads, creates a draft and 1 more on its own, sends email as you and the rest with your approval")
    expect(capabilityLine({ default: "allow", rules: [] }, "untrusted")).toBe("everything on its own")
    expect(capabilityLine({ default: "deny", rules: [] }, "untrusted")).toBe("every call refused")
    expect(capabilityLine({ default: "approve", rules: [] }, "untrusted")).toBe("every call with your approval")
    expect(capabilityLine({ default: "deny", rules: [{ action: "allow", methods: ["GET"], paths: ["/a", "/b", "/c"] }] }, "untrusted")).toBe("GET on 3 paths on its own, the rest refused")
  })

  it("marks a destination verified only when the hosts are exactly the template's", () => {
    expect(destinationVerified({ provider: "openai", binding: { hosts: ["api.openai.com"], paths: ["/v1/**"] } })).toBe(true)
    expect(destinationVerified({ provider: "openai", binding: { hosts: ["api.openai.com", "api.example.com"] } })).toBe(false)
    expect(destinationVerified({ provider: null, binding: { hosts: ["api.openai.com"] } })).toBe(false)
  })
})

const devices = new Map([["dev_mac", "Mac mini"]])

describe("audit sentences", () => {
  it("says You only when the actor is the signed-in member, from the session and nothing else", () => {
    expect(actorWords("member:mem_a", { self: "mem_a", devices })).toBe("You")
    expect(actorWords("member:mem_a", { self: "mem_b", devices })).toBe("Another member")
    // Another member by the name they chose, where the page loaded the members; never "You".
    const members = new Map([["mem_a", "Sam"], ["mem_b", "Alex"]])
    expect(actorWords("member:mem_a", { self: "mem_b", devices, members })).toBe("Sam")
    expect(actorWords("member:mem_b", { self: "mem_b", devices, members })).toBe("You")
    expect(actorWords("member:mem_c", { self: "mem_b", devices, members })).toBe("Another member")
    expect(actorWords("member:mem_a", { self: null, devices })).toBe("Another member")
    expect(actorWords("member:", { self: null, devices })).toBe("Another member")
  })

  it("names a device through the name the owner approved, never a session label, and says what it does not know", () => {
    expect(actorWords("device:dev_mac", { self: null, devices })).toBe("An agent on Mac mini")
    expect(actorWords("device:dev_gone", { self: null, devices })).toBe("An agent on a machine the vault no longer lists")
    expect(actorWords("system", { self: null, devices })).toBe("The vault")
    expect(actorWords("enrolment:enr_x", { self: null, devices })).toBe("A machine enrolling")
    expect(actorWords("sam", { self: null, devices })).toBe("Someone")
    // A relay row carrying the agent's session label in its detail never
    // reaches the actor line.
    const line = auditLine({ actor: "device:dev_mac", action: "relay.allow", target: "gmail-alex", detail: '{"host":"gmail.googleapis.com","method":"GET","session":"Robin"}' }, { self: null, devices })
    expect(line.actor).toBe("An agent on Mac mini")
    expect(line.pieces.map((p) => p.text).join("")).not.toContain("Robin")
  })

  it("turns each action into a sentence with a link only where the event has a page", () => {
    const ctx = { self: "mem_a", devices }
    const text = (line: ReturnType<typeof auditLine>) => line.actor + line.pieces.map((p) => p.text).join("")
    const request = auditLine({ actor: "device:dev_mac", action: "approval.request", target: "apr_1", detail: '{"item":"gmail-alex","method":"POST"}' }, ctx)
    expect(text(request)).toBe("An agent on Mac mini asked to use gmail-alex for a POST request")
    expect(request.link).toEqual({ href: "/a/apr_1", label: "Open the request" })
    const replaced = auditLine({ actor: "device:dev_mac", action: "approval.supersede", target: "apr_1", detail: '{"item":"gmail-alex","replacedBy":"apr_2"}' }, ctx)
    expect(text(replaced)).toBe("An agent on Mac mini replaced an ask to use gmail-alex with a newer one to the same place")
    expect(replaced.link).toEqual({ href: "/a/apr_2", label: "Open the newer request" })
    const bundled = auditLine({ actor: "device:dev_mac", action: "approval.bundle", target: "bnd_1", detail: '{"requests":3,"asked":2,"allowed":1,"refused":0}' }, ctx)
    expect(text(bundled)).toBe("An agent on Mac mini asked for 3 requests at once, 2 needing approval")
    expect(bundled.link).toBeNull()
    const deny = auditLine({ actor: "device:dev_mac", action: "relay.deny", target: "github-example", detail: '{"host":"api.github.com","method":"DELETE"}' }, ctx)
    expect(text(deny)).toBe("An agent on Mac mini tried DELETE api.github.com with github-example. Refused by its rules.")
    expect(deny.pieces.find((p) => p.as === "danger")?.text).toBe("Refused")
    expect(deny.link).toEqual({ href: "/items/github-example", label: "See the rules" })
    const approve = auditLine({ actor: "member:mem_a", action: "approval.approve", target: "apr_1", detail: '{"item":"gmail-alex","uses":1}' }, ctx)
    expect(text(approve)).toBe("You approved a request with gmail-alex, once")
    expect(approve.link).toBeNull()
    const reauth = auditLine({ actor: "system", action: "oauth.needs_reauth", target: "calendar-alex", detail: "{}" }, ctx)
    expect(reauth.link).toEqual({ href: "/items/calendar-alex", label: "Reconnect" })
    const echo = auditLine({ actor: "system", action: "relay.echo", target: "github-example", detail: '{"host":"api.github.com"}' }, ctx)
    expect(echo.link).toEqual({ href: "/items/github-example", label: "Review it" })
    const run = auditLine({ actor: "device:dev_mac", action: "run.create", target: "run_1", detail: '{"project":"prj_1","env":"dev","command":"bun test","vars":{"A":"plain","B":"placeholder:x"}}' }, ctx)
    expect(text(run)).toBe("An agent on Mac mini ran bun test in dev with 2 variables")
    expect(run.link).toEqual({ href: "/projects/prj_1", label: "Open the project" })
    // With the projects loaded, the run names its project.
    const named = auditLine({ actor: "device:dev_mac", action: "run.create", target: "run_1", detail: '{"project":"prj_1","env":"dev","command":"bun test","vars":{}}' }, { ...ctx, projects: new Map([["prj_1", "agent-runtime"]]) })
    expect(text(named)).toBe("An agent on Mac mini ran bun test in dev of agent-runtime with 0 variables")
    expect(named.pieces.find((p) => p.text === "agent-runtime")?.as).toBe("code")
    const enrol = auditLine({ actor: "member:mem_a", action: "device.enrol", target: "dev_mac", detail: '{"name":"the Linux box"}' }, ctx)
    expect(text(enrol)).toBe("You enrolled the Linux box")
    expect(enrol.pieces.find((p) => p.text === "the Linux box")?.as).toBe("name")
    expect(enrol.link).toEqual({ href: "/devices", label: "See machines" })
    const intake = auditLine({ actor: "device:dev_mac", action: "intake.create", target: "x", detail: '{"intake":"int_1"}' }, ctx)
    expect(intake.link).toEqual({ href: "/i/int_1", label: "Open the request" })
    const unknown = auditLine({ actor: "system", action: "something.new", target: "x/y", detail: "not json" }, ctx)
    expect(text(unknown)).toBe("The vault recorded something.new on x/y")
    expect(unknown.link).toBeNull()
    // A slug with a slash or a quote is encoded into the link, never pasted.
    const odd = auditLine({ actor: "system", action: "oauth.needs_reauth", target: 'a/b"c', detail: "{}" }, ctx)
    expect(odd.link?.href).toBe("/items/a%2Fb%22c")
  })

  it.each([
    ["grant.invalidate", "system", "gnt_1", {}, "The vault ended saved permission gnt_1 because access changed"],
    ["grant.create", "system", "gnt_1", { approval: "apr_1", proposal: null, parent: null }, "The vault saved permission gnt_1"],
    ["grant.revoke", "member:mem_a", "gnt_1", {}, "You stopped saved permission gnt_1"],
    ["policy.expire", "system", "pov_1", { item: "itm_1", device: "dev_mac" }, "The vault ended window pov_1 because its time ran out"],
    ["policy.replace", "system", "pov_1", { item: "itm_1", device: "dev_mac" }, "The vault replaced window pov_1 with a newer window"],
    ["policy.stale", "system", "pov_1", { item: "itm_1", device: "dev_mac" }, "The vault ended window pov_1 because access changed"],
    ["policy.revoke", "member:mem_a", "pov_1", { item: "itm_1", device: "dev_mac" }, "You stopped window pov_1"],
    ["policy.cancel", "device:dev_mac", "pol_1", {}, "An agent on Mac mini withdrew proposal pol_1 for wider access"],
    ["policy.propose", "device:dev_mac", "pol_1", { item: "itm_1", device: "dev_mac" }, "An agent on Mac mini proposed wider access in pol_1 for itm_1"],
    ["policy.activate", "member:mem_a", "pov_1", { item: "itm_1", device: "dev_mac", policyMode: "relaxed" }, "You turned on window pov_1 for wider access with itm_1"],
    ["policy.approve", "member:mem_a", "pol_1", { effectDigest: "hash" }, "You approved proposal pol_1 for wider access"],
    ["policy.deny", "member:mem_a", "pol_1", { effectDigest: null }, "You denied proposal pol_1 for wider access"],
  ])("words %s with its recorded actor and target", (action, actor, target, detail, expected) => {
    const line = auditLine({ actor, action, target, detail: JSON.stringify(detail) }, { self: "mem_a", devices })
    expect(line.actor + line.pieces.map((p) => p.text).join("")).toBe(expected)
    expect(line.pieces).toContainEqual({ text: target, as: "code" })
    expect(line.link).toBeNull()
  })

  it("distinguishes a proposal closed by changed access from a window that ended", () => {
    const line = auditLine({ actor: "system", action: "policy.stale", target: "pol_1", detail: '{"item":"custom-key"}' }, { self: null, devices })
    expect(line.actor + line.pieces.map((p) => p.text).join("")).toBe("The vault closed proposal pol_1 because access changed")
  })

  it("does not call every saved permission a remembered route: exact approvals use the same events", () => {
    for (const detail of [{ approval: "apr_1", proposal: null, parent: null }, { approval: null, proposal: "pol_1", parent: null }, { approval: "apr_1", proposal: null, parent: "pov_1" }]) {
      const line = auditLine({ actor: "system", action: "grant.create", target: "gnt_1", detail: JSON.stringify(detail) }, { self: null, devices })
      expect(line.actor + line.pieces.map((p) => p.text).join("")).toBe("The vault saved permission gnt_1")
    }
  })

  it("tells how careful a credential was set, put back, and used without asking, never with a path", () => {
    const say = (action: string, detail: Record<string, unknown>) => { const line = auditLine({ actor: "system", action, target: "github-work", detail: JSON.stringify(detail) }, { self: null, devices }); return line.actor + line.pieces.map((p) => p.text).join("") }
    expect(say("posture.set", { before: "ask", after: "routine", machines: null })).toBe("The vault set how careful github-work is: let routine building through")
    expect(say("posture.set", { before: "routine", after: "trust", machines: 2 })).toBe("The vault set how careful github-work is: trust the machines of those who manage it, on 2 machines")
    expect(say("posture.reset", { reason: "rehome", before: "routine" })).toBe("The vault put github-work back to asking for every change, as it moved to another home")
    expect(say("posture.use", { entry: "github.issue-create", method: "POST", host: "api.github.com", level: "routine" })).toBe("The vault used github-work without asking, as routine building: POST api.github.com")
    expect(say("posture.use", { entry: "unreviewed", method: "POST", host: "api.github.com", level: "trust" })).toBe("The vault used github-work without asking, on a trusted machine: POST api.github.com")
    expect(say("posture.nudge_quiet", {})).toBe("The vault chose not to be reminded about github-work for 7 days")
  })

  // A private credential's row keeps only its minimal event, so the level
  // or reason is its outcome; with neither, the sentence stays neutral.
  it("tells a private credential's posture rows from their outcome, and neutrally with neither", () => {
    const minimal = (action: string, actor: string, outcome: string) => { const line = auditLine({ actor, action, target: "github-mine", detail: JSON.stringify({ action, at: 1, actor: actor === "member:mem_a" ? { kind: "member", member: "mem_a" } : { kind: "device", device: "dev_mac", owner: { kind: "member", member: "mem_a" } }, session: null, item: "itm_1", slug: "github-mine", outcome, run: null }) }, { self: "mem_a", devices }); return line.actor + line.pieces.map((p) => p.text).join("") }
    const say = (action: string, detail: Record<string, unknown>) => { const line = auditLine({ actor: "system", action, target: "github-mine", detail: JSON.stringify(detail) }, { self: null, devices }); return line.actor + line.pieces.map((p) => p.text).join("") }
    expect(minimal("posture.set", "member:mem_a", "routine")).toBe("You set how careful github-mine is: let routine building through")
    expect(minimal("posture.set", "member:mem_a", "trust")).toBe("You set how careful github-mine is: trust the machines of those who manage it")
    expect(minimal("posture.set", "member:mem_a", "ask")).toBe("You set how careful github-mine is: ask for every change")
    expect(minimal("posture.reset", "member:mem_a", "rehome")).toBe("You put github-mine back to asking for every change, as it moved to another home")
    expect(say("posture.reset", { item: "itm_1", outcome: "managed" })).toBe("The vault put github-mine back to asking for every change, as its platform decides")
    expect(minimal("posture.use", "device:dev_mac", "routine")).toBe("An agent on Mac mini used github-mine without asking, as routine building")
    expect(minimal("posture.use", "device:dev_mac", "trust")).toBe("An agent on Mac mini used github-mine without asking, on a trusted machine")
    expect(say("posture.set", {})).toBe("The vault set how careful github-mine is")
    expect(say("posture.reset", {})).toBe("The vault put github-mine back to asking for every change")
    expect(say("posture.use", {})).toBe("The vault used github-mine without asking")
  })

  it("has a sentence for every action the vault records, so the audit log never falls back to an action code", () => {
    const sources = import.meta.glob<string>(["../src/**/*.ts", "!../src/**/*.test.ts"], { query: "?raw", import: "default", eager: true })
    const actions = new Set<string>()
    for (const source of Object.values(sources)) {
      for (const call of source.matchAll(/audit\(\{[^}]*?action: ([^,}]+)/g)) {
        for (const quoted of (call[1] as string).matchAll(/"([a-z_]+\.[a-z_.]+)"/g)) actions.add(quoted[1] as string)
      }
    }
    expect(actions.size).toBeGreaterThan(30)
    expect([...actions].filter((a) => a.startsWith("item."))).toEqual(expect.arrayContaining(["item.create", "item.replace"]))
    const ctx = { self: "mem_a", devices }
    const fallback = [...actions].filter((action) => {
      const line = auditLine({ actor: "system", action, target: "x", detail: "{}" }, ctx)
      return line.pieces.some((p) => p.text === " recorded ")
    })
    expect(fallback).toEqual([])
  })
})

describe("binding paths in words", () => {
  it("words a path glob plainly wherever a binding is shown to a person", () => {
    expect(pathWords("/v1/**")).toBe("anything under /v1/")
    expect(pathWords("/repos/*/pulls")).toBe("/repos/<any>/pulls")
    expect(pathWords("/repos/*/pulls/**")).toBe("anything under /repos/<any>/pulls/")
    expect(pathWords("/**")).toBe("any path")
    expect(pathWords("/v1/**/capture")).toBe("/v1/<anything>/capture")
    expect(pathWords("/token")).toBe("/token")
    expect(bindingLimits({ hosts: ["gmail.googleapis.com"], paths: ["/gmail/v1/**", "/upload/gmail/v1/**"], methods: ["get", "post"] })).toEqual([
      "Only to anything under /gmail/v1/ or anything under /upload/gmail/v1/",
      "Only with GET or POST requests",
    ])
    const block = destinationBlock({ hosts: ["api.github.com"], paths: ["/repos/*/pulls", "/user"] }, false, null).value
    expect(block).toContain("<li>Only to /repos/&lt;any&gt;/pulls or /user</li>")
    expect(block).not.toContain("/*")
  })
})

describe("times", () => {
  it("words relative times and the activity column in UTC", () => {
    expect(relativeAgo(NOW - 20_000, NOW)).toBe("just now")
    expect(relativeAgo(NOW - 32 * 60_000, NOW)).toBe("32 min ago")
    expect(relativeAgo(NOW - 6 * 3_600_000, NOW)).toBe("6 hours ago")
    expect(relativeAgo(NOW - 26 * 3_600_000, NOW)).toBe("yesterday")
    expect(relativeAgo(NOW - 4 * 86_400_000, NOW)).toBe("4 days ago")
    expect(relativeAgo(NOW - 30 * 86_400_000, NOW)).toBe("24 Sep")
    expect(relativeAgo("not a time", NOW)).toBeNull()
    expect(activityTime(NOW - 2 * 60_000, NOW)).toBe("18:28")
    expect(activityTime(NOW - 26 * 3_600_000, NOW)).toBe("Fri")
    expect(activityTime(NOW - 12 * 86_400_000, NOW)).toBe("12 Oct")
    expect(weekLabels([{ day: "2026-10-18" }, { day: "2026-10-24" }, { day: "bad" }])).toEqual(["Sun", "Sat", "bad"])
  })
})
