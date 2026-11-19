import { describe, expect, it } from "vitest"
import { auditLine } from "../src/ui/wording.ts"

const sentences = [
  ["project.share", " changed access to a project"],
  ["project.unshare", " removed a project share"],
  ["project.delete", " deleted a project"],
  ["device.enrol_rejected", " rejected a machine enrolment"],
  ["device.rescope_proposed", " asked to change what a machine may use"],
  ["device.rescope_signed", " confirmed a proposed change to what a machine may use"],
  ["device.rescope_rejected", " rejected a proposed change to what a machine may use"],
  ["member.role", " updated a member's role"],
  ["member.invite", " invited someone to the workspace"],
  ["account.security.install", " updated account security"],
  ["account.security.restriction", " changed the account's temporary security limits"],
  ["account.session_revoke", " signed out a session"],
  ["name.miss_limit", " reached the hourly limit for unavailable names"],
] as const

for (const [action, sentence] of sentences) {
  it(`renders ${action} without private detail or invented links`, () => {
    const result = auditLine({
      actor: "system",
      action,
      target: "private-target",
      detail: JSON.stringify({ slug: "guessed-private-slug", member: "private-member", session: "private-session", email: "private@example.test" }),
    }, { self: null, devices: new Map<string, string>() })
    expect(result.pieces).toEqual([{ text: sentence }])
    expect(result.link).toBeNull()
  })
}

// push.* rows (areas/pushes.ts auditPush): the credential by the row's
// target, never the detail's item id; the place in words; the carrying
// credential only when the row names it; a refusal in red with the
// provider's status; a push not sent with the vault's reason.
describe("push rows", () => {
  const words = { self: "mem_alex0001", members: new Map([["mem_alex0001", "Alex"]]), devices: new Map([["dev_macmini1", "mac-mini"]]) }
  const pushRow = (action: string, detail: Record<string, unknown>, actor = "device:dev_macmini1") => auditLine({ actor, action, target: "openai-prod", detail: JSON.stringify({ item: "itm_openaiprod0001", destination: "github:acme/api/OPENAI_API_KEY", via: "gh-token", version: 4, approval: "apr_9pq4wn2kx7", ...detail }) }, words)
  const text = (line: ReturnType<typeof auditLine>) => `${line.actor}${line.pieces.map((p) => p.text).join("")}`

  it("says where it was put, which version, with what, and whether it was new there", () => {
    const done = pushRow("push.done", { outcome: "replaced" })
    expect(text(done)).toBe("An agent on mac-mini put openai-prod version 4 into GitHub acme/api, Actions secret OPENAI_API_KEY with gh-token, replacing the value there")
    expect(done.pieces).toContainEqual({ text: "GitHub acme/api, Actions secret OPENAI_API_KEY", as: "code" })
    expect(done.link).toEqual({ href: "/items/openai-prod", label: "Open the credential" })
    expect(text(pushRow("push.done", { outcome: "created" }, "member:mem_alex0001"))).toBe("You put openai-prod version 4 into GitHub acme/api, Actions secret OPENAI_API_KEY with gh-token, where it was new")
    expect(text(pushRow("push.done", { outcome: "set", via: null }))).toBe("An agent on mac-mini put openai-prod version 4 into GitHub acme/api, Actions secret OPENAI_API_KEY")
  })

  it("puts a provider's refusal in red with its status, and a push not sent with the vault's reason", () => {
    const failed = pushRow("push.failed", { providerStatus: 403 })
    expect(text(failed)).toBe("An agent on mac-mini tried to put openai-prod version 4 into GitHub acme/api, Actions secret OPENAI_API_KEY with gh-token. Refused by GitHub (403)")
    expect(failed.pieces).toContainEqual({ text: "Refused", as: "danger" })
    const notSent = pushRow("push.not_sent", { reason: "It waited too long to be sent; nothing was sent." }, "member:mem_alex0001")
    expect(text(notSent)).toBe("You asked to put openai-prod version 4 into GitHub acme/api, Actions secret OPENAI_API_KEY with gh-token. Not sent: It waited too long to be sent; nothing was sent.")
    expect(notSent.pieces).toContainEqual({ text: "Not sent", as: "danger" })
    expect(text(pushRow("push.unknown", {}))).toBe("An agent on mac-mini put openai-prod version 4 into GitHub acme/api, Actions secret OPENAI_API_KEY with gh-token, but Mehen could not confirm it. Check GitHub.")
  })

  it("never shows an id, and a private credential's minimal row names only the credential and how it went", () => {
    for (const action of ["push.done", "push.failed", "push.not_sent", "push.unknown"]) expect(JSON.stringify(pushRow(action, {})), action).not.toMatch(/itm_|apr_/)
    const minimal = auditLine({ actor: "member:mem_alex0001", action: "push.failed", target: "github-alex", detail: JSON.stringify({ action: "push.failed", at: 1, actor: { kind: "member", member: "mem_alex0001" }, session: null, item: "itm_githubalex01", slug: "github-alex", outcome: "refused:provider_refused", run: null }) }, words)
    expect(text(minimal)).toBe("You tried to put github-alex into another service's secret store. Refused")
    expect(JSON.stringify(minimal)).not.toContain("itm_")
  })

  it("names a credential deleted before its push was settled as a deleted credential, with no id and no link", () => {
    const notSent = auditLine({ actor: "system", action: "push.not_sent", target: "itm_x", detail: JSON.stringify({ item: "itm_x", destination: "github:acme/api/OPENAI_API_KEY", via: null, version: 4, reason: "It waited too long to be sent; nothing was sent." }) }, words)
    expect(JSON.stringify(notSent)).not.toContain("itm_")
    expect(JSON.stringify(notSent)).not.toContain("/items/")
    expect(notSent.link).toBeNull()
    expect(notSent.pieces).toContainEqual({ text: "a deleted credential" })
    expect(notSent.pieces.filter((p) => p.as === "code").map((p) => p.text)).toEqual(["GitHub acme/api, Actions secret OPENAI_API_KEY"])
  })
})
