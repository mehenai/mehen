// The browser's workspace logic (client/workspace-logic.ts) against the vault's own functions: the
// action the page expects back is byte for byte the one the vault builds,
// so a page signs only what it showed; and every check that refuses before
// a passkey refuses with nothing sent.

import { describe, expect, it } from "vitest"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import type { ApprovalSubject } from "@mehen/protocol/api"
import { approvalBinding } from "../vault/areas/approvals-workspace.ts"
import { stepUpDigest } from "../vault/areas/items.ts"
import { workspaceEnvironmentDigest, workspaceVarDigest } from "../vault/areas/projects-workspace.ts"
import { CHANGED_SINCE_SHOWN, type ReviewRowBoot, approvalBindingMatches, reviewBatchBody, reviewBatchMatches, reviewBindingMismatches, reviewChoices, approvalDecision, chosenConstraints, createdAskPath, credentialStart, environmentChange, itemChangedRefusal, itemDeleteAction, itemRehomeAction, itemRestoreAction, itemRestoreRefusal, itemUpdateAction, webPageOrigin, webPagesChange, overrideChange, overrideOffered, purgeMatches, homeFromValue, homeInput, identityRefusal, intakeWithHome, nameRefusalWords, projectCreate, remoteChange, rotationStart, ruleOutcomeWords, sameAction, shareChange, variableChange } from "./client/workspace-logic.ts"
import { RULE_COSIGN_ASKED_WORDS, RULE_NOT_NAMED_WORDS, ruleAllowedWords } from "./wording.ts"

describe("expected actions equal the vault's", () => {
  it("environment changes sign the vault's environment digest, fences in the order shown", async () => {
    const before = { protected: true, fences: [], fourEyes: false }
    const after = { protected: true, fences: ["b.example", "a.example"], fourEyes: true }
    const change = environmentChange("prj_a", "prod", before, after)
    expect(await change.expected).toEqual({ type: "item.update", item: "prj_a", digest: workspaceEnvironmentDigest({ project: "prj_a", env: "prod", before, ...after }) })
    expect(change.path).toBe("/projects/prj_a/environments/prod")
  })

  it("variable changes sign the vault's variable digest for a credential, a plain value and unset", async () => {
    const credential = variableChange("prj_a", "prod", "TOKEN", null, { kind: "item", item: "prod-key", field: "key" })
    expect(credential.input).toEqual({ project: "prj_a", env: "prod", name: "TOKEN", before: null, item: "prod-key", field: "key" })
    expect(await credential.expected).toEqual({ type: "item.update", item: "prj_a", digest: workspaceVarDigest({ project: "prj_a", env: "prod", name: "TOKEN", before: null, item: "prod-key", field: "key" }) })
    const noField = variableChange("prj_a", "dev", "TOKEN", null, { kind: "item", item: "prod-key", field: "" })
    expect(await noField.expected).toEqual({ type: "item.update", item: "prj_a", digest: workspaceVarDigest({ project: "prj_a", env: "dev", name: "TOKEN", before: null, item: "prod-key" }) })
    const plain = variableChange("prj_a", "dev", "LOG_LEVEL", null, { kind: "plain", value: "info" })
    expect(await plain.expected).toEqual({ type: "item.update", item: "prj_a", digest: workspaceVarDigest({ project: "prj_a", env: "dev", name: "LOG_LEVEL", before: null, plain: "info" }) })
    const unset = variableChange("prj_a", "dev", "TOKEN", { kind: "item", item: "prod-key", field: "key" }, null)
    expect(await unset.expected).toEqual({ type: "item.update", item: "prj_a", digest: workspaceVarDigest({ project: "prj_a", env: "dev", name: "TOKEN", before: { kind: "item", item: "prod-key", field: "key" } }) })
  })

  it("shares, remotes, creation and deletion name exactly what the page showed", async () => {
    const after = { level: "use" as const, protected: true, expiresAt: null }
    expect(shareChange("prj_a", { kind: "member", member: "mem_t" }, null, after).expected).toEqual({ type: "project.share", project: "prj_a", subject: { kind: "member", member: "mem_t" }, before: null, after })
    const remote = remoteChange("prj_a", "git@github.com:Owner/Repo.git", true)
    expect(remote?.input).toEqual({ project: "prj_a", remote: "github.com/owner/repo", bound: true })
    expect(remoteChange("prj_a", "not a remote", true)).toBeNull()
    const created = projectCreate("platform", "", [{ name: "dev", protected: false, fourEyes: false }, { name: "prod", protected: true, fourEyes: true }], "dev")
    expect(created.ok && created.value.expected).toEqual({ type: "project.create", slug: "platform", remote: null, environments: [{ name: "dev", protected: false, fourEyes: false }, { name: "prod", protected: true, fourEyes: true }] })
    expect(projectCreate("Not A Slug", "", [], "dev")).toEqual({ ok: false, problems: ["Name the project with lowercase letters, digits and dashes."] })
  })

  it("an intake signs its home with the submission, as the vault rebuilds it", async () => {
    const submission = { slug: "openai-dev", binding: { hosts: ["api.openai.com"] }, publicFields: {}, sealed: { key: { v: 1 } }, tags: ["b", "a"] }
    const home = { kind: "project" as const, project: "prj_a" }
    const { body, digest } = await intakeWithHome(submission, home)
    expect(body).toEqual({ ...submission, home })
    expect(digest).toBe(await stepUpDigest({ ...submission, home, tags: ["a", "b"] }))
  })
})

describe("checks before signing", () => {
  it("a changed action is not the shown one", () => {
    const shown = { type: "project.share" as const, project: "prj_a", subject: { kind: "member" as const, member: "mem_t1" }, before: null, after: { level: "use" as const, protected: false, expiresAt: null } }
    expect(sameAction(shown, JSON.parse(canonicalJson(shown)))).toBe(true)
    // Another Tom: same name, another member id.
    expect(sameAction(shown, { ...shown, subject: { kind: "member", member: "mem_t2" } })).toBe(false)
    expect(sameAction(shown, { ...shown, after: { level: "edit", protected: false, expiresAt: null } })).toBe(false)
  })

  it("a renamed or swapped workspace refuses before the passkey", () => {
    const shown = { id: "tn_a", slug: "northwind", name: "Northwind" }
    expect(identityRefusal(shown, shown)).toBeNull()
    expect(identityRefusal(shown, { ...shown, name: "Northwind Labs" })?.message).toBe("This workspace was renamed to Northwind Labs (northwind) since the page loaded.")
    expect(identityRefusal(shown, { ...shown, slug: "northwind-labs" })?.error).toBe("conflict")
    expect(identityRefusal(shown, { ...shown, id: "tn_b" })?.message).toBe("This address now belongs to a different workspace than the one this page showed.")
  })

  it("item actions name the shown credential's stable id; a replacement or a changed revision refuses", () => {
    const shown = { id: "itm_1", kind: "api-key", version: 3, configRevision: 2, dependencyRevision: 1 }
    const before = { kind: "workspace" as const }
    const after = { kind: "project" as const, project: "prj_a" }
    expect(itemDeleteAction(shown)).toEqual({ type: "item.delete", item: "itm_1" })
    expect(sameAction(itemDeleteAction(shown), { type: "item.delete", item: "itm_REPLACEMENT" })).toBe(false)
    const rehome = itemRehomeAction(shown, before, after)
    expect(rehome).toEqual({ type: "item.rehome", item: "itm_1", before, after, dependencyRevision: 1 })
    expect(sameAction(rehome, { ...rehome, item: "itm_REPLACEMENT" })).toBe(false)
    expect(sameAction(rehome, { ...rehome, dependencyRevision: 999 })).toBe(false)
    expect(itemChangedRefusal(shown, shown)).toBeNull()
    expect(itemChangedRefusal(shown, { ...shown, id: "itm_2" })?.message).toBe("This name now belongs to a different credential than the one this page showed.")
    expect(itemChangedRefusal(shown, { ...shown, configRevision: 3 })?.error).toBe("conflict")
    expect(itemChangedRefusal(shown, { ...shown, version: 4 })?.error).toBe("conflict")
    // The vault renews a connection's token on its own: that is not a change.
    const connection = { ...shown, kind: "oauth-connection" }
    expect(itemChangedRefusal(connection, { ...connection, version: 4 })).toBeNull()
    expect(itemChangedRefusal(connection, { ...connection, version: 4, configRevision: 3 })?.error).toBe("conflict")
    expect(itemRestoreRefusal(connection, 2, { ...connection, version: 4, previous: { version: 2 } })).toEqual(CHANGED_SINCE_SHOWN)
  })

  it("a restore signs the shown credential's id, its version and the kept version, and refuses once either moved", async () => {
    const shown = { id: "itm_1", kind: "api-key", version: 3, configRevision: 2, dependencyRevision: 1 }
    const restore = await itemRestoreAction(shown, 2)
    expect(restore).toEqual({ type: "item.restore", item: "itm_1", digest: await stepUpDigest({ item: "itm_1", version: 3, previous: 2 }) })
    expect(sameAction(restore, await itemRestoreAction({ ...shown, version: 4 }, 2))).toBe(false)
    expect(sameAction(restore, await itemRestoreAction(shown, 1))).toBe(false)
    expect(itemRestoreRefusal(shown, 2, { ...shown, previous: { version: 2 } })).toBeNull()
    expect(itemRestoreRefusal(shown, 2, { ...shown, previous: { version: 3 } })).toEqual(CHANGED_SINCE_SHOWN)
    expect(itemRestoreRefusal(shown, 2, { ...shown, previous: null })).toEqual(CHANGED_SINCE_SHOWN)
    expect(itemRestoreRefusal(shown, 2, { ...shown, version: 4, previous: { version: 2 } })).toEqual(CHANGED_SINCE_SHOWN)
  })

  it("the purge accepts only a bare delete, so nothing about the credential travels with it", () => {
    expect(purgeMatches({ type: "item.delete", item: "itm_1" })).toBe(true)
    expect(purgeMatches({ type: "item.delete", item: "itm_1", slug: "github-kim" })).toBe(false)
    expect(purgeMatches({ type: "item.rehome", item: "itm_1" })).toBe(false)
  })
})

describe("personal overrides", () => {
  const project = { environments: [{ name: "dev", protected: false }, { name: "prod", protected: true }], vars: [{ env: "prod", name: "GITHUB_TOKEN" }, { env: "dev", name: "OPENAI_API_KEY" }] }

  it("Use my own is offered only where that exact environment has the variable, never protected", () => {
    expect(overrideOffered(project, "dev", "OPENAI_API_KEY")).toBe(true)
    // Declared in prod only: dev has no row, so no control there.
    expect(overrideOffered(project, "dev", "GITHUB_TOKEN")).toBe(false)
    expect(overrideOffered(project, "prod", "GITHUB_TOKEN")).toBe(false)
    expect(overrideOffered(project, "staging", "OPENAI_API_KEY")).toBe(false)
  })

  it("the vault's override action must match every part the page shows", () => {
    const change = overrideChange("prj_a", "dev", "OPENAI_API_KEY", { kind: "item", item: "github-alex", field: "key" })
    expect(change.body).toEqual({ environment: "dev", variable: "OPENAI_API_KEY", source: { kind: "item", item: "github-alex", field: "key" } })
    expect(change.matches({ type: "override.set", project: "prj_a", environment: "dev", variable: "OPENAI_API_KEY", source: { kind: "item", item: "itm_stable", field: "key" } })).toBe(true)
    expect(change.matches({ type: "override.set", project: "prj_a", environment: "staging", variable: "OPENAI_API_KEY", source: { kind: "item", item: "itm_stable", field: "key" } })).toBe(false)
    expect(change.matches({ type: "override.set", project: "prj_a", environment: "dev", variable: "OPENAI_API_KEY", source: { kind: "item", item: "itm_stable", field: "secret" } })).toBe(false)
    const plain = overrideChange("prj_a", "dev", "LOG_LEVEL", { kind: "plain", value: "debug" })
    expect(plain.matches({ type: "override.set", project: "prj_a", environment: "dev", variable: "LOG_LEVEL", source: { kind: "plain", value: "info" } })).toBe(false)
    expect(overrideChange("prj_a", "dev", "LOG_LEVEL", null).matches({ type: "override.set", project: "prj_a", environment: "dev", variable: "LOG_LEVEL", source: null })).toBe(true)
  })
})

describe("homes and names", () => {
  it("home values and bodies", () => {
    expect(homeFromValue("member", "mem_m")).toEqual({ kind: "member", member: "mem_m" })
    expect(homeFromValue("project:prj_a", "mem_m")).toEqual({ kind: "project", project: "prj_a" })
    expect(homeFromValue("project:", "mem_m")).toBeNull()
    expect(homeInput({ kind: "member", member: "mem_m" })).toEqual({ home: "private" })
    expect(credentialStart("openai", "intake", "openai-dev", { kind: "workspace" })).toEqual({ path: "/intakes", body: { provider: "openai", slug: "openai-dev", home: "workspace" } })
    expect(credentialStart("google-gmail", "connect", "gmail-alex", { kind: "project", project: "prj_a" })).toEqual({ path: "/connect", body: { provider: "google-gmail", slug: "gmail-alex", requestClient: true, home: "project", project: "prj_a" } })
    expect(rotationStart("openai-dev", { kind: "workspace" })).toEqual({ path: "/intakes", body: { slug: "openai-dev", home: "workspace" } })
    expect(rotationStart("gmail-alex", { kind: "member", member: "mem_m" }, "google-gmail")).toEqual({ path: "/connect", body: { provider: "google-gmail", slug: "gmail-alex", home: "private" } })
    expect(createdAskPath("northwind", { intake: "int_1" })).toBe("/w/northwind/i/int_1")
    expect(createdAskPath("northwind", { connect: "con_1", intake: { intake: "int_2" } })).toBe("/w/northwind/i/int_2")
    expect(createdAskPath("northwind", { connect: "con_1" })).toBe("/w/northwind/c/con_1")
  })

  it("the uniform name refusal and its rate limit read the same for every name", () => {
    expect(nameRefusalWords({ error: "conflict", message: "name not available" })).toBe("That name is not available. Choose another; for a credential only you use, try adding your own name, as in openai-alex.")
    expect(nameRefusalWords({ error: "rate_limited", message: "Too many unavailable names; try again later." })).toBe("Too many names were not available this hour. Try again later.")
    expect(nameRefusalWords({ error: "conflict", message: "The expected state changed." })).toBeNull()
  })
})

describe("approvals", () => {
  const subject: ApprovalSubject = { item: "platform", method: "RUN", url: "https://vault.test/w/northwind/projects/prj_a", contentType: null, contentEncoding: null, headersSha256: "h", bodySha256: "b", constraints: { uses: 5, ttlSeconds: 3600 } }
  const presentation = { title: "Run platform in prod", details: [], body: null }

  it("recomputes the vault's binding digest from the subject and binding", async () => {
    const binding = approvalBinding(subject, presentation, { snapshot: 1 })
    const boot = { approval: "apr_1", digest: binding.digest, subject, binding: { snapshotDigest: binding.snapshotDigest, presentationDigest: binding.presentationDigest }, headers: null }
    expect(await approvalBindingMatches(boot)).toBe(true)
    expect(await approvalBindingMatches({ ...boot, subject: { ...subject, url: "https://vault.test/w/northwind/projects/prj_b" } })).toBe(false)
    expect(await approvalBindingMatches({ ...boot, binding: null })).toBe(false)
  })

  it("never chooses more uses or time than the agent asked for", () => {
    expect(chosenConstraints(subject.constraints, "5", "3600")).toEqual({ ok: true, value: { uses: 5, ttlSeconds: 3600 } })
    expect(chosenConstraints(subject.constraints, "6", "600").ok).toBe(false)
    expect(chosenConstraints(subject.constraints, "unlimited", "600").ok).toBe(false)
    expect(chosenConstraints(subject.constraints, "1", "3601").ok).toBe(false)
    expect(chosenConstraints({ uses: null, ttlSeconds: 600 }, "unlimited", "600")).toEqual({ ok: true, value: { uses: null, ttlSeconds: 600 } })
  })

  it("a denial signs the asked terms; an approval the chosen ones", () => {
    const boot = { approval: "apr_1", digest: "d", subject }
    expect(approvalDecision(boot, "deny", { uses: 1, ttlSeconds: 60 }).expected).toEqual({ type: "approval.decide", approval: "apr_1", digest: "d", decision: "deny", constraints: subject.constraints })
    expect(approvalDecision(boot, "approve", { uses: 1, ttlSeconds: 60 }).body).toEqual({ decision: "approve", constraints: { uses: 1, ttlSeconds: 60 } })
  })

  it("says what a remember made only from the vault's answer: the rule's own end, the co-sign, or no Allowed at all", () => {
    const answer = (approval: Record<string, unknown>) => ({ view: "detail", approval: { approval: "apr_1", status: "approved", ...approval } })
    expect(ruleOutcomeWords(answer({ rule: { id: "rul_1", endsAt: "2026-10-30T09:15:00.000Z" }, ruleProposal: null }))).toBe(ruleAllowedWords(Date.parse("2026-10-30T09:15:00.000Z")))
    expect(ruleOutcomeWords(answer({ rule: null, ruleProposal: { id: "pol_1", url: "u", bindingCode: "C", expiresAt: "2026-10-28T09:15:00.000Z" } }))).toBe(RULE_COSIGN_ASKED_WORDS)
    expect(ruleOutcomeWords(answer({}))).toBe(RULE_NOT_NAMED_WORDS)
    expect(ruleOutcomeWords(answer({ rule: { id: "rul_1", endsAt: "not a time" } }))).toBe(RULE_NOT_NAMED_WORDS)
    for (const other of [answer({ status: "pending", rule: { id: "rul_1", endsAt: "2026-10-30T09:15:00.000Z" } }), { status: "approved" }, { view: "stop" }, null, "approved"]) expect(ruleOutcomeWords(other)).toBeNull()
  })
})

describe("Review together", () => {
  const subject = (path: string, uses: number | null = 1): ApprovalSubject => ({ item: "cloudflare", method: "POST", url: `https://api.cloudflare.com${path}`, contentType: null, contentEncoding: null, headersSha256: "h", bodySha256: "b", constraints: { uses, ttlSeconds: 600 } })
  const row = (approval: string, section: ReviewRowBoot["section"], path = `/v1/${approval}`, pending = true): ReviewRowBoot => {
    const asked = subject(path)
    const binding = approvalBinding(asked, { title: approval, details: [], body: null }, { snapshot: approval })
    return { approval, view: "detail", section, pending, newer: false, digest: binding.digest, subject: asked, binding: { snapshotDigest: binding.snapshotDigest, presentationDigest: binding.presentationDigest }, headers: null }
  }
  const rows: ReviewRowBoot[] = [row("apr_c", "routine"), row("apr_a", "floor"), row("apr_b", "deny-only"), row("apr_d", "own-page"), { approval: "apr_e", view: "stop", section: "deny-only", pending: true }, row("apr_f", "routine", "/v1/f", false)]
  const all = new Set(rows.map((r) => r.approval))
  // The vault's approval.decide_many: each entry from storage, sorted by approval id.
  const vaultAction = (choices: { approval: string; decision: "approve" | "deny" }[]) => ({ type: "approval.decide_many", entries: choices.map((c) => { const r = rows.find((x) => x.approval === c.approval)!; return r.view === "detail" ? { approval: r.approval, digest: r.digest, decision: c.decision, uses: r.subject.constraints.uses, ttlSeconds: r.subject.constraints.ttlSeconds } : { approval: r.approval, digest: "stored", decision: c.decision, uses: 1, ttlSeconds: 600 } }) })

  it("builds the entries from the ticked rows: Approve leaves out deny-only, own-page and settled rows; Deny leaves out own-page and settled ones; each once, sorted", () => {
    expect(reviewChoices(rows, all, "approve")).toEqual([{ approval: "apr_a", decision: "approve" }, { approval: "apr_c", decision: "approve" }])
    expect(reviewChoices(rows, all, "deny").map((c) => c.approval)).toEqual(["apr_a", "apr_b", "apr_c", "apr_e"])
    expect(reviewChoices(rows, new Set(["apr_c"]), "approve")).toEqual([{ approval: "apr_c", decision: "approve" }])
    expect(reviewBatchBody(reviewChoices(rows, new Set(["apr_c", "apr_a"]), "deny"))).toEqual({ entries: [{ id: "apr_a", decision: "deny" }, { id: "apr_c", decision: "deny" }] })
  })

  it("accepts the vault's action only when every entry is its row's own digest, decision and asked terms, in order", () => {
    const choices = reviewChoices(rows, all, "approve")
    const action = vaultAction(choices)
    expect(reviewBatchMatches(rows, choices, action)).toBe(true)
    expect(reviewBatchMatches(rows, choices, { ...action, entries: [...action.entries].reverse() })).toBe(false)
    expect(reviewBatchMatches(rows, choices, { ...action, entries: action.entries.slice(1) })).toBe(false)
    expect(reviewBatchMatches(rows, choices, { ...action, entries: [...action.entries, { ...action.entries[0]!, approval: "apr_z" }] })).toBe(false)
    for (const change of [{ digest: "other" }, { decision: "deny" }, { uses: 2 }, { ttlSeconds: 86_400 }, { remember: {} }]) expect(reviewBatchMatches(rows, choices, { ...action, entries: [{ ...action.entries[0]!, ...change }, action.entries[1]!] }), JSON.stringify(change)).toBe(false)
    expect(reviewBatchMatches(rows, choices, { ...action, type: "approval.decide" })).toBe(false)
    expect(reviewBatchMatches(rows, choices, { ...action, extra: true })).toBe(false)
    // A stop row shows no request: its entry may only deny it.
    const denial = reviewChoices(rows, new Set(["apr_e"]), "deny")
    expect(reviewBatchMatches(rows, denial, vaultAction(denial))).toBe(true)
    expect(reviewBatchMatches(rows, [{ approval: "apr_e", decision: "approve" }], vaultAction([{ approval: "apr_e", decision: "approve" }]))).toBe(false)
  })

  it("names every row whose shown request does not recompute to the vault's digest", async () => {
    expect(await reviewBindingMismatches(rows)).toEqual([])
    const tampered = rows.map((r) => r.approval === "apr_c" && r.view === "detail" ? { ...r, subject: subject("/v1/elsewhere") } : r)
    expect(await reviewBindingMismatches(tampered)).toEqual(["apr_c"])
  })
})

describe("the In web pages card's change", () => {
  const shown = { ceiling: "fill", signinOrigins: ["https://gist.github.com"], typeInto: [] }

  it("is nothing when nothing changed, and only what changed otherwise", () => {
    expect(webPagesChange(shown, { ...shown })).toBeNull()
    expect(webPagesChange(shown, { ...shown, ceiling: "relay" })).toEqual({ ceiling: "relay" })
    expect(webPagesChange(shown, { ...shown, typeInto: ["https://dash.example.net"] })).toEqual({ browser: { signinOrigins: ["https://gist.github.com"], typeInto: ["https://dash.example.net"] } })
    expect(webPagesChange(shown, { ceiling: "relay", signinOrigins: [], typeInto: [] })).toEqual({ ceiling: "relay", browser: null })
  })

  it("never sends a ceiling other than relay or fill", () => {
    expect(webPagesChange(shown, { ...shown, ceiling: "lease" })).toBeNull()
  })

  it("keeps a typed page as its https origin, and nothing else", () => {
    expect(webPageOrigin("  https://Login.Example.com/session?next=/ ")).toBe("https://login.example.com")
    for (const typed of ["http://login.example.com", "https://10.0.0.1", "https://alex@login.example.com", "login.example.com", ""]) expect(webPageOrigin(typed)).toBeNull()
  })

  it("signs the digest item.update rebuilds from the change, the version and the configuration shown", async () => {
    const item = { id: "itm_githublogin", kind: "password-login", version: 3, configRevision: 2 }
    const change = { ceiling: "relay", browser: null }
    expect(await itemUpdateAction(item, change)).toEqual({ type: "item.update", item: item.id, digest: await stepUpDigest({ change, version: 3, configRevision: 2 }) })
    // An OAuth connection's renewals do not move what its settings pin.
    expect(await itemUpdateAction({ ...item, kind: "oauth-connection" }, change)).toEqual(await itemUpdateAction({ ...item, kind: "oauth-connection", version: 9 }, change))
  })
})
