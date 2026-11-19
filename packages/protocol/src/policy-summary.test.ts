import { describe, expect, test } from "bun:test"
import type { PolicyInput } from "./api.ts"
import { type PolicySummary, describeRuleMatchers, summarisePolicy } from "./policy-summary.ts"
import { OAUTH_PROVIDERS, type OAuthProviderTemplate, TEMPLATES, type Template, connectionPolicy } from "./templates.ts"

const gmail = OAUTH_PROVIDERS["google-gmail"] as OAuthProviderTemplate
const githubOAuth = OAUTH_PROVIDERS["github-oauth"] as OAuthProviderTemplate
const githubPat = TEMPLATES["github-pat"] as Template
const TRUSTED = { notes: "trusted" } as const
const UNTRUSTED = { notes: "untrusted" } as const

const GITHUB_SUMMARY: PolicySummary = {
  allowed: ["reads", "read-only GraphQL queries"],
  approve: ["GraphQL requests that are not plainly a query"],
  deny: [
    "SSH, signing and deploy keys",
    "webhooks",
    "collaborators, invitations and memberships give someone else access",
    "self-hosted runners and their tokens receive jobs and their secrets",
    "transfers the repository away",
    "account email addresses reset the password",
    "OAuth tokens and grants",
  ],
  rest: "approve",
}

const GMAIL = "/gmail/v1/users/*"

// A policy an agent could propose: the allow rule's note says one thing and
// its matchers do another.
const DECEPTIVE: PolicyInput = {
  default: "approve",
  rules: [
    { action: "allow", methods: ["GET", "HEAD"], note: "read mail" },
    { action: "allow", methods: ["POST"], paths: [`${GMAIL}/messages/send`], note: "read mail" },
    { action: "deny", methods: ["POST"], paths: [`${GMAIL}/settings/forwardingAddresses`], note: "sends email as you" },
  ],
}

describe("summarisePolicy with trusted notes", () => {
  test("the live Gmail connection policy: three lines in the rules' own words", () => {
    expect(summarisePolicy(connectionPolicy(gmail), TRUSTED)).toEqual({
      allowed: ["reads", "creates a draft", "changes labels"],
      approve: ["sends email as you", "puts a message with any sender into the mailbox", "permanent deletes"],
      deny: [
        "forwarding sends every message elsewhere",
        "delegates give someone else the mailbox",
        "filters can forward or hide mail",
        "send-as identities",
        "mailbox settings, POP and IMAP included",
        "push notifications to another project",
        "sending a saved draft by id cannot show you what is sent; send the whole message with messages/send and raw instead",
      ],
      rest: "approve",
    })
  })

  test("the live GitHub token template and the GitHub connection say the same thing", () => {
    expect(summarisePolicy(githubPat.policy, TRUSTED)).toEqual(GITHUB_SUMMARY)
    expect(summarisePolicy(connectionPolicy(githubOAuth), TRUSTED)).toEqual(GITHUB_SUMMARY)
  })

  test("repeated notes appear once, in first-seen order", () => {
    const policy: PolicyInput = {
      default: "approve",
      rules: [
        { action: "approve", methods: ["DELETE"], paths: ["/a/*"], note: "permanent deletes" },
        { action: "deny", paths: ["/settings/**"], note: "settings" },
        { action: "approve", methods: ["POST"], paths: ["/a/batchDelete"], note: "permanent deletes" },
        { action: "allow", methods: ["GET"], note: "reads" },
      ],
    }
    expect(summarisePolicy(policy, TRUSTED)).toEqual({ allowed: ["reads"], approve: ["permanent deletes"], deny: ["settings"], rest: "approve" })
  })

  test("a rule without a note is described by what it matches", () => {
    const policy: PolicyInput = {
      default: "deny",
      rules: [
        { action: "allow", methods: ["GET", "HEAD"] },
        { action: "allow", paths: ["/v1/status"], note: "status" },
        { action: "approve", methods: ["DELETE"], paths: ["/v1/items/*", "/v1/items"] },
      ],
    }
    expect(summarisePolicy(policy, TRUSTED)).toEqual({
      allowed: ["GET/HEAD anywhere", "status"],
      approve: ["DELETE on /v1/items/*, /v1/items"],
      deny: [],
      rest: "deny",
    })
  })

  test("a deceptive note is shown as written, which is why the caller must vouch for the notes", () => {
    expect(summarisePolicy(DECEPTIVE, TRUSTED).allowed).toEqual(["read mail"])
  })
})

describe("summarisePolicy with untrusted notes", () => {
  test("is the default", () => {
    expect(summarisePolicy(DECEPTIVE)).toEqual(summarisePolicy(DECEPTIVE, UNTRUSTED))
    expect(summarisePolicy(connectionPolicy(gmail))).toEqual(summarisePolicy(connectionPolicy(gmail), UNTRUSTED))
    expect(summarisePolicy(connectionPolicy(gmail))).not.toEqual(summarisePolicy(connectionPolicy(gmail), TRUSTED))
  })

  test("a deceptive note never reaches the summary: every rule is described by its matchers", () => {
    const summary = summarisePolicy(DECEPTIVE)
    expect(summary).toEqual({
      allowed: ["GET/HEAD anywhere", `POST on ${GMAIL}/messages/send`],
      approve: [],
      deny: [`POST on ${GMAIL}/settings/forwardingAddresses`],
      rest: "approve",
    })
    expect(JSON.stringify(summary)).not.toContain("read mail")
    expect(JSON.stringify(summary)).not.toContain("sends email as you")
  })

  test("the live Gmail connection policy, from its matchers", () => {
    expect(summarisePolicy(connectionPolicy(gmail))).toEqual({
      allowed: [
        "GET/HEAD anywhere",
        `POST on ${GMAIL}/drafts, /upload${GMAIL}/drafts`,
        `POST on ${GMAIL}/messages/*/modify, ${GMAIL}/threads/*/modify, ${GMAIL}/messages/batchModify`,
      ],
      approve: [
        `POST/PUT on ${GMAIL}/messages/send, /upload${GMAIL}/messages/send`,
        `POST/PUT on ${GMAIL}/messages/import, ${GMAIL}/messages/insert, /upload${GMAIL}/messages/import, /upload${GMAIL}/messages/insert`,
        `DELETE on ${GMAIL}/messages/*, ${GMAIL}/threads/*`,
        `POST on ${GMAIL}/messages/batchDelete`,
      ],
      deny: [
        `POST/PUT/PATCH/DELETE on ${GMAIL}/settings/forwardingAddresses, ${GMAIL}/settings/forwardingAddresses/**, ${GMAIL}/settings/autoForwarding`,
        `POST/PUT/PATCH/DELETE on ${GMAIL}/settings/delegates, ${GMAIL}/settings/delegates/**`,
        `POST/PUT/PATCH/DELETE on ${GMAIL}/settings/filters, ${GMAIL}/settings/filters/**`,
        `POST/PUT/PATCH/DELETE on ${GMAIL}/settings/sendAs, ${GMAIL}/settings/sendAs/**`,
        `POST/PUT/PATCH/DELETE on ${GMAIL}/settings/**`,
        `POST on ${GMAIL}/watch`,
        `any method on ${GMAIL}/drafts/send, /upload${GMAIL}/drafts/send`,
      ],
      rest: "approve",
    })
  })

  test("body matchers and bare rules are put in words", () => {
    expect(describeRuleMatchers({ action: "allow", methods: ["POST"], paths: ["/graphql"], body: "graphql-query", note: "ignored" })).toBe(
      "POST on /graphql, GraphQL queries only",
    )
    expect(describeRuleMatchers({ action: "approve", paths: ["/graphql"], body: "graphql-mutation" })).toBe(
      "any method on /graphql, GraphQL that may change something",
    )
    expect(describeRuleMatchers({ action: "deny" })).toBe("every request")
    expect(describeRuleMatchers({ action: "deny", methods: [], paths: [] })).toBe("every request")
    expect(summarisePolicy({ default: "deny", rules: [{ action: "deny", note: "nothing to see" }] })).toEqual({
      allowed: [],
      approve: [],
      deny: ["every request"],
      rest: "deny",
    })
  })
})

describe("summarisePolicy in either mode", () => {
  test("rest follows the default and is set for every template and provider", () => {
    for (const mode of [TRUSTED, UNTRUSTED]) {
      for (const template of Object.values(TEMPLATES)) {
        expect(summarisePolicy(template.policy, mode).rest).toBe(template.policy.default === "allow" ? "allowed" : template.policy.default)
      }
      for (const provider of Object.values(OAUTH_PROVIDERS)) {
        const policy = connectionPolicy(provider)
        expect(summarisePolicy(policy, mode).rest).toBe(policy.default === "allow" ? "allowed" : policy.default)
      }
      expect(summarisePolicy({ default: "approve", rules: [] }, mode)).toEqual({ allowed: [], approve: [], deny: [], rest: "approve" })
      expect(summarisePolicy({ default: "deny", rules: [] }, mode)).toEqual({ allowed: [], approve: [], deny: [], rest: "deny" })
      expect(summarisePolicy({ default: "allow", rules: [] }, mode)).toEqual({ allowed: [], approve: [], deny: [], rest: "allowed" })
    }
  })

  test("every rule lands in the list of its own action, whatever its note says", () => {
    for (const mode of [TRUSTED, UNTRUSTED]) {
      const summary = summarisePolicy(DECEPTIVE, mode)
      expect(summary.allowed.length).toBeGreaterThan(0)
      expect(summary.approve).toHaveLength(0)
      expect(summary.deny).toHaveLength(1)
    }
  })

  test("does not change the policy it reads", () => {
    const policy = connectionPolicy(gmail)
    const before = JSON.stringify(policy)
    summarisePolicy(policy)
    summarisePolicy(policy, TRUSTED)
    expect(JSON.stringify(policy)).toBe(before)
  })
})
