import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

// A PagerDuty REST API key, account-wide or a user's, sent as
// "Token token=<key>". The Events API takes a routing key in the body
// instead and is not bound. Without a human: reads. Triggering,
// acknowledging and resolving incidents and everything else need an
// approval; creating an incident, its status updates and responder
// requests are pinned to one, since they page people. Users (their roles,
// contact methods and notification rules), team membership, webhooks and
// extensions, and OAuth delegations are refused.
// https://developer.pagerduty.com/api-reference/
export const pagerduty: Template = {
  id: "pagerduty",
  displayName: "PagerDuty REST API key",
  kind: "api-key",
  category: "observability",
  docsUrl: "https://support.pagerduty.com/main/docs/api-access-keys",
  binding: { hosts: ["api.pagerduty.com"] },
  injection: { in: "header", name: "Authorization", format: "Token token={key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "approve", methods: ["POST"], paths: ["/incidents", "/incidents/*/status_updates", "/incidents/*/responder_requests"], note: "pages people or messages subscribers" },
      { action: "deny", methods: WRITES, paths: ["/users/**"], note: "users, their roles, contact methods and notification rules decide who gets paged" },
      { action: "deny", methods: WRITES, paths: ["/teams/*/users/**"], note: "team membership gives someone else access" },
      { action: "deny", methods: WRITES, paths: ["/webhook_subscriptions/**", "/extensions/**"], note: "webhooks and extensions send incidents elsewhere" },
      { action: "deny", methods: WRITES, paths: ["/oauth_delegations/**"], note: "OAuth grants" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "PAGERDUTY_TOKEN",
  check: { method: "GET", path: "/abilities" },
  fields: { key: { label: "API key" } },
}
