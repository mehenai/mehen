import type { Template } from "../templates.ts"
import { NAMED_READS, READS, WRITES } from "./shared.ts"

// A PagerDuty REST API key, account-wide or a user's, sent as
// "Token token=<key>". The Events API takes a routing key in the body
// instead and is not bound. Without a human: the named reads (incidents
// and their log entries, notes and alerts, on-calls, schedules,
// escalation policies, teams, users, business services, maintenance
// windows, priorities and abilities). Services are not named: with
// include[]=integrations a service read returns integration keys, and a
// rule cannot read the query. Every other read asks, and those that return
// routing or integration keys are pinned to an approval: event
// orchestrations, rulesets, service integrations, automation runners,
// extensions and webhook subscriptions. Triggering,
// acknowledging and resolving incidents and everything else need an
// approval; creating an incident, its status updates and responder
// requests are pinned to one, since they page people. Users (their roles,
// contact methods and notification rules), team membership, webhooks and
// extensions, creating integrations or automation runners, and OAuth
// delegations are refused.
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
      NAMED_READS(
        [
          "/incidents",
          "/incidents/*",
          "/incidents/*/log_entries",
          "/incidents/*/notes",
          "/incidents/*/alerts",
          "/incidents/*/alerts/*",
          "/incidents/*/related_incidents",
          "/oncalls",
          "/schedules",
          "/schedules/*",
          "/schedules/*/users",
          "/escalation_policies",
          "/escalation_policies/*",
          "/teams",
          "/teams/*",
          "/teams/*/members",
          "/users",
          "/users/*",
          "/log_entries",
          "/log_entries/*",
          "/business_services",
          "/business_services/*",
          "/maintenance_windows/**",
          "/priorities",
          "/abilities/**",
        ],
        "reads of incidents, on-calls, schedules, escalation policies, teams and users",
      ),
      {
        action: "approve",
        methods: READS,
        paths: ["/event_orchestrations/**", "/rulesets/**", "/services/*/integrations/**", "/automation_actions/runners/**", "/extensions/**", "/webhook_subscriptions/**"],
        note: "orchestrations, rulesets, integrations, runners and webhooks hand back routing and integration keys",
      },
      { action: "approve", methods: ["POST"], paths: ["/incidents", "/incidents/*/status_updates", "/incidents/*/responder_requests"], note: "pages people or messages subscribers" },
      { action: "deny", methods: WRITES, paths: ["/users/**"], note: "users, their roles, contact methods and notification rules decide who gets paged" },
      { action: "deny", methods: WRITES, paths: ["/teams/*/users/**"], note: "team membership gives someone else access" },
      { action: "deny", methods: WRITES, paths: ["/webhook_subscriptions/**", "/extensions/**"], note: "webhooks and extensions send incidents elsewhere" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/services/*/integrations/**", "/event_orchestrations/*/integrations/**", "/automation_actions/runners/**"],
        note: "creates or changes an integration or automation runner, each of which carries a key",
      },
      { action: "deny", methods: WRITES, paths: ["/oauth_delegations/**"], note: "OAuth grants" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "PAGERDUTY_TOKEN",
  check: { method: "GET", path: "/abilities" },
  fields: { key: { label: "API key" } },
}
