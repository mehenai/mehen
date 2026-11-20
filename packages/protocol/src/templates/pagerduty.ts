import type { Template } from "../templates.ts"
import { NAMED_READS, READS, WRITES } from "./shared.ts"

// A PagerDuty REST API key, account-wide or a user's, sent as
// "Token token=<key>". The Events API takes a routing key in the body
// instead and is not bound. Without a human: the named reads (on-calls,
// schedules, escalation policies, teams and their members, the user list,
// business services, maintenance windows, priorities and abilities), each
// checked against the OpenAPI for an include[] that expands a key: theirs
// expand only references. Every other read asks, and those that can return
// a key are pinned to an approval, since a rule cannot read the query
// string that asks for it: incidents and every incident sub-read (notes,
// alerts and related incidents ask too: an incident or its alerts with
// include[]=first_trigger_log_entries return a trigger log entry's
// service_key), a user's details (include[]=calendar_urls returns calendar
// feed URLs, which are bearer credentials), services (integration keys
// with include[]=integrations), log entries (a channel's service_key with
// include[]=channels), event orchestrations, rulesets, service
// integrations, automation runners, extensions and webhook subscriptions.
// Triggering, acknowledging and resolving incidents and everything else
// need an approval; creating an incident, its status updates and responder
// requests are pinned to one, since they page people. Users (their roles,
// contact methods and notification rules), team membership, webhooks and
// extensions, creating event orchestrations (each mints an integration
// with a routing key), integrations or automation runners, and OAuth
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
          "/business_services",
          "/business_services/*",
          "/maintenance_windows/**",
          "/priorities",
          "/abilities/**",
        ],
        "reads of on-calls, schedules, escalation policies, teams and users",
      ),
      {
        action: "approve",
        methods: READS,
        paths: [
          "/services",
          "/services/*",
          "/services/*/integrations/**",
          "/incidents/**",
          "/users/*",
          "/log_entries",
          "/log_entries/*",
          "/incidents/*/log_entries",
          "/event_orchestrations/**",
          "/rulesets/**",
          "/automation_actions/runners/**",
          "/extensions/**",
          "/webhook_subscriptions/**",
        ],
        note: "incidents, user details, services, log entries, orchestrations, rulesets, integrations, runners and webhooks can hand back routing, service and integration keys or bearer URLs",
      },
      { action: "approve", methods: ["POST"], paths: ["/incidents", "/incidents/*/status_updates", "/incidents/*/responder_requests"], note: "pages people or messages subscribers" },
      { action: "deny", methods: WRITES, paths: ["/users/**"], note: "users, their roles, contact methods and notification rules decide who gets paged" },
      { action: "deny", methods: WRITES, paths: ["/teams/*/users/**"], note: "team membership gives someone else access" },
      { action: "deny", methods: WRITES, paths: ["/webhook_subscriptions/**", "/extensions/**"], note: "webhooks and extensions send incidents elsewhere" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/event_orchestrations", "/services/*/integrations/**", "/event_orchestrations/*/integrations/**", "/automation_actions/runners/**"],
        note: "creates an event orchestration, or creates or changes an integration or automation runner, each of which carries a key",
      },
      { action: "deny", methods: WRITES, paths: ["/oauth_delegations/**"], note: "OAuth grants" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "PAGERDUTY_TOKEN",
  check: { method: "GET", path: "/abilities" },
  fields: { key: { label: "API key" } },
}
