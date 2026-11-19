import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, READS, WRITES } from "./shared.ts"

// Better Stack Uptime. Without a human: reads, except heartbeats, whose
// URL lets anyone holding it report a job as healthy or failed. Opening
// an incident, which pages whoever is on call, and posting a status
// report on a public status page are pinned to an approval, as is
// everything else.
// https://betterstack.com/docs/uptime/api/getting-started-with-uptime-api/
export const betterstackUptime: Template = {
  id: "betterstack-uptime",
  displayName: "Better Stack Uptime API token",
  kind: "api-key",
  category: "observability",
  docsUrl: "https://betterstack.com/docs/uptime/api/getting-started-with-uptime-api/",
  binding: { hosts: ["uptime.betterstack.com"], paths: ["/api/v2/**", "/api/v3/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "approve", methods: ["POST"], paths: ["/api/v2/incidents", "/api/v3/incidents"], note: "opens an incident, which pages whoever is on call" },
      { action: "approve", methods: WRITES, paths: ["/api/v2/status-pages/*/status-reports/**"], note: "posts on a public status page" },
      {
        action: "approve",
        methods: READS,
        paths: ["/api/v2/heartbeats/**", "/api/v3/heartbeats/**", "/api/v2/heartbeat-groups/*/*/**", "/api/v3/heartbeat-groups/*/*/**"],
        note: "heartbeats carry their URL, which lets anyone holding it report a job as healthy or failed",
      },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "API token" } },
  setup: {
    title: "In Better Stack",
    steps: [
      { title: "Find the API tokens", body: "In Better Stack, open Settings, then API tokens, in the team the agent works in. The guide explains where.", docs: true },
      { title: "Copy a team token", body: "Create a token of type Uptime API and copy it. Logs and Telemetry tokens are different and do not work here.", field: "key" },
    ],
  },
}
