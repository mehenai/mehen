import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER } from "./shared.ts"

// Hetzner Cloud. Without a human: reads. Creating or resizing anything
// billed, and any route that hands out root access (a password reset,
// rescue mode, a rebuild, a console), are pinned to an approval, as is
// everything else. https://docs.hetzner.cloud/
export const hetznerCloud: Template = {
  id: "hetzner-cloud",
  displayName: "Hetzner Cloud API token",
  kind: "api-key",
  category: "infrastructure",
  docsUrl: "https://console.hetzner.cloud/projects",
  binding: { hosts: ["api.hetzner.cloud"], paths: ["/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "approve",
        methods: ["POST"],
        paths: ["/v1/servers", "/v1/volumes", "/v1/load_balancers", "/v1/primary_ips", "/v1/floating_ips", "/v1/servers/*/actions/change_type"],
        note: "creates or resizes something that is billed",
      },
      {
        action: "approve",
        methods: ["POST"],
        paths: ["/v1/servers/*/actions/reset_password", "/v1/servers/*/actions/enable_rescue", "/v1/servers/*/actions/rebuild", "/v1/servers/*/actions/request_console"],
        note: "hands out root access to a server",
      },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "HCLOUD_TOKEN",
  check: { method: "GET", path: "/v1/locations" },
  fields: { key: { label: "API token" } },
  setup: {
    title: "In the Hetzner Cloud console",
    steps: [
      { title: "Open the project", body: "A token belongs to one project: pick it in the console.", docs: true },
      { title: "Create a token", body: "Security, then API tokens, then Generate API token. Choose Read unless the agent is to change servers.", field: "key" },
    ],
  },
}
