import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

// A Figma personal access token, in Figma's X-Figma-Token header.
// Without a human: reads, file images and exports among them. Comments,
// variables, dev resources and everything else need an approval;
// webhooks are refused.
// https://developers.figma.com/docs/rest-api/
export const figma: Template = {
  id: "figma",
  displayName: "Figma personal access token",
  kind: "api-key",
  category: "productivity",
  docsUrl: "https://www.figma.com/settings",
  binding: { hosts: ["api.figma.com"] },
  injection: { in: "header", name: "X-Figma-Token", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "deny", methods: WRITES, paths: ["/v2/webhooks/**"], note: "webhooks send file and comment events elsewhere" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "FIGMA_ACCESS_TOKEN",
  check: { method: "GET", path: "/v1/me" },
  fields: { key: { label: "Personal access token", pattern: "^figd_" } },
  prefixes: ["figd_"],
  setup: {
    title: "In Figma",
    steps: [
      { title: "Open your settings", body: "Your account menu, then Settings, then Security, then Personal access tokens.", docs: true },
      { title: "Generate a token with read scopes", body: "Tick the read scopes the agent needs, such as File content read-only, and set an expiry.", field: "key" },
    ],
  },
}
