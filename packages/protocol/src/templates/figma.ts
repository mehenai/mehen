import type { Template } from "../templates.ts"
import { NAMED_READS, READS, WRITES } from "./shared.ts"

// A Figma personal access token, in Figma's X-Figma-Token header.
// Without a human: the named reads (the user, files with their nodes,
// images, comments, versions, components, styles, variables and dev
// resources, team projects and their files, and published components and
// styles). Every other read asks, and webhooks and their request history
// are pinned to an approval, since a delivery may echo the webhook's
// passcode. Comments, variables, dev resources and everything else need an
// approval; webhook changes are refused.
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
      NAMED_READS(
        [
          "/v1/me",
          "/v1/files/*",
          "/v1/files/*/nodes",
          "/v1/files/*/images",
          "/v1/files/*/meta",
          "/v1/files/*/comments",
          "/v1/files/*/comments/*/reactions",
          "/v1/files/*/versions",
          "/v1/files/*/components",
          "/v1/files/*/component_sets",
          "/v1/files/*/styles",
          "/v1/files/*/variables/local",
          "/v1/files/*/variables/published",
          "/v1/files/*/dev_resources",
          "/v1/images/*",
          "/v1/teams/*/projects",
          "/v1/projects/*/files",
          "/v1/teams/*/components",
          "/v1/teams/*/component_sets",
          "/v1/teams/*/styles",
          "/v1/components/*",
          "/v1/component_sets/*",
          "/v1/styles/*",
        ],
        "reads of files, comments, components, styles, variables and team projects",
      ),
      { action: "approve", methods: READS, paths: ["/v2/webhooks/**", "/v2/teams/*/webhooks"], note: "webhooks and their request history may carry the passcode" },
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
