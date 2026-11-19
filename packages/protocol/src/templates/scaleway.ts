import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

// Scaleway takes the secret key in X-Auth-Token. Without a human: reads,
// except a Secret Manager secret's value, which needs an approval.
// Creating servers, clusters and anything else billed is pinned to an
// approval, as is everything else. IAM (API keys, users, applications,
// groups, policies and SSH keys) and deleting a project are refused.
// https://www.scaleway.com/en/developers/api/
export const scaleway: Template = {
  id: "scaleway",
  displayName: "Scaleway API key",
  kind: "api-key",
  category: "infrastructure",
  docsUrl: "https://console.scaleway.com/iam/api-keys",
  binding: { hosts: ["api.scaleway.com"] },
  injection: { in: "header", name: "X-Auth-Token", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "approve",
        paths: ["/secret-manager/*/regions/*/secrets/*/versions/*/access", "/secret-manager/*/regions/*/secrets-by-path/versions/*/access"],
        note: "reads a stored secret's value",
      },
      {
        action: "approve",
        methods: ["POST"],
        paths: ["/instance/*/zones/*/servers", "/baremetal/*/zones/*/servers", "/k8s/*/regions/*/clusters", "/rdb/*/regions/*/instances"],
        note: "creates something that is billed",
      },
      { action: "deny", methods: WRITES, paths: ["/iam/**"], note: "IAM: API keys, users, applications, groups, policies and SSH keys" },
      { action: "deny", methods: ["DELETE"], paths: ["/account/*/projects/*"], note: "deletes a project" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "Secret key", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" } },
  setup: {
    title: "In the Scaleway console",
    steps: [
      { title: "Open API keys", body: "IAM, then API keys. Create the key for an IAM application with only the permission sets the agent needs, not for your own user.", docs: true },
      { title: "Copy the secret key", body: "Scaleway shows the secret key once. The access key (SCW...) is not needed.", field: "key" },
    ],
  },
}
