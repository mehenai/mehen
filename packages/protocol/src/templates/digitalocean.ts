import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, READS, WRITES } from "./shared.ts"

// Without a human: reads, except those that hand back a secret: database
// clusters and users (their connection details carry passwords),
// kubeconfigs and cluster credentials, registry credentials, stored
// secrets and keys, and an App Platform console. Creating droplets,
// clusters, apps and everything else needs an approval, and so does
// resetting a database user's password. Minting or changing SSH keys,
// Spaces keys, Functions keys and access tokens, and log sinks that
// forward logs elsewhere, are refused.
// https://docs.digitalocean.com/reference/api/
export const digitalocean: Template = {
  id: "digitalocean",
  displayName: "DigitalOcean personal access token",
  kind: "api-key",
  category: "infrastructure",
  docsUrl: "https://cloud.digitalocean.com/account/api/tokens",
  binding: { hosts: ["api.digitalocean.com"], paths: ["/v2/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "approve",
        methods: READS,
        paths: [
          "/v2/databases",
          "/v2/databases/*",
          "/v2/databases/*/users/**",
          "/v2/databases/metrics/credentials",
          "/v2/kubernetes/clusters/*/kubeconfig",
          "/v2/kubernetes/clusters/*/credentials",
          "/v2/registry/docker-credentials",
          "/v2/registries/*/docker-credentials",
          "/v2/vector-databases/*/credentials",
          "/v2/security/secrets/**",
          "/v2/spaces/keys/**",
          "/v2/functions/namespaces/*/keys/**",
          "/v2/partner_network_connect/attachments/*/bgp_auth_key",
          "/v2/partner_network_connect/attachments/*/service_key",
          "/v2/action-gateway/provider-credentials/**",
          "/v2/apps/*/components/*/exec",
          "/v2/apps/*/deployments/*/components/*/exec",
        ],
        note: "hands back a password, key, kubeconfig or console session",
      },
      { action: "approve", methods: ["POST"], paths: ["/v2/databases/*/users/*/reset_auth"], note: "resets a database user's password" },
      { action: "deny", methods: WRITES, paths: ["/v2/account/keys/**"], note: "SSH keys let someone sign in to new droplets" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/v2/spaces/keys/**", "/v2/functions/namespaces/*/keys/**", "/v2/dedicated-inferences/*/tokens/**", "/v2/microvms/*/access_tokens/**"],
        note: "mints or changes access keys and tokens",
      },
      { action: "deny", methods: WRITES, paths: ["/v2/monitoring/sinks/**"], note: "log sinks forward logs elsewhere" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "DIGITALOCEAN_ACCESS_TOKEN",
  check: { method: "GET", path: "/v2/account" },
  fields: { key: { label: "Personal access token", pattern: "^dop_v1_" } },
  prefixes: ["dop_v1_"],
}
