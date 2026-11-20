import type { Template } from "../templates.ts"
import { BEARER, NAMED_READS, READS, WRITES } from "./shared.ts"

// Without a human: the named reads (the account, droplets, images,
// volumes, snapshots, domains, firewalls, load balancers, VPCs, projects,
// IPs, tags, Kubernetes clusters and node pools, metrics, billing and
// registry repositories). Every other read asks, and those that hand back
// a secret are pinned to an approval: database clusters, users, replicas,
// pools and log sinks (their connection details carry passwords and
// keys), kubeconfigs and cluster credentials, registry credentials, stored
// secrets and keys, Functions namespaces (each carries its key), App
// Platform apps (their specs carry environment values and registry
// credentials), GenAI, microVMs, monitoring sinks and notification
// channels. Creating droplets, clusters, apps and everything else needs an
// approval, and so does resetting a database user's password. Minting or
// changing SSH keys, Spaces, Functions, GenAI, inference and microVM keys
// and tokens, and log sinks that forward logs elsewhere, are refused.
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
      NAMED_READS(
        [
          "/v2/account",
          "/v2/actions/**",
          "/v2/droplets/**",
          "/v2/images/**",
          "/v2/regions",
          "/v2/sizes",
          "/v2/volumes/**",
          "/v2/snapshots/**",
          "/v2/domains/**",
          "/v2/firewalls/**",
          "/v2/load_balancers/**",
          "/v2/vpcs/**",
          "/v2/projects/**",
          "/v2/reserved_ips/**",
          "/v2/tags/**",
          "/v2/kubernetes/clusters",
          "/v2/kubernetes/clusters/*",
          "/v2/kubernetes/clusters/*/node_pools/**",
          "/v2/kubernetes/options",
          "/v2/monitoring/metrics/**",
          "/v2/customers/my/balance",
          "/v2/customers/my/billing_history",
          "/v2/customers/my/invoices/**",
          "/v2/registry",
          "/v2/registry/*/repositories/**",
          "/v2/registry/*/repositoriesV2",
        ],
        "reads of droplets, networking, Kubernetes clusters, projects, metrics, billing and registry repositories",
      ),
      {
        action: "approve",
        methods: READS,
        paths: [
          "/v2/databases",
          "/v2/databases/*",
          "/v2/databases/*/users/**",
          "/v2/databases/*/replicas/**",
          "/v2/databases/*/pools/**",
          "/v2/databases/*/logsink/**",
          "/v2/databases/metrics/credentials",
          "/v2/kubernetes/clusters/*/kubeconfig",
          "/v2/kubernetes/clusters/*/credentials",
          "/v2/registry/docker-credentials",
          "/v2/registries/*/docker-credentials",
          "/v2/vector-databases/*/credentials",
          "/v2/security/secrets/**",
          "/v2/spaces/keys/**",
          "/v2/functions/namespaces/**",
          "/v2/partner_network_connect/attachments/*/bgp_auth_key",
          "/v2/partner_network_connect/attachments/*/service_key",
          "/v2/action-gateway/**",
          "/v2/harness-runtime/**",
          "/v2/gen-ai/**",
          "/v2/microvms/**",
          "/v2/monitoring/sinks/**",
          "/v2/insights/notification-channels/**",
          "/v2/dedicated-inferences/*/tokens/**",
          "/v2/apps/**",
        ],
        note: "hands back a password, key, token, kubeconfig, app spec or console session",
      },
      { action: "approve", methods: ["POST"], paths: ["/v2/databases/*/users/*/reset_auth"], note: "resets a database user's password" },
      { action: "deny", methods: WRITES, paths: ["/v2/account/keys/**"], note: "SSH keys let someone sign in to new droplets" },
      {
        action: "deny",
        methods: WRITES,
        paths: [
          "/v2/spaces/keys/**",
          "/v2/functions/namespaces/*/keys/**",
          "/v2/dedicated-inferences/*/tokens/**",
          "/v2/microvms/*/access_tokens/**",
          "/v2/gen-ai/agents/*/api_keys/**",
          "/v2/gen-ai/models/api_keys/**",
          "/v2/gen-ai/anthropic/keys/**",
          "/v2/gen-ai/openai/keys/**",
        ],
        note: "mints or changes access keys and tokens",
      },
      { action: "deny", methods: WRITES, paths: ["/v2/monitoring/sinks/**", "/v2/databases/*/logsink/**"], note: "log sinks forward logs elsewhere" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "DIGITALOCEAN_ACCESS_TOKEN",
  check: { method: "GET", path: "/v2/account" },
  fields: { key: { label: "Personal access token", pattern: "^dop_v1_" } },
  prefixes: ["dop_v1_"],
}
