import type { Template } from "../templates.ts"
import { BEARER, NAMED_READS, READS, WRITES } from "./shared.ts"

// Without a human: the named reads (services, deploys, events, jobs,
// instances, domains, routes and headers, owners and members, projects,
// environments, databases and key-value stores, disks, blueprints, logs
// and metrics). Every other read asks, and those that hand back a secret
// are pinned to an approval: environment variables, secret files,
// environment groups, connection details, webhooks (each carries its
// signing secret) and log and metrics streams. Deploys, scaling, services and everything
// else need an approval, and so does minting database credentials.
// Changing workspace members, webhooks, log and metrics streams (they send
// data elsewhere) and minting sandbox tokens are refused.
// https://api-docs.render.com/reference/introduction
export const render: Template = {
  id: "render",
  displayName: "Render API key",
  kind: "api-key",
  category: "code",
  docsUrl: "https://dashboard.render.com/u/settings#api-keys",
  binding: { hosts: ["api.render.com"], paths: ["/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      NAMED_READS(
        [
          "/v1/services",
          "/v1/services/*",
          "/v1/services/*/deploys/**",
          "/v1/services/*/events",
          "/v1/services/*/jobs/**",
          "/v1/services/*/instances",
          "/v1/services/*/custom-domains/**",
          "/v1/services/*/routes",
          "/v1/services/*/headers",
          "/v1/owners",
          "/v1/owners/*",
          "/v1/owners/*/members",
          "/v1/projects/**",
          "/v1/environments/**",
          "/v1/env-groups",
          "/v1/postgres",
          "/v1/postgres/*",
          "/v1/postgres/*/query/**",
          "/v1/redis",
          "/v1/redis/*",
          "/v1/key-value",
          "/v1/key-value/*",
          "/v1/disks/**",
          "/v1/blueprints/**",
          "/v1/events/*",
          "/v1/logs",
          "/v1/logs/values",
          "/v1/metrics/**",
          "/v1/users",
        ],
        "reads of services, deploys, projects, databases, logs and metrics",
      ),
      {
        action: "approve",
        methods: READS,
        paths: [
          "/v1/services/*/env-vars/**",
          "/v1/services/*/secret-files/**",
          "/v1/env-groups/*",
          "/v1/env-groups/*/env-vars/*",
          "/v1/env-groups/*/secret-files/*",
          "/v1/build-sources/*/env-vars/**",
          "/v1/build-sources/*/secret-files/**",
          "/v1/postgres/*/connection-info",
          "/v1/redis/*/connection-info",
          "/v1/key-value/*/connection-info",
          "/v1/sandbox-groups/*/credentials/**",
          "/v1/webhooks/**",
          "/v1/logs/streams/**",
          "/v1/metrics-stream/**",
        ],
        note: "environment variables, secret files, connection details, webhooks and streams hand back secrets",
      },
      { action: "approve", methods: WRITES, paths: ["/v1/postgres/*/credentials/**"], note: "mints or removes database credentials" },
      { action: "deny", methods: WRITES, paths: ["/v1/owners/*/members/**"], note: "changing members gives someone else access" },
      { action: "deny", methods: WRITES, paths: ["/v1/webhooks/**"], note: "webhooks send events elsewhere" },
      { action: "deny", methods: WRITES, paths: ["/v1/logs/streams/**", "/v1/metrics-stream/**"], note: "log and metrics streams send data elsewhere" },
      { action: "deny", methods: WRITES, paths: ["/v1/sandboxes/*/runs/*/token", "/v1/sandboxes/*/files/*/token"], note: "mints sandbox tokens" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "RENDER_API_KEY",
  check: { method: "GET", path: "/v1/owners" },
  fields: { key: { label: "API key", pattern: "^rnd_" } },
  prefixes: ["rnd_"],
}
