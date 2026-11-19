import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, READS, WRITES } from "./shared.ts"

// Without a human: reads, except environment variables, secret files,
// environment groups and database connection details, which hand back
// secrets and need an approval. Deploys, scaling, services and everything
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
      ALLOW_READS,
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
        ],
        note: "environment variables, secret files and connection details hand back secrets",
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
