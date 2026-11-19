import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, MODEL_CALLS, WRITES } from "./shared.ts"

// Without a human: reads, predictions (on a model, a version or a
// deployment), cancelling one, and file uploads. Deployments and
// trainings are pinned to an approval because they are billed, and the
// webhook signing secret needs an approval even to read. Model, deployment
// and file changes and everything else need an approval.
// https://replicate.com/docs/reference/http
export const replicate: Template = {
  id: "replicate",
  displayName: "Replicate API token",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://replicate.com/account/api-tokens",
  binding: { hosts: ["api.replicate.com"], paths: ["/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: ["/v1/predictions", "/v1/predictions/*/cancel", "/v1/models/*/*/predictions", "/v1/deployments/*/*/predictions", "/v1/files"],
        note: MODEL_CALLS,
      },
      { action: "approve", methods: WRITES, paths: ["/v1/deployments", "/v1/deployments/*/*", "/v1/models/*/*/versions/*/trainings"], note: "starts billed hardware or a training" },
      { action: "approve", paths: ["/v1/webhooks/default/secret"], note: "hands back the webhook signing secret" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "REPLICATE_API_TOKEN",
  check: { method: "GET", path: "/v1/account" },
  fields: { key: { label: "API token", pattern: "^r8_" } },
  prefixes: ["r8_"],
}
