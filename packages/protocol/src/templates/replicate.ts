import type { Template } from "../templates.ts"
import { BEARER, MODEL_CALLS, NAMED_READS, READS, WRITES } from "./shared.ts"

// Without a human: the named reads (the account, models, versions,
// collections, hardware, predictions, trainings, deployments, files and
// search), predictions, cancelling one, and file uploads. A prediction whose
// body names a webhook (which receives the output) or cannot be read is
// pinned to an approval. Deployments and trainings are
// pinned to one because they are billed, and the webhook signing secret
// even to read. Every other read asks, and so does everything else.
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
      NAMED_READS(
        [
          "/v1/account",
          "/v1/models",
          "/v1/models/*/*",
          "/v1/models/*/*/examples",
          "/v1/models/*/*/readme",
          "/v1/models/*/*/versions/**",
          "/v1/collections/**",
          "/v1/hardware",
          "/v1/predictions/**",
          "/v1/trainings/**",
          "/v1/deployments/**",
          "/v1/files/**",
          "/v1/search",
        ],
        "reads of models, predictions, trainings, deployments and files",
      ),
      {
        action: "allow",
        methods: ["POST"],
        paths: ["/v1/predictions", "/v1/models/*/*/predictions", "/v1/deployments/*/*/predictions", "/v1/predictions/*/cancel", "/v1/files"],
        note: MODEL_CALLS,
      },
      {
        action: "approve",
        methods: ["POST"],
        paths: ["/v1/predictions", "/v1/models/*/*/predictions", "/v1/deployments/*/*/predictions"],
        body: "json-webhook",
        note: "names a webhook that receives the output, or cannot be read",
      },
      { action: "approve", methods: WRITES, paths: ["/v1/deployments", "/v1/deployments/*/*", "/v1/models/*/*/versions/*/trainings"], note: "starts billed hardware or a training" },
      { action: "approve", methods: READS, paths: ["/v1/webhooks/**"], note: "hands back the webhook signing secret" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "REPLICATE_API_TOKEN",
  check: { method: "GET", path: "/v1/account" },
  fields: { key: { label: "API token", pattern: "^r8_" } },
  prefixes: ["r8_"],
}
