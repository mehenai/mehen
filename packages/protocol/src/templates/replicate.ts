import type { Template } from "../templates.ts"
import { BEARER, NAMED_READS, READS, WRITES } from "./shared.ts"

// Without a human: the named reads (the account, models, versions,
// collections, hardware, predictions, trainings, deployments, files and
// search), cancelling a prediction, and file uploads. Every prediction is
// pinned to an approval: its body may name a webhook that receives the
// output, and no body matcher can yet tell. Deployments and trainings are
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
      { action: "allow", methods: ["POST"], paths: ["/v1/predictions/*/cancel", "/v1/files"], note: "cancels a prediction, or uploads a file" },
      {
        action: "approve",
        methods: ["POST"],
        paths: ["/v1/predictions", "/v1/models/*/*/predictions", "/v1/deployments/*/*/predictions"],
        note: "runs a model, whose request may name a webhook that receives the output",
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
