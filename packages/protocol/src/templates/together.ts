import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, MODEL_CALLS } from "./shared.ts"

// Without a human: reads, and model calls (chat, completions, embeddings,
// images, speech, transcription, translation, reranking). Fine-tuning,
// dedicated endpoints, clusters and everything else need an approval.
// https://docs.together.ai/reference/chat-completions
export const together: Template = {
  id: "together",
  displayName: "Together AI API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://api.together.ai/settings/api-keys",
  binding: { hosts: ["api.together.xyz"], paths: ["/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: [
          "/v1/chat/completions",
          "/v1/completions",
          "/v1/embeddings",
          "/v1/images/generations",
          "/v1/audio/speech",
          "/v1/audio/transcriptions",
          "/v1/audio/translations",
          "/v1/rerank",
        ],
        note: MODEL_CALLS,
      },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/v1/models" },
  fields: { key: { label: "API key" } },
}
