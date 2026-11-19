import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, MODEL_CALLS, WRITES } from "./shared.ts"

// Without a human: reads, and model calls (chat, completions, agents,
// embeddings, moderation, classification, OCR, speech and transcription)
// with the files, batches and conversations they use. Fine-tuning,
// libraries and everything else need an approval; service accounts and
// sharing a library are refused. https://docs.mistral.ai/api
export const mistral: Template = {
  id: "mistral",
  displayName: "Mistral API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://console.mistral.ai/api-keys",
  binding: { hosts: ["api.mistral.ai"], paths: ["/v1/**", "/v2/**"] },
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
          "/v1/fim/completions",
          "/v1/agents/completions",
          "/v1/embeddings",
          "/v1/moderations",
          "/v1/chat/moderations",
          "/v1/classifications",
          "/v1/chat/classifications",
          "/v1/ocr",
          "/v1/audio/speech",
          "/v1/audio/transcriptions",
          "/v1/files",
          "/v1/batch/jobs",
          "/v1/batch/jobs/*/cancel",
          "/v1/conversations",
          "/v1/conversations/*",
          "/v1/conversations/*/restart",
        ],
        note: MODEL_CALLS,
      },
      { action: "deny", methods: WRITES, paths: ["/v1/service-accounts/**"], note: "service accounts and their roles" },
      { action: "deny", methods: WRITES, paths: ["/v1/libraries/*/share"], note: "shares a library with someone else" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "MISTRAL_API_KEY",
  check: { method: "GET", path: "/v1/models" },
  fields: { key: { label: "API key" } },
}
