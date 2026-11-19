import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, MODEL_CALLS } from "./shared.ts"

// Without a human: reads, and model calls (chat, responses, speech,
// transcription, translation, reranking) with the files and batches they
// use. Everything else needs an approval.
// https://console.groq.com/docs/api-reference
export const groq: Template = {
  id: "groq",
  displayName: "Groq API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://console.groq.com/keys",
  binding: { hosts: ["api.groq.com"], paths: ["/openai/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: [
          "/openai/v1/chat/completions",
          "/openai/v1/responses",
          "/openai/v1/audio/speech",
          "/openai/v1/audio/transcriptions",
          "/openai/v1/audio/translations",
          "/openai/v1/reranking",
          "/openai/v1/files",
          "/openai/v1/batches",
          "/openai/v1/batches/*/cancel",
        ],
        note: MODEL_CALLS,
      },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/openai/v1/models" },
  fields: { key: { label: "API key", pattern: "^gsk_" } },
  prefixes: ["gsk_"],
}
