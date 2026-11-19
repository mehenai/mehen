import type { Template } from "../templates.ts"
import { ALLOW_READS, MODEL_CALLS, WRITES } from "./shared.ts"

// Without a human: reads, and model calls (generateContent, streaming,
// token counts, embeddings and the other model methods, and the OpenAI
// compatible endpoints) with the files and context caches they use. Tuned
// models and everything else need an approval; sharing a tuned model or a
// corpus is refused. https://ai.google.dev/api
export const googleGemini: Template = {
  id: "google-gemini",
  displayName: "Google Gemini API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://aistudio.google.com/apikey",
  binding: { hosts: ["generativelanguage.googleapis.com"], paths: ["/v1beta/**", "/v1/**", "/upload/v1beta/**"] },
  injection: { in: "header", name: "x-goog-api-key", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: [
          "/v1beta/models/*",
          "/v1/models/*",
          "/v1beta/openai/chat/completions",
          "/v1beta/openai/embeddings",
          "/v1beta/openai/images/generations",
          "/v1beta/files",
          "/upload/v1beta/files",
          "/v1beta/cachedContents",
        ],
        note: MODEL_CALLS,
      },
      { action: "deny", methods: WRITES, paths: ["/v1beta/tunedModels/*/permissions/**", "/v1beta/corpora/*/permissions/**"], note: "shares a tuned model or a corpus with someone else" },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/v1beta/models" },
  fields: { key: { label: "API key", pattern: "^AIza" } },
  prefixes: ["AIza"],
}
