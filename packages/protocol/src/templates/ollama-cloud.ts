import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, MODEL_CALLS } from "./shared.ts"

// Ollama's cloud API on ollama.com, not a local Ollama. Without a human:
// reads, model calls (the native API and its OpenAI and Anthropic
// compatible endpoints) and web searches. Fetching a page through Ollama
// needs an approval, since it reaches any address; creating, pushing,
// copying or deleting a model and everything else does too.
// https://docs.ollama.com/cloud
export const ollamaCloud: Template = {
  id: "ollama-cloud",
  displayName: "Ollama Cloud API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://ollama.com/settings/keys",
  binding: { hosts: ["ollama.com"], paths: ["/api/**", "/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: [
          "/api/chat",
          "/api/generate",
          "/api/embed",
          "/api/embeddings",
          "/api/show",
          "/v1/chat/completions",
          "/v1/completions",
          "/v1/embeddings",
          "/v1/responses",
          "/v1/messages",
          "/v1/messages/count_tokens",
        ],
        note: MODEL_CALLS,
      },
      { action: "allow", methods: ["POST"], paths: ["/api/web_search"], note: "web searches" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "API key" } },
}
