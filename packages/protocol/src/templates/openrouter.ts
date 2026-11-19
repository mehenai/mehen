import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, MODEL_CALLS, WRITES } from "./shared.ts"

// Without a human: reads, and model calls (chat, completions, responses,
// messages, embeddings, reranking, images, speech, transcription).
// Batches, presets and everything else need an approval, and buying
// credits or setting a budget is pinned to one. Minting keys, provider
// keys, observability destinations, members and the stored-secrets API
// are refused. https://openrouter.ai/docs/api-reference/overview
export const openrouter: Template = {
  id: "openrouter",
  displayName: "OpenRouter API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://openrouter.ai/settings/keys",
  binding: { hosts: ["openrouter.ai"], paths: ["/api/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: [
          "/api/v1/chat/completions",
          "/api/v1/completions",
          "/api/v1/responses",
          "/api/v1/messages",
          "/api/v1/embeddings",
          "/api/v1/rerank",
          "/api/v1/images",
          "/api/v1/audio/speech",
          "/api/v1/audio/transcriptions",
        ],
        note: MODEL_CALLS,
      },
      { action: "approve", methods: WRITES, paths: ["/api/v1/credits/**", "/api/v1/workspaces/*/budgets/**"], note: "buys credits or changes a budget" },
      { action: "deny", methods: WRITES, paths: ["/api/v1/keys/**", "/api/v1/auth/keys/**"], note: "mints or revokes API keys" },
      { action: "deny", methods: WRITES, paths: ["/api/v1/byok/**"], note: "provider keys" },
      { action: "deny", methods: WRITES, paths: ["/api/v1/observability/destinations/**"], note: "observability destinations copy every request elsewhere" },
      { action: "deny", methods: WRITES, paths: ["/api/v1/workspaces/*/members/**", "/api/v1/scim/**"], note: "members and directory sync give someone else access" },
      { action: "deny", methods: WRITES, paths: ["/api/v1/vault/**"], note: "stored secrets" },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/api/v1/key" },
  fields: { key: { label: "API key", pattern: "^sk-or-" } },
  prefixes: ["sk-or-v1-"],
}
