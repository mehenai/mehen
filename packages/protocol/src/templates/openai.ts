import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, MODEL_CALLS } from "./shared.ts"

// Without a human: reads, and model calls (responses, chat completions,
// completions, embeddings, moderations, images, audio) with the files,
// uploads, batches and conversations they use. Deletes, realtime client
// secrets and anything else need an approval; the admin API is refused.
export const openai: Template = {
  id: "openai",
  displayName: "OpenAI API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://platform.openai.com/api-keys",
  binding: { hosts: ["api.openai.com"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: [
          "/v1/responses",
          "/v1/responses/*/cancel",
          "/v1/responses/input_tokens",
          "/v1/chat/completions",
          "/v1/completions",
          "/v1/embeddings",
          "/v1/moderations",
          "/v1/images/generations",
          "/v1/images/edits",
          "/v1/images/variations",
          "/v1/audio/speech",
          "/v1/audio/transcriptions",
          "/v1/audio/translations",
          "/v1/files",
          "/v1/uploads",
          "/v1/uploads/*/parts",
          "/v1/uploads/*/complete",
          "/v1/batches",
          "/v1/batches/*/cancel",
          "/v1/conversations",
          "/v1/conversations/*/items",
        ],
        note: MODEL_CALLS,
      },
      { action: "deny", paths: ["/v1/organization/**"], note: "admin API" },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/v1/models" },
  fields: { key: { label: "API key", pattern: "^sk-" } },
  prefixes: ["sk-proj-", "sk-"],
}
