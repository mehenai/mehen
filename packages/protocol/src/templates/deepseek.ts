import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, MODEL_CALLS } from "./shared.ts"

// DeepSeek serves an OpenAI-style API at the root and an Anthropic-style
// one under /anthropic, both with the same key as a bearer token. Without
// a human: reads and model calls (chat, the beta completions, and
// Anthropic-style messages). Anything else needs an approval.
// https://api-docs.deepseek.com/
export const deepseek: Template = {
  id: "deepseek",
  displayName: "DeepSeek API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://platform.deepseek.com/api_keys",
  binding: { hosts: ["api.deepseek.com"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: ["/chat/completions", "/v1/chat/completions", "/beta/completions", "/beta/chat/completions", "/anthropic/v1/messages", "/anthropic/v1/messages/count_tokens"],
        note: MODEL_CALLS,
      },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "DEEPSEEK_API_KEY",
  check: { method: "GET", path: "/models" },
  fields: { key: { label: "API key", pattern: "^sk-" } },
  prefixes: ["sk-"],
}
