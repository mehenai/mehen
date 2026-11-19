import type { Template } from "../templates.ts"
import { ALLOW_READS, MODEL_CALLS } from "./shared.ts"

// Without a human: reads, messages (with token counts and batches),
// legacy completions and file uploads. Deletes and anything else need an
// approval; the admin API is refused.
export const anthropic: Template = {
  id: "anthropic",
  displayName: "Anthropic API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://console.anthropic.com/settings/keys",
  binding: { hosts: ["api.anthropic.com"] },
  injection: { in: "header", name: "x-api-key", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: ["/v1/messages", "/v1/messages/count_tokens", "/v1/messages/batches", "/v1/messages/batches/*/cancel", "/v1/complete", "/v1/files"],
        note: MODEL_CALLS,
      },
      { action: "deny", paths: ["/v1/organizations/**"], note: "admin API" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "ANTHROPIC_API_KEY",
  check: { method: "GET", path: "/v1/models", headers: [["anthropic-version", "2023-06-01"]] },
  fields: { key: { label: "API key", pattern: "^sk-ant-" } },
  prefixes: ["sk-ant-api03-", "sk-ant-"],
}
