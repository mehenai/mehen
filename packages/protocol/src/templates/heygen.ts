import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

// HeyGen takes the key in X-Api-Key. Without a human: reads, and text to
// speech. Rendering a video spends credits, and creating an avatar or
// cloning a voice copies a real person, so both are pinned to an
// approval, as is everything else. Webhooks are refused.
// https://developers.heygen.com/docs/quick-start
export const heygen: Template = {
  id: "heygen",
  displayName: "HeyGen API key",
  kind: "api-key",
  category: "search",
  docsUrl: "https://app.heygen.com/settings?nav=API",
  binding: { hosts: ["api.heygen.com"] },
  injection: { in: "header", name: "X-Api-Key", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: ["/v3/models/audio/tts", "/v3/models/audio/tts/stream", "/v3/voices/speech"], note: "text to speech" },
      { action: "approve", methods: ["POST"], paths: ["/v3/videos", "/v3/video-agents", "/v3/models/videos", "/v2/video/generate"], note: "renders a video, which spends credits" },
      { action: "approve", methods: ["POST"], paths: ["/v3/avatars/**", "/v3/models/audio/voices", "/v3/voices"], note: "creates an avatar or clones a voice" },
      { action: "deny", methods: WRITES, paths: ["/v3/webhooks/**", "/v1/webhook/**"], note: "webhooks" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "HEYGEN_API_KEY",
  fields: { key: { label: "API key" } },
}
