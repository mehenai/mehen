import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

// ElevenLabs takes the key in xi-api-key. Without a human: reads, and
// speech, dialogue, transcription, sound effects, audio isolation and
// alignment. Cloning or designing a voice, dubbing, music and everything
// else need an approval. Service accounts and their keys, API key
// settings, invitations, members, groups, sign-in connections, sharing
// and webhooks are refused. https://elevenlabs.io/docs/api-reference/introduction
export const elevenlabs: Template = {
  id: "elevenlabs",
  displayName: "ElevenLabs API key",
  kind: "api-key",
  category: "search",
  docsUrl: "https://elevenlabs.io/app/settings/api-keys",
  binding: { hosts: ["api.elevenlabs.io"] },
  injection: { in: "header", name: "xi-api-key", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "allow",
        methods: ["POST"],
        paths: [
          "/v1/text-to-speech/*",
          "/v1/text-to-speech/*/stream",
          "/v1/text-to-speech/*/with-timestamps",
          "/v1/text-to-speech/*/stream/with-timestamps",
          "/v1/text-to-dialogue",
          "/v1/text-to-dialogue/stream",
          "/v1/text-to-dialogue/with-timestamps",
          "/v1/text-to-dialogue/stream/with-timestamps",
          "/v1/speech-to-text",
          "/v1/sound-generation",
          "/v1/audio-isolation",
          "/v1/audio-isolation/stream",
          "/v1/forced-alignment",
        ],
        note: "speech, transcription and sound",
      },
      { action: "deny", methods: WRITES, paths: ["/v1/service-accounts/**", "/v1/workspaces/api-keys/**"], note: "service accounts, API keys and their settings" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/v1/workspace/invites/**", "/v1/workspace/members/**", "/v1/workspace/groups/**", "/v1/workspace/auth-connections/**", "/v1/workspace/resources/*/share"],
        note: "invitations, members, groups, sign-in connections and sharing give someone else access",
      },
      { action: "deny", methods: WRITES, paths: ["/v1/workspace/webhooks/**"], note: "webhooks" },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/v1/user" },
  fields: { key: { label: "API key" } },
}
