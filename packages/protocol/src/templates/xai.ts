import type { Template } from "../templates.ts"
import { BEARER, MODEL_CALLS, NAMED_READS, READS, WRITES } from "./shared.ts"

// xAI's inference API. The management API is another host with its own
// key and is not bound. Without a human: the named reads (models, deferred
// completions, images, videos, batches and voices), and model calls (chat,
// responses, images, video, speech, tokenising and requests added inline to
// a batch). Creating a batch and uploading or publishing a file are pinned
// to an approval: a batch can run requests from an uploaded JSONL file,
// which the vault never reads, and those can name remote MCP tools too. A
// model call or inline batch request whose body names a remote MCP server
// (a tool of type "mcp", or any server_url), or that cannot be read, is
// pinned to an approval: xAI
// calls that server itself, with whatever headers and authorization the
// request names, and its MCP tools do not honour require_approval. Stored
// responses are pinned to an approval too, since their tools carry those
// headers and that authorization. An image or video request, direct or
// added inline to a batch, whose storage_options publish the output at a
// permanent unauthenticated URL (public_url anything but false), or that
// cannot be read, is pinned to an approval; ordinary generation and
// private storage pass. The API key's details, realtime client
// secrets and phone numbers are pinned to an approval; every other read
// asks, as do deletes and anything else.
// https://api.x.ai/api-docs/openapi.json
// https://docs.x.ai/developers/rest-api-reference/inference
export const xai: Template = {
  id: "xai",
  displayName: "xAI API key",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://console.x.ai/",
  binding: { hosts: ["api.x.ai"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      NAMED_READS(
        [
          "/v1/models",
          "/v1/models/*",
          "/v1/language-models/**",
          "/v1/image-generation-models/**",
          "/v1/video-generation-models/**",
          "/v1/chat/deferred-completion/*",
          "/v1/images/*",
          "/v1/videos/*",
          "/v1/batches/**",
          "/v1/tts/voices/**",
          "/v1/custom-voices/**",
        ],
        "reads of models, generated media, batches and voices",
      ),
      { action: "approve", methods: READS, paths: ["/v1/responses/*"], note: "a stored response, whose MCP tools carry their authorization and headers" },
      {
        action: "approve",
        methods: ["POST"],
        paths: ["/v1/responses", "/v1/chat/completions", "/v1/batches/*/requests"],
        body: "json-remote-mcp",
        note: "names a remote MCP server, which xAI calls itself, or cannot be read",
      },
      {
        action: "approve",
        methods: ["POST"],
        paths: ["/v1/images/generations", "/v1/images/edits", "/v1/videos/generations", "/v1/videos/edits", "/v1/videos/extensions", "/v1/batches/*/requests"],
        body: "json-public-url",
        note: "publishes the output at a permanent public URL, or cannot be read",
      },
      { action: "approve", methods: READS, paths: ["/v1/api-key"], note: "the API key's own details" },
      {
        action: "allow",
        methods: ["POST"],
        paths: [
          "/v1/chat/completions",
          "/v1/responses",
          "/v1/responses/compact",
          "/v1/images/generations",
          "/v1/images/edits",
          "/v1/videos/generations",
          "/v1/videos/edits",
          "/v1/videos/extensions",
          "/v1/tts",
          "/v1/stt",
          "/v1/tokenize-text",
          "/v1/batches/*/requests",
        ],
        note: MODEL_CALLS,
      },
      {
        action: "approve",
        methods: ["POST"],
        paths: ["/v1/batches"],
        note: "creates a batch, which may run requests from an uploaded file the vault never reads, remote MCP tools among them",
      },
      {
        action: "approve",
        methods: WRITES,
        paths: ["/v1/files", "/v1/files/**"],
        note: "uploads a file, which can hold batch requests, or makes a file public",
      },
      { action: "approve", methods: ["POST"], paths: ["/v1/realtime/client_secrets"], note: "mints a realtime client secret" },
      { action: "approve", methods: WRITES, paths: ["/v2/phone-numbers/**"], note: "buys or releases a billed phone number" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "XAI_API_KEY",
  check: { method: "GET", path: "/v1/models" },
  fields: { key: { label: "API key", pattern: "^xai-" } },
  prefixes: ["xai-"],
}
