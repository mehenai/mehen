import type { Template } from "../templates.ts"
import { ALLOW_READS, WRITES } from "./shared.ts"

// A Discord bot token, sent as "Bot <token>", for the HTTP API under
// discord.com/api (versioned or not). The gateway (WebSocket) is not
// bound. Without a human: reads and adding the bot's own reaction.
// Posting is pinned to an approval, and everything else needs one too.
// Webhooks, invites, roles, channel permissions, members and bans, the
// application's own settings (its interactions endpoint is a webhook),
// OAuth endpoints and deleting a server are refused.
// https://docs.discord.com/developers/reference
export const discord: Template = {
  id: "discord",
  displayName: "Discord bot token",
  kind: "api-key",
  category: "productivity",
  docsUrl: "https://discord.com/developers/applications",
  binding: { hosts: ["discord.com"], paths: ["/api/**"] },
  injection: { in: "header", name: "Authorization", format: "Bot {key}" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["PUT"], paths: ["/api/*/channels/*/messages/*/reactions/*/@me", "/api/channels/*/messages/*/reactions/*/@me"], note: "adds the bot's own reaction" },
      { action: "approve", methods: ["POST"], paths: ["/api/**/channels/*/messages", "/api/**/channels/*/threads", "/api/**/channels/*/messages/*/threads"], note: "posts as the bot" },
      { action: "deny", methods: WRITES, paths: ["/api/**/channels/*/webhooks", "/api/**/webhooks/**"], note: "webhooks let anyone with the URL post" },
      { action: "deny", methods: WRITES, paths: ["/api/**/channels/*/invites", "/api/**/invites/**"], note: "invites let someone else join" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/api/**/guilds/*/roles/**", "/api/**/channels/*/permissions/**", "/api/**/guilds/*/members/**", "/api/**/guilds/*/bans/**", "/api/**/guilds/*/bulk-ban"],
        note: "roles, permissions, members and bans change who can do what",
      },
      { action: "deny", methods: WRITES, paths: ["/api/**/applications/*"], note: "the application's settings, its interactions endpoint among them" },
      { action: "deny", methods: WRITES, paths: ["/api/**/oauth2/**"], note: "OAuth tokens and grants" },
      { action: "deny", methods: ["DELETE"], paths: ["/api/*/guilds/*", "/api/guilds/*"], note: "deletes a server" },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/api/v10/users/@me" },
  fields: { key: { label: "Bot token" } },
}
