import type { Template } from "../templates.ts"
import { NAMED_READS, WRITES } from "./shared.ts"

// A Discord bot token, sent as "Bot <token>", for the HTTP API under
// discord.com/api (versioned or not). The gateway (WebSocket) is not
// bound. Without a human: the named reads on a versioned API path (the
// bot's user and servers, a server, its channels, members, roles, active
// threads and emojis, a channel, its messages, reactions, pins and
// archived threads, and the gateway), and adding the bot's own reaction.
// Every other read asks, the unversioned API included. Posting is pinned
// to an approval, and everything else needs one too. Webhooks (reading
// one hands back its token), invites, following a channel, roles, channel
// permissions, thread members, editing a channel or creating one (either
// can rewrite permission overwrites), members and bans, the application's
// own settings (its interactions endpoint is a webhook), OAuth endpoints
// and deleting a server are refused.
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
      NAMED_READS(
        [
          "/api/*/users/@me",
          "/api/*/users/@me/guilds",
          "/api/*/guilds/*",
          "/api/*/guilds/*/channels",
          "/api/*/guilds/*/members",
          "/api/*/guilds/*/members/*",
          "/api/*/guilds/*/roles",
          "/api/*/guilds/*/threads/active",
          "/api/*/guilds/*/emojis/**",
          "/api/*/channels/*",
          "/api/*/channels/*/messages",
          "/api/*/channels/*/messages/*",
          "/api/*/channels/*/messages/*/reactions/**",
          "/api/*/channels/*/pins",
          "/api/*/channels/*/threads/archived/**",
          "/api/*/gateway",
          "/api/*/gateway/bot",
        ],
        "reads of servers, channels, members, roles, messages and threads",
      ),
      { action: "allow", methods: ["PUT"], paths: ["/api/*/channels/*/messages/*/reactions/*/@me", "/api/channels/*/messages/*/reactions/*/@me"], note: "adds the bot's own reaction" },
      { action: "approve", methods: ["POST"], paths: ["/api/**/channels/*/messages", "/api/**/channels/*/threads", "/api/**/channels/*/messages/*/threads"], note: "posts as the bot" },
      { action: "deny", paths: ["/api/**/channels/*/webhooks", "/api/**/guilds/*/webhooks", "/api/**/webhooks/**"], note: "webhooks let anyone with the URL post, and reading one hands back its token" },
      { action: "deny", methods: WRITES, paths: ["/api/**/channels/*/invites", "/api/**/invites/**"], note: "invites let someone else join" },
      { action: "deny", methods: WRITES, paths: ["/api/**/channels/*/followers"], note: "following a channel posts its messages into another server" },
      { action: "deny", methods: WRITES, paths: ["/api/**/channels/*/thread-members/**"], note: "adds or removes thread members" },
      { action: "deny", methods: ["PATCH"], paths: ["/api/**/channels/*"], note: "editing a channel can rewrite its permission overwrites" },
      { action: "deny", methods: ["POST", "PATCH"], paths: ["/api/**/guilds/*/channels"], note: "creating or reordering channels can set or sync permission overwrites" },
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
