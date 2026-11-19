import type { Template } from "../templates.ts"
import { BEARER } from "./shared.ts"

// Slack's Web API is RPC: every method takes GET or POST, so the HTTP
// method says nothing. Without a human: the read methods named below, and
// adding a reaction. File uploads are refused: their bytes go to a URL
// the vault never sees, so no card could show them. Every other method
// needs an approval.
export const slackBot: Template = {
  id: "slack-bot",
  displayName: "Slack bot token",
  kind: "api-key",
  category: "productivity",
  docsUrl: "https://api.slack.com/apps",
  binding: { hosts: ["slack.com"], paths: ["/api/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      {
        action: "allow",
        paths: [
          "/api/auth.test",
          "/api/bots.info",
          "/api/chat.getPermalink",
          "/api/conversations.history",
          "/api/conversations.info",
          "/api/conversations.list",
          "/api/conversations.members",
          "/api/conversations.replies",
          "/api/emoji.list",
          "/api/files.info",
          "/api/files.list",
          "/api/pins.list",
          "/api/reactions.get",
          "/api/reactions.list",
          "/api/team.info",
          "/api/usergroups.list",
          "/api/usergroups.users.list",
          "/api/users.conversations",
          "/api/users.getPresence",
          "/api/users.info",
          "/api/users.list",
          "/api/users.lookupByEmail",
          "/api/users.profile.get",
        ],
        note: "read methods",
      },
      { action: "allow", paths: ["/api/reactions.add"], note: "adds an emoji reaction" },
      {
        action: "deny",
        paths: [
          "/api/files.getUploadURLExternal",
          "/api/files.completeUploadExternal",
          "/api/files.upload",
          "/api/files.remote.add",
          "/api/files.remote.info",
          "/api/files.remote.list",
          "/api/files.remote.remove",
          "/api/files.remote.share",
          "/api/files.remote.update",
        ],
        note: "uploads bypass the approval card; ask the human to upload",
      },
      {
        action: "approve",
        paths: [
          "/api/chat.postMessage",
          "/api/chat.postEphemeral",
          "/api/chat.scheduleMessage",
          "/api/chat.meMessage",
          "/api/chat.update",
        ],
        note: "posts as the bot",
      },
      { action: "approve", paths: ["/api/chat.delete"], note: "deletes a message as the bot" },
      { action: "approve", paths: ["/api/conversations.invite"], note: "invites someone to a channel as the bot" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "Bot token", pattern: "^xoxb-" } },
  prefixes: ["xoxb-"],
}
