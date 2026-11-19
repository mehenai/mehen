import type { Template } from "../templates.ts"
import { ALLOW_READS, READS, WRITES } from "./shared.ts"

// Upstash's Developer API takes the account email and an API key as HTTP
// Basic credentials. A database's own REST host depends on the database,
// so it is not bound. Without a human: reads, except databases and vector
// indexes, whose details carry their passwords and REST tokens and need an
// approval. Creating databases and indexes, changing plans, budgets and
// regions, and resetting passwords are pinned to an approval, as is
// everything else. Team members and moving a database or an index to
// another team are refused.
// https://upstash.com/docs/devops/developer-api/introduction
export const upstash: Template = {
  id: "upstash",
  displayName: "Upstash Developer API key",
  kind: "basic-auth",
  category: "infrastructure",
  docsUrl: "https://console.upstash.com/account/api",
  binding: { hosts: ["api.upstash.com"], paths: ["/v2/**"] },
  injection: { in: "basic", username: "username", password: "password" },
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "approve",
        methods: READS,
        paths: ["/v2/redis/databases", "/v2/redis/database/*", "/v2/vector/index", "/v2/vector/index/*"],
        note: "database and index details hand back passwords and REST tokens",
      },
      {
        action: "approve",
        methods: WRITES,
        paths: ["/v2/redis/reset-password/*", "/v2/vector/index/*/reset-password"],
        note: "resets a database password or index tokens",
      },
      {
        action: "approve",
        methods: WRITES,
        paths: ["/v2/redis/database", "/v2/redis/*/change-plan", "/v2/redis/update-budget/*", "/v2/redis/update-regions/*", "/v2/vector/index", "/v2/vector/index/*/setplan"],
        note: "creates or changes something billed",
      },
      { action: "deny", methods: WRITES, paths: ["/v2/teams/member"], note: "team members get access to every database in the team" },
      { action: "deny", methods: WRITES, paths: ["/v2/redis/move-to-team", "/v2/vector/index/*/transfer"], note: "moves a database or an index to another team" },
    ],
  },
  ceiling: "relay",
  check: { method: "GET", path: "/v2/teams" },
  fields: { username: { label: "Account email" }, password: { label: "API key" } },
  setup: {
    title: "In the Upstash console",
    steps: [
      { title: "Open the Developer API page", body: "Account, then Management API.", docs: true },
      { title: "Give your account email", body: "The email address you sign in to Upstash with.", field: "username" },
      { title: "Create an API key", body: "Create a key and paste it here; it is shown once.", field: "password" },
    ],
  },
}
