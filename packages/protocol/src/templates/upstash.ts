import type { Template } from "../templates.ts"
import { NAMED_READS, READS, WRITES } from "./shared.ts"

// Upstash's Developer API takes the account email and an API key as HTTP
// Basic credentials. A database's own REST host depends on the database,
// so it is not bound. Without a human: the named reads (teams, the audit
// log, and Redis, vector, Search and QStash statistics and backups). Every
// other read asks, and those that hand back a password or token are pinned
// to an approval: Redis databases, vector indexes, Search indexes, QStash
// users and Blob stores. Creating databases and indexes, changing plans,
// budgets and regions, and resetting passwords and tokens are pinned to an
// approval, as is everything else. Team members and moving a database, an
// index or QStash to another team are refused.
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
      NAMED_READS(
        [
          "/v2/teams",
          "/v2/teams/*",
          "/v2/auditlogs",
          "/v2/redis/stats/*",
          "/v2/redis/traffic/*",
          "/v2/redis/list-backup/*",
          "/v2/redis/backup-analysis/*/*",
          "/v2/vector/index/*/stats",
          "/v2/search/*/stats",
          "/v2/qstash/stats/*",
          "/v2/qstash/ipv4",
        ],
        "reads of teams, the audit log, statistics and backups",
      ),
      {
        action: "approve",
        methods: READS,
        paths: ["/v2/redis/databases", "/v2/redis/database/*", "/v2/vector/index", "/v2/vector/index/*", "/v2/search", "/v2/search/*", "/v2/qstash/users", "/v2/qstash/user/*", "/v2/blob/**"],
        note: "database, index, Search, QStash and Blob details hand back passwords and tokens",
      },
      {
        action: "approve",
        methods: WRITES,
        paths: ["/v2/redis/reset-password/*", "/v2/vector/index/*/reset-password", "/v2/search/*/reset-password", "/v2/qstash/rotate-token/*"],
        note: "resets a database password, or index or QStash tokens",
      },
      {
        action: "approve",
        methods: WRITES,
        paths: [
          "/v2/redis/database",
          "/v2/redis/*/change-plan",
          "/v2/redis/update-budget/*",
          "/v2/redis/update-regions/*",
          "/v2/vector/index",
          "/v2/vector/index/*/setplan",
          "/v2/search",
          "/v2/qstash/set-plan/*",
          "/v2/qstash/update-budget/*",
          "/v2/qstash/enable-prodpack/*",
        ],
        note: "creates or changes something billed",
      },
      { action: "deny", methods: WRITES, paths: ["/v2/teams/member"], note: "team members get access to every database in the team" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/v2/redis/move-to-team", "/v2/vector/index/*/transfer", "/v2/search/*/transfer", "/v2/qstash/move-to-team"],
        note: "moves a database, an index or QStash to another team",
      },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "UPSTASH_API_KEY",
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
