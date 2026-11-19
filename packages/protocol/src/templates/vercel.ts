import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// Without a human: reads, except a decrypted environment variable, which
// needs an approval. Deployments, domains, project settings and
// everything else need one too. Minting tokens, members and access
// groups, webhooks, log drains, transfers, deleting a project, team or
// account, and buying credits are refused.
// https://vercel.com/docs/rest-api/reference
export const vercel: Template = {
  id: "vercel",
  displayName: "Vercel access token",
  kind: "api-key",
  category: "code",
  docsUrl: "https://vercel.com/account/settings/tokens",
  binding: { hosts: ["api.vercel.com"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "approve", paths: ["/*/env/**", "/*/projects/*/env/**"], note: "environment variables, whose values are secrets" },
      { action: "deny", methods: WRITES, paths: ["/*/user/tokens/**"], note: "mints or revokes access tokens" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/*/teams/*/members/**", "/*/teams/*/invites/**", "/*/teams/*/request", "/*/projects/*/members/**", "/*/access-groups/**"],
        note: "members, invitations and access groups give someone else access",
      },
      { action: "deny", methods: WRITES, paths: ["/*/webhooks/**"], note: "webhooks" },
      { action: "deny", methods: WRITES, paths: ["/*/drains/**", "/*/log-drains/**", "/*/integrations/log-drains/**"], note: "drains send logs and traces elsewhere" },
      { action: "deny", methods: WRITES, paths: ["/projects/*/transfer-request", "/projects/transfer-request/**", "/*/projects/*/transfer-request"], note: "transfers a project to another account" },
      { action: "deny", methods: ["DELETE"], paths: ["/*/projects/*", "/*/teams/*", "/*/user"], note: "deletes a project, a team or the account" },
      { action: "deny", methods: WRITES, paths: ["/*/billing/**"], note: "buys credits" },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/v2/user" },
  fields: { key: { label: "Token" } },
  setup: {
    title: "In Vercel",
    steps: [
      { title: "Open the tokens page", body: "Account settings, then Tokens.", docs: true },
      { title: "Create a token for one team", body: "Set the scope to the team the agent works in, not your whole account, and pick an expiry.", field: "key" },
    ],
  },
}
