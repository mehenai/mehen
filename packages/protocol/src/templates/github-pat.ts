import type { Template } from "../templates.ts"
import { BEARER, GITHUB_ALLOWED, GITHUB_SENSITIVE } from "./shared.ts"

// Without a human: reads, read-only GraphQL queries, and opening,
// commenting on and labelling issues and pull requests (GITHUB_ALLOWED).
// Keys, webhooks, collaborators, invitations, runners, transfers and
// account emails are refused; everything else needs an approval.
export const githubPat: Template = {
  id: "github-pat",
  displayName: "GitHub personal access token",
  kind: "api-key",
  category: "code",
  docsUrl: "https://github.com/settings/personal-access-tokens",
  binding: { hosts: ["api.github.com"] },
  injection: BEARER(),
  policy: { default: "approve", rules: [...GITHUB_ALLOWED, ...GITHUB_SENSITIVE] },
  ceiling: "placeholder",
  check: { method: "GET", path: "/user" },
  fields: { key: { label: "Token", pattern: "^(github_pat_|ghp_)" } },
  prefixes: ["github_pat_", "ghp_"],
}
