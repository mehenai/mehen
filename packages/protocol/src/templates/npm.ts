import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// A registry token, for reading private packages and publishing. Scoped
// package names travel as "@scope%2fname", an encoded slash the vault
// refuses as ambiguous, so this reaches unscoped packages only.
// Without a human: reads. Publishing, deprecating or unpublishing a
// package needs an approval; minting tokens, signing in, account
// settings, access, owners, teams, organisation members, trusted
// publishers and hooks are refused. https://docs.npmjs.com/about-access-tokens
export const npm: Template = {
  id: "npm",
  displayName: "npm access token",
  kind: "api-key",
  category: "code",
  docsUrl: "https://docs.npmjs.com/creating-and-viewing-access-tokens",
  binding: { hosts: ["registry.npmjs.org"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "approve", methods: ["PUT", "DELETE"], paths: ["/*", "/*/-rev/**"], note: "publishes, deprecates or unpublishes a package" },
      { action: "deny", methods: WRITES, paths: ["/-/npm/v1/tokens/**"], note: "mints or revokes tokens" },
      { action: "deny", methods: WRITES, paths: ["/-/user/**", "/-/v1/login/**", "/-/npm/v1/user/**"], note: "signs in, adds a user or changes account settings" },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/-/package/*/access", "/-/package/*/collaborators/**", "/-/package/*/trust/**", "/-/team/**", "/-/org/**"],
        note: "access, owners, teams, organisation members and trusted publishers decide who may publish",
      },
      { action: "deny", methods: WRITES, paths: ["/-/npm/v1/hooks/**"], note: "hooks" },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/-/whoami" },
  fields: { key: { label: "Access token", pattern: "^npm_" } },
  prefixes: ["npm_"],
  setup: {
    title: "On npmjs.com",
    steps: [
      { title: "Open your access tokens", body: "On npmjs.com, your avatar, then Access tokens, then Generate new token. The guide explains each kind.", docs: true },
      {
        title: "Create a granular token",
        body: "Choose Granular access token, give it read-only or read and write access to only the packages it needs, and set an expiry.",
        warn: "Scoped packages (@scope/name) cannot be reached through the vault yet: their names contain an encoded slash, which the vault refuses.",
        field: "key",
      },
    ],
  },
}
