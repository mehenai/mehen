import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, WRITES } from "./shared.ts"

// The Machines API. Without a human: reads, except app secrets, app
// secret keys and a database user's password, which need an approval (a
// secrets read may ask for the values, and a secret key read is not
// known to leave the key out). Machines, volumes, certificates, secrets
// and everything else that writes need an approval too. Minting a
// deploy, KMS or OIDC token is refused.
// https://docs.fly.io/api/machines/openapi.json
export const fly: Template = {
  id: "fly",
  displayName: "Fly.io API token",
  kind: "api-key",
  category: "code",
  docsUrl: "https://fly.io/docs/security/tokens/",
  binding: { hosts: ["api.machines.dev"], paths: ["/v1/**"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      {
        action: "approve",
        paths: ["/v1/apps/*/secrets", "/v1/apps/*/secrets/**", "/v1/apps/*/secretkeys", "/v1/apps/*/secretkeys/**", "/v1/postgres/*/users/*/credentials"],
        note: "app secrets, app secret keys and database passwords",
      },
      { action: "deny", methods: WRITES, paths: ["/v1/apps/*/deploy_token", "/v1/tokens/kms", "/v1/tokens/oidc"], note: "mints tokens" },
    ],
  },
  ceiling: "placeholder",
  check: { method: "GET", path: "/v1/tokens/current" },
  fields: { key: { label: "API token" } },
  setup: {
    title: "In Fly.io",
    steps: [
      { title: "Open the tokens page", body: "Your organisation's dashboard, then Tokens.", docs: true },
      { title: "Create a token for one app or organisation", body: "Prefer a deploy token for the one app the agent works on, and pick an expiry. Paste the whole token, including FlyV1 at the start.", field: "key" },
    ],
  },
}
