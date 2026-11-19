import type { Template } from "../templates.ts"
import { BEARER } from "./shared.ts"

// An account or workspace token for Railway's GraphQL API; a project
// token goes in another header and is not this template. Every request
// needs an approval, queries included: a query can read every service's
// variables, database passwords among them, and no body matcher can yet
// tell such a query from a harmless one.
// https://docs.railway.com/integrations/api
export const railway: Template = {
  id: "railway",
  displayName: "Railway API token",
  kind: "api-key",
  category: "code",
  docsUrl: "https://railway.com/account/tokens",
  binding: { hosts: ["backboard.railway.com"], paths: ["/graphql/v2"], methods: ["POST"] },
  injection: BEARER(),
  policy: { default: "approve", rules: [] },
  ceiling: "placeholder",
  defaultEnvVar: "RAILWAY_API_TOKEN",
  fields: { key: { label: "API token" } },
}
