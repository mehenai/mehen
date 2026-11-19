import type { Template } from "../templates.ts"

// Without a human: read-only GraphQL queries. Every mutation, routine or
// not, needs an approval: no matcher can yet prove a mutation is only an
// issueCreate or commentCreate.
export const linear: Template = {
  id: "linear",
  displayName: "Linear API key",
  kind: "api-key",
  category: "productivity",
  docsUrl: "https://linear.app/settings/account/security",
  binding: { hosts: ["api.linear.app"], paths: ["/graphql"], methods: ["POST"] },
  injection: { in: "header", name: "Authorization", format: "{key}" },
  policy: {
    default: "approve",
    rules: [
      { action: "allow", methods: ["POST"], paths: ["/graphql"], body: "graphql-query", note: "read-only GraphQL queries" },
      { action: "approve", paths: ["/graphql"], body: "graphql-mutation", note: "GraphQL requests that are not plainly a query" },
    ],
  },
  ceiling: "placeholder",
  fields: { key: { label: "API key", pattern: "^lin_api_" } },
  prefixes: ["lin_api_"],
}
