import type { Template } from "../templates.ts"
import { ALLOW_READS, BEARER, MODEL_CALLS, WRITES } from "./shared.ts"

// A Hugging Face user access token, for the Hub (huggingface.co: the API,
// file downloads and git over HTTPS) and Inference Providers
// (router.huggingface.co). Without a human: reads, path lookups and
// chat completions through the router. Commits, repositories, Spaces and
// everything else need an approval; jobs and Space hardware are pinned to
// one because they are billed, and so is changing a repository's
// visibility or gating. Webhooks, organisation members, roles, SCIM, SSO,
// resource groups, service accounts and their tokens, trusted publishers,
// access requests, repository moves, Inference Provider keys and billing
// are refused, and a registry token needs an approval even to read.
// https://huggingface.co/docs/hub/api
export const huggingface: Template = {
  id: "huggingface",
  displayName: "Hugging Face access token",
  kind: "api-key",
  category: "ai",
  docsUrl: "https://huggingface.co/settings/tokens",
  binding: { hosts: ["huggingface.co", "router.huggingface.co"] },
  injection: BEARER(),
  policy: {
    default: "approve",
    rules: [
      ALLOW_READS,
      { action: "allow", methods: ["POST"], paths: ["/v1/chat/completions", "/hf-inference/models/**"], note: MODEL_CALLS },
      { action: "allow", methods: ["POST"], paths: ["/api/models/*/*/paths-info/*", "/api/datasets/*/*/paths-info/*", "/api/spaces/*/*/paths-info/*"], note: "looks up file paths in a repository" },
      { action: "approve", methods: ["POST"], paths: ["/api/jobs/*", "/api/spaces/*/*/hardware"], note: "runs billed compute" },
      { action: "approve", methods: WRITES, paths: ["/api/models/*/*/settings", "/api/datasets/*/*/settings", "/api/spaces/*/*/settings"], note: "changes a repository's visibility or gating" },
      { action: "approve", paths: ["/api/registry/token"], note: "hands back a registry token" },
      { action: "deny", methods: WRITES, paths: ["/api/settings/webhooks/**"], note: "webhooks send repository events elsewhere" },
      {
        action: "deny",
        methods: WRITES,
        paths: [
          "/api/organizations/*/members/**",
          "/api/organizations/*/scim/**",
          "/api/organizations/*/scim-provisioning/**",
          "/api/organizations/*/resource-groups/**",
          "/api/organizations/*/settings/sso/**",
          "/api/models/*/*/user-access-request/**",
          "/api/datasets/*/*/user-access-request/**",
        ],
        note: "members, roles, SSO and access requests give someone else access",
      },
      {
        action: "deny",
        methods: WRITES,
        paths: ["/api/organizations/*/service-accounts/**", "/api/organizations/*/settings/tokens/**", "/api/credentials/**", "/api/*/*/*/settings/trusted-publishers/**", "/oauth/**"],
        note: "mints or revokes tokens, or lets an outside CI publish",
      },
      { action: "deny", methods: WRITES, paths: ["/api/repos/move"], note: "moves a repository to another owner" },
      { action: "deny", methods: WRITES, paths: ["/api/settings/inference-providers/**"], note: "Inference Provider keys and billing" },
      { action: "deny", methods: WRITES, paths: ["/api/settings/billing/**", "/api/organizations/*/billing/**"], note: "billing and credit purchases" },
    ],
  },
  ceiling: "placeholder",
  defaultEnvVar: "HF_TOKEN",
  check: { method: "GET", path: "/api/whoami-v2" },
  fields: { key: { label: "Access token", pattern: "^hf_" } },
  prefixes: ["hf_"],
  setup: {
    title: "On Hugging Face",
    steps: [
      { title: "Open your access tokens", body: "Settings, then Access Tokens.", docs: true },
      { title: "Create a fine-grained token", body: "Grant only what the agent needs, for example read access to the repositories it uses and Make calls to Inference Providers.", field: "key" },
    ],
  },
}
