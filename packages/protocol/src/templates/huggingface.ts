import type { Template } from "../templates.ts"
import { BEARER, MODEL_CALLS, NAMED_READS, READS, WRITES } from "./shared.ts"

const REPO_TYPES = ["models", "datasets", "spaces"]
const perRepo = (...suffixes: string[]): string[] => REPO_TYPES.flatMap((t) => suffixes.map((s) => `/api/${t}/*/*${s}`))

// A Hugging Face user access token, for the Hub (huggingface.co: the API,
// file downloads and git over HTTPS) and Inference Providers
// (router.huggingface.co). Without a human: the named reads (the account,
// repository listings and details, trees, revisions, commits and refs, and
// file downloads), path lookups and chat completions through the router.
// Every other read asks: JWTs, Xet read and write tokens, Space secrets
// and variables, jobs, webhooks, service accounts, tokens and the registry
// token are pinned to an approval. Commits, repositories, Spaces and
// everything else need an approval; jobs and Space hardware are pinned to
// one because they are billed, and so is changing a repository's
// visibility or gating. Webhooks, organisation members, roles, SCIM, SSO,
// resource groups, service accounts and their tokens, trusted publishers,
// access requests, repository moves, putting a repository in a resource
// group, Inference Provider keys and billing are refused.
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
      NAMED_READS(
        [
          "/api/whoami-v2",
          "/api/models",
          "/api/datasets",
          "/api/spaces",
          ...perRepo("", "/revision/**", "/tree/**", "/refs", "/commits/*", "/compare/*"),
          "/*/*/resolve/**",
          "/datasets/*/*/resolve/**",
          "/spaces/*/*/resolve/**",
          "/v1/models",
        ],
        "reads of the account, repositories, their files and the router's models",
      ),
      { action: "allow", methods: ["POST"], paths: ["/v1/chat/completions", "/hf-inference/models/**"], note: MODEL_CALLS },
      { action: "allow", methods: ["POST"], paths: ["/api/models/*/*/paths-info/*", "/api/datasets/*/*/paths-info/*", "/api/spaces/*/*/paths-info/*"], note: "looks up file paths in a repository" },
      { action: "approve", methods: ["POST"], paths: ["/api/jobs/*", "/api/spaces/*/*/hardware"], note: "runs billed compute" },
      { action: "approve", methods: WRITES, paths: ["/api/models/*/*/settings", "/api/datasets/*/*/settings", "/api/spaces/*/*/settings"], note: "changes a repository's visibility or gating" },
      {
        action: "approve",
        methods: READS,
        paths: [
          "/api/*/*/*/jwt",
          "/api/*/*/*/xet-read-token/**",
          "/api/*/*/*/xet-write-token/**",
          "/api/registry/token",
          "/api/spaces/*/*/secrets",
          "/api/spaces/*/*/variables",
          "/api/jobs/**",
          "/api/scheduled-jobs/**",
          "/api/settings/webhooks/**",
          "/api/organizations/*/service-accounts/**",
          "/api/organizations/*/settings/tokens/**",
          "/api/organizations/*/audit-log/**",
        ],
        note: "hands back a token, a Space secret or a job's secrets",
      },
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
      { action: "deny", methods: WRITES, paths: ["/api/*/*/*/resource-group"], note: "moves a repository into a resource group, which changes who can reach it" },
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
