import { describe, expect, test } from "bun:test"
import { ENV_NAME_KIND_RULES, ENV_NAME_TEMPLATES, envNameProposal } from "./adopt-names.ts"
import { VarName } from "./api.ts"
import { KINDS } from "./kinds.ts"
import { TEMPLATES } from "./templates.ts"

describe("ENV_NAME_TEMPLATES", () => {
  test("every entry names a real template whose kind matches, and a field of that kind", () => {
    for (const [name, entry] of Object.entries(ENV_NAME_TEMPLATES)) {
      expect(VarName.safeParse(name).success, name).toBe(true)
      const template = TEMPLATES[entry.template]
      expect(template, `${name} -> ${entry.template}`).toBeDefined()
      expect(template!.kind, name).toBe(entry.kind)
      expect(KINDS[entry.kind].fields.map((f) => f.name), name).toContain(entry.field)
    }
  })

  test("every template in the catalogue has a conventional name, and an OAuth client both of its fields", () => {
    const covered = new Map<string, Set<string>>()
    for (const entry of Object.values(ENV_NAME_TEMPLATES)) covered.set(entry.template, (covered.get(entry.template) ?? new Set()).add(entry.field))
    for (const template of Object.values(TEMPLATES)) {
      expect(covered.has(template.id), template.id).toBe(true)
      if (template.kind === "oauth-client") expect([...covered.get(template.id)!].sort(), template.id).toEqual(["client_id", "client_secret"])
    }
  })

  test("the names the spec lists map to their templates", () => {
    const expected: Record<string, string> = {
      OPENAI_API_KEY: "openai",
      ANTHROPIC_API_KEY: "anthropic",
      GITHUB_TOKEN: "github-pat",
      GH_TOKEN: "github-pat",
      CLOUDFLARE_API_TOKEN: "cloudflare-api-token",
      STRIPE_SECRET_KEY: "stripe",
      LINEAR_API_KEY: "linear",
      SLACK_BOT_TOKEN: "slack-bot",
      RESEND_API_KEY: "resend",
      SENTRY_AUTH_TOKEN: "sentry",
      NPM_TOKEN: "npm",
    }
    for (const [name, template] of Object.entries(expected)) expect(envNameProposal(name)?.template, name).toBe(template)
  })
})

describe("kind rules for names without a template", () => {
  test("every rule names a field of its kind", () => {
    for (const rule of ENV_NAME_KIND_RULES) expect(KINDS[rule.kind].fields.map((f) => f.name), rule.rule).toContain(rule.field)
  })

  test("a name proposes the kind and field the spec's source table gives it", () => {
    const expected: [string, string, string][] = [
      ["DATABASE_URL", "database-url", "url"],
      ["REDIS_URL", "database-url", "url"],
      ["BILLING_DATABASE_URL", "database-url", "url"],
      ["PG_DSN", "database-url", "url"],
      ["AWS_SECRET_ACCESS_KEY", "cloud-access-key", "secret_access_key"],
      ["AWS_ACCESS_KEY_ID", "cloud-access-key", "access_key_id"],
      ["R2_SECRET_ACCESS_KEY", "cloud-access-key", "secret_access_key"],
      ["STRIPE_WEBHOOK_SECRET", "hmac-key", "key"],
      ["SLACK_SIGNING_SECRET", "hmac-key", "key"],
      ["SESSION_SECRET", "generic", "value"],
      ["NEXTAUTH_SECRET", "generic", "value"],
      ["JWT_SECRET", "generic", "value"],
      ["DATA_ENCRYPTION_KEY", "generic", "value"],
      ["SMTP_PASSWORD", "smtp-imap", "password"],
      ["SMTP_USER", "smtp-imap", "username"],
      ["SMTP_HOST", "smtp-imap", "host"],
      ["ADMIN_PASSWORD", "generic", "value"],
      ["DEPLOY_SSH_KEY", "ssh-key", "private_key"],
      ["SSH_PRIVATE_KEY", "ssh-key", "private_key"],
      ["GITHUB_APP_PRIVATE_KEY", "file", "content"],
      ["GCP_SERVICE_ACCOUNT_JSON", "google-service-account", "key_json"],
      ["ACME_API_KEY", "api-key", "key"],
      ["ACME_TOKEN", "api-key", "key"],
    ]
    for (const [name, kind, field] of expected) expect(envNameProposal(name), name).toMatchObject({ template: null, kind, field })
  })

  test("public and config names propose nothing", () => {
    for (const name of ["NEXT_PUBLIC_API_KEY", "VITE_STRIPE_KEY", "PUBLIC_TOKEN", "STRIPE_PUBLISHABLE_KEY", "SSH_PUBLIC_KEY", "SENTRY_DSN", "NEXT_PUBLIC_SENTRY_DSN", "LOG_LEVEL", "NODE_ENV", "PORT", "API_URL", "BYPASS"]) {
      expect(envNameProposal(name), name).toBeNull()
    }
  })

  test("a template's own name wins over the broad rules", () => {
    expect(envNameProposal("GITHUB_TOKEN")).toEqual({ template: "github-pat", kind: "api-key", field: "key", rule: "the github-pat variable name" })
    expect(envNameProposal("GOOGLE_CLIENT_SECRET")).toMatchObject({ template: "google-oauth-client", kind: "oauth-client", field: "client_secret" })
  })
})
