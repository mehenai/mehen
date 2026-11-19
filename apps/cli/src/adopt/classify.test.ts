import { describe, expect, it } from "bun:test"
import { classify } from "./classify.ts"

const env = (variable: string, value: string | null) => classify({ type: "dotenv", variable, pointer: null, value })
const pick = (c: ReturnType<typeof classify>) => ({ class: c.class, kind: c.kind, provider: c.provider, field: c.field })

describe("classify", () => {
  it("names a provider by its variable name, or by its key's prefix", () => {
    expect(pick(env("OPENAI_API_KEY", "anything-at-all"))).toEqual({ class: "secret", kind: "api-key", provider: "openai", field: "key" })
    const byPrefix = env("MY_KEY_FOR_LLM", "sk-ant-api03-abcdefghijklmnop")
    expect(pick(byPrefix)).toEqual({ class: "secret", kind: "api-key", provider: "anthropic", field: "key" })
    expect(byPrefix.reason).toBe('"sk-ant-api03-" prefix')
  })

  // Seen on a real machine: a WorkOS key (sk_test_) became a Stripe item and
  // a gateway key (sk-) an OpenAI one, so mehen run would relay each only to
  // the wrong service.
  it("names a provider by a prefix other services share only when the name agrees", () => {
    const none = { class: "secret", kind: "api-key", provider: null, field: "key" } as const
    expect(pick(env("WORKOS_API_KEY", `sk_test_${"a".repeat(60)}`))).toEqual(none)
    expect(pick(env("CLERK_SECRET_KEY", `sk_live_${"a".repeat(40)}`))).toEqual({ ...none, kind: "generic", field: "value" })
    expect(pick(env("ALT_GATEWAY_API_KEY", `sk-${"a".repeat(17)}`))).toEqual(none)
    expect(pick(env("LITELLM_MASTER_KEY", `sk-${"a".repeat(30)}`))).toEqual({ ...none, kind: "generic", field: "value" })
    expect(pick(env("org__abc123_OPENAI_API_KEY", `sk-${"a".repeat(40)}`)).provider).toBe("openai")
    expect(pick(env("STRIPE_KEY", `sk_live_${"a".repeat(40)}`)).provider).toBe("stripe")
    expect(pick(env("API_KEY", `sk_test_${"a".repeat(40)}`)).provider).toBe("stripe")
    expect(pick(env("OPENAI", `sk-proj-${"a".repeat(40)}`)).provider).toBe("openai")
    expect(pick(env("MY_GATEWAY_KEY", `sk-proj-${"a".repeat(40)}`)).provider).toBe("openai")
    expect(pick(env("MY_KEY_FOR_LLM", `sk-ant-api03-${"a".repeat(20)}`)).provider).toBe("anthropic")
  })

  it("says why without carrying the value", () => {
    const value = "postgres://user:hunter2-hunter2@db.example:5432/app"
    const c = env("PRIMARY", value)
    expect(pick(c)).toEqual({ class: "secret", kind: "database-url", provider: null, field: "url" })
    expect(c.reason).toBe("URL with a password")
    expect(JSON.stringify(c)).not.toContain("hunter2")
  })

  it("knows PEM blocks and service account keys", () => {
    expect(pick(env("DEPLOY_KEY", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"))).toMatchObject({ kind: "ssh-key", field: "private_key" })
    expect(pick(env("TLS", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"))).toMatchObject({ kind: "file", field: "content" })
    expect(pick(env("GCP", JSON.stringify({ type: "service_account" })))).toMatchObject({ kind: "google-service-account", field: "key_json" })
  })

  it("treats public names, URLs without a password, flags and numbers as config", () => {
    expect(env("NEXT_PUBLIC_API_KEY", "pk_live_abcdefghijklmnopqrstuvwx").class).toBe("config")
    expect(env("API_BASE_URL", "https://api.example.com/v1").class).toBe("config")
    expect(env("LOG_LEVEL", "debug").class).toBe("config")
    // Seen on a real machine: infrastructure settings read as unknown and left as gaps.
    for (const [name, value] of [["TALOS_VERSION", "v1.9.4"], ["ORG_DOMAIN", "example.com"], ["APP_R2_BUCKET", "app-files"], ["SUPPORT_FROM_EMAIL", "help@example.com"], ["CONTROL_PLANE_IPS", "10.0.0.1,10.0.0.2"], ["ADMIN_SOURCE_CIDRS", "192.0.2.0/24"], ["GCP_KMS_KEYRING", "prod-ring"], ["PROVIDER", "scaleway"], ["OUT", "203.0.113.7"], ["ANY", "sam@example.com"]] as const) expect([name, env(name, value).class]).toEqual([name, "config"])
    // A secret signal still wins over a config name.
    expect(env("ORG_DOMAIN", "sk-proj-0123456789abcdefghijklmnop").class).toBe("secret")
    expect(env("FEATURE_X", "true").class).toBe("config")
    expect(env("WORKERS", "4").class).toBe("config")
    expect(env("GREETING", "hello there").class).toBe("unknown")
  })

  // Seen on a real machine: price, template and org ids, site keys, model
  // names and a KMS key's resource name were planned as secrets.
  it("treats ids, site keys and model names as config by name, and a KMS key name by its shape, unless the value has a secret's shape", () => {
    const random = "Zx9qW2vB7nK4mL8pR3tY6uI1oA5sD0fG"
    for (const [name, value] of [
      ["STRIPE_PRO_MONTHLY_PRICE_ID", "price_1Q2w3E4r5T6y7U8i9O0pAsDf"],
      ["BASIC_TEMPLATE_ID", random],
      ["NORTHWIND_ORG_ID", "org_2a9Xk3Lq7Vb1Zt8Pw4Ny6Mr0"],
      ["ORGANISATION_ID", random],
      ["ORGANIZATION_ID", random],
      ["BROWSERBASE_PROJECT_ID", "8f3c2a1e-7b6d-4c5e-9a0f-1b2c3d4e5f60"],
      ["RECAPTCHA_SITE_KEY", "6LcX9qWAAAAAAB7nK4mL8pR3tY6uI1oA5sD0fGhJ"],
      ["RECAPTCHA_SITE_KEY_V2", "6LdZx9qWAAAAAK4mL8pR3tY6uI1oA5sD0fGhJkLz"],
      ["OPENAI_MODEL", "gpt-4o-2024-08-06-ft-abc123def456ghi789"],
      ["LITELLM_ANTHROPIC_MODEL_HAIKU_4_5", "claude-haiku-4-5-20251001-Zx9qW2vB7nK4mL8p"],
      ["GCP_KMS_KEY", "projects/acme-prod-7f3a9c/locations/europe-west4/keyRings/app-ring/cryptoKeys/Zx9qW2vB7nK4mL8pR3tY6uI1"],
    ] as const) {
      expect([name, env(name, value).class]).toEqual([name, "config"])
    }
    // Before the name rules, each of these looked like a secret.
    expect(env("BASIC_TEMPLATE_THING", random).class).toBe("secret")
    expect(env("KMS_KEY_NAME_FOR", "projects/acme-prod-7f3a9c/locations/europe-west4/keyRings/app-ring/cryptoKeys/Zx9qW2vB7nK4mL8pR3tY6uI1").class).toBe("config")
    // A secret's own shape wins over a config name.
    for (const [name, value] of [
      ["STRIPE_PRO_PRICE_ID", "sk_live_0123456789abcdefghijkl"],
      ["OPENAI_MODEL", "sk-proj-0123456789abcdefghijklmnop"],
      ["GH_ORG_ID", "ghp_0123456789abcdefghijklmnopqrstuvwxyz"],
      ["SLACK_PROJECT_ID", "xoxb-1234567890-abcdefghijklmnop"],
      ["AWS_SITE_KEY", "AKIAABCDEFGHIJKLMNOP0123"],
      ["TLS_TEMPLATE_ID", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"],
      ["DB_MODEL_URL", "postgres://user:hunter2-hunter2@db.example:5432/app"],
    ] as const) {
      expect([name, env(name, value).class]).toEqual([name, "secret"])
    }
    // A secret's name wins over an id or model name; only a site key stays config.
    for (const [name, value] of [
      ["LLM_MODEL_PASSWORD", "Winter2026!"],
      ["AZURE_OPENAI_MODEL_KEY", "0123456789abcdef0123456789abcdef"],
      ["HF_MODEL_SECRET", "hf-short-1"],
      ["X_MODEL_API_KEY", "short-key"],
      ["STRIPE_PROJECT_ID_TOKEN", "tok-short"],
    ] as const) {
      expect([name, env(name, value).class]).toEqual([name, "secret"])
    }
    const json = (pointer: string, value: string) => classify({ type: "json", variable: null, pointer, value }).class
    expect(json("/llm/llmModelPassword", "Winter2026!")).not.toBe("config")
    expect(json("/billing/stripeProMonthlyPriceId", "price_1Q2w3E4r5T6y7U8i9O0pAsDf")).toBe("config")
    for (const [name, value] of [
      ["STRIPE_PRO_MONTHLY_PRICE_ID", "price_1ABCdefGHIjklMNOpqrSTUvwx"],
      ["LITELLM_ANTHROPIC_MODEL_HAIKU_4_5", "claude-haiku-4-5"],
    ] as const) {
      expect([name, env(name, value).class]).toEqual([name, "config"])
    }
    // A client id is still half of an OAuth client.
    expect(pick(env("GOOGLE_CLIENT_ID", "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com"))).toMatchObject({ class: "secret", kind: "oauth-client", field: "client_id" })
  })

  it("marks a Stripe live secret or restricted key as live by its shape, and nothing else", () => {
    for (const [name, value] of [["STRIPE_SECRET_KEY", "sk_live_0123456789abcdefghijkl"], ["STRIPE_RESTRICTED_KEY", "rk_live_0123456789abcdefghijkl"], ["BILLING", "sk_live_0123456789abcdefghijkl"]] as const) {
      expect([name, env(name, value).liveKey]).toEqual([name, true])
    }
    for (const [name, value] of [
      ["STRIPE_SECRET_KEY", "sk_test_0123456789abcdefghijkl"],
      ["STRIPE_RESTRICTED_KEY", "rk_test_0123456789abcdefghijkl"],
      ["STRIPE_WEBHOOK_SECRET", "whsec_0123456789abcdefghijklmnop"],
      ["STRIPE_SECRET_KEY", "sk_live_"],
      ["NEXT_PUBLIC_STRIPE_KEY", "pk_live_0123456789abcdefghijkl"],
      ["OPENAI_API_KEY", "sk-proj-0123456789abcdefghijklmnop"],
    ] as const) {
      expect([name, value, env(name, value).liveKey]).toEqual([name, value, false])
    }
    expect(JSON.stringify(env("STRIPE_SECRET_KEY", "sk_live_0123456789abcdefghijkl"))).not.toContain("0123456789")
  })

  // Seen on a real machine: TEMPLATE_ORDERING planned as a secret.
  it("treats an ordering as config unless the value has a secret's shape", () => {
    for (const [name, value] of [
      ["TEMPLATE_ORDERING", "tpl_9fK2xQ7mLp3Rz8Vb,tpl_4Hn6Wc1Ys5Ue0Jd,tpl_7Gt2Mv8Kq1Xs4Pb"],
      ["TEMPLATE_ORDERING", "Zx9qW2vB7nK4mL8pR3tY6uI1oA5sD0fG"],
      ["MENU_ORDER", "Zx9qW2vB7nK4mL8pR3tY6uI1oA5sD0fG"],
    ] as const) {
      expect([name, env(name, value).class]).toEqual([name, "config"])
    }
    expect(env("TEMPLATE_ORDERING", "sk_live_0123456789abcdefghijkl").class).toBe("secret")
    expect(env("TEMPLATE_ORDERING_SECRET", "Zx9qW2vB7nK4mL8pR3tY6uI1oA5sD0fG").class).toBe("secret")
  })

  // Seen on a real machine: a Firebase web app's API key planned as a secret.
  it("stores a Firebase web key as a generic secret only when the name says Firebase, and keeps Firebase admin keys secret", () => {
    const web = "AIzaSyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tUvW"
    for (const name of ["FIREBASE_WEB_API_KEY", "VITE_FIREBASE_API_KEY", "APP_FIREBASE_API_KEY", "NEXT_PUBLIC_FIREBASE_API_KEY"]) {
      const c = env(name, web)
      expect([name, pick(c), c.reason]).toEqual([name, { class: "secret", kind: "generic", provider: null, field: "value" }, "a Firebase web key is public by design, stored as a generic secret so mehen run delivers it"])
    }
    expect(pick(env("GOOGLE_API_KEY", web))).toEqual({ class: "secret", kind: "api-key", provider: "google-gemini", field: "key" })
    expect(env("FIREBASE_WEB_API_KEY", "sk-proj-0123456789abcdefghijklmnop").class).toBe("secret")
    expect(pick(env("FIREBASE_ADMIN_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"))).toMatchObject({ class: "secret", kind: "file" })
    expect(env("FIREBASE_ADMIN_PRIVATE_KEY", web).class).toBe("secret")
    expect(pick(env("FIREBASE_SERVICE_ACCOUNT", JSON.stringify({ type: "service_account" })))).toMatchObject({ class: "secret", kind: "google-service-account" })
    expect(env("FIREBASE_SERVICE_ACCOUNT", web).class).toBe("secret")
  })

  it("treats a settings key that names a variable or a file as config, and a service's PATH and HOME", () => {
    const json = (pointer: string, value: string) => classify({ type: "json", variable: null, pointer, value }).class
    expect(json("/app/slack/botTokenEnv", "SLACK_BOT_TOKEN")).toBe("config")
    expect(json("/app/mobile/tokenEnvFile", "/Users/sam/.config/app/mobile.env")).toBe("config")
    expect(json("/app/telegram/tokenFile", "/Users/sam/.config/app/token")).toBe("config")
    expect(json("/app/slack/botToken", "xoxb-1234567890-abcdefghijklmnop")).toBe("secret")
    expect(json("/app/slack/botTokenEnv", "Zx9qW2vB7nK4mL8pR3tY6uI1oA5sD0fG")).toBe("secret")
    expect(classify({ type: "plist", variable: "PATH", pointer: null, value: "/opt/homebrew/bin:/usr/bin:/bin" }).class).toBe("config")
    expect(classify({ type: "plist", variable: "HOME", pointer: null, value: "/Users/sam" }).class).toBe("config")
  })

  it("puts both halves of an AWS pair in one kind, the id public", () => {
    expect(pick(env("AWS_ACCESS_KEY_ID", "AKIAABCDEFGHIJKLMNOP"))).toEqual({ class: "secret", kind: "cloud-access-key", provider: null, field: "access_key_id" })
    expect(pick(env("AWS_SECRET_ACCESS_KEY", "abc/def+ghijklmnopqrstuvwxyz0123456789ABCD"))).toEqual({ class: "secret", kind: "cloud-access-key", provider: null, field: "secret_access_key" })
  })

  it("follows decision 8 for login state", () => {
    const kube = classify({ type: "kubeconfig", variable: null, pointer: "", value: "apiVersion: v1" })
    expect([kube.kind, kube.status, kube.storeOnly !== null]).toEqual(["file", "new", true])
  })

  // Adopt reconcile: a gh login and Google tokens are connections made once,
  // never secrets; gcloud ADC and wrangler join them with no provider.
  it("makes the gh login, Google OAuth tokens, gcloud ADC and wrangler connectors, never secrets to upload", () => {
    const connector = (c: ReturnType<typeof classify>) => [c.status, c.kind, c.provider, c.field]
    expect(connector(classify({ type: "gh-hosts", variable: null, pointer: "/github.com/oauth_token", value: "gho_abcdefghijklmnop" }))).toEqual(["connector", "oauth-connection", "github-oauth", null])
    const gcloud = classify({ type: "gcloud-adc", variable: null, pointer: "", value: "{}" })
    expect([...connector(gcloud), gcloud.why]).toEqual(["connector", null, null, null, "gcloud ADC is skipped (decision 8); it needs a re-auth anyway"])
    const wrangler = classify({ type: "wrangler", variable: null, pointer: "/oauth_token", value: "x" })
    expect([...connector(wrangler), wrangler.why]).toEqual(["connector", null, null, null, "wrangler OAuth tokens rotate (decision 8); adopt a cloudflare-api-token instead"])
    const refresh = "1//0gSENTINELrefresh0123456789abcdefghijklmnop"
    expect(connector(env("GMAIL_REFRESH_TOKEN", refresh))).toEqual(["connector", "oauth-connection", "google-gmail", null])
    expect(connector(env("GOOGLE_CALENDAR_REFRESH_TOKEN", "opaque-refresh-token-value"))).toEqual(["connector", "oauth-connection", "google-calendar", null])
    expect(connector(env("DRIVE_TOKEN", "ya29.a0SENTINELaccess0123456789abcdef"))).toEqual(["connector", "oauth-connection", "google-drive", null])
    expect(connector(classify({ type: "json", variable: null, pointer: "/google/gmailRefreshToken", value: refresh }))).toEqual(["connector", "oauth-connection", "google-gmail", null])
    // A Google token whose name says no service gets no provider, never a guess.
    const unsaid = env("GOOGLE_REFRESH_TOKEN", refresh)
    expect([...connector(unsaid), unsaid.why]).toEqual(["connector", "oauth-connection", null, null, "a Google OAuth token for a service its name does not say: connect the Google service it uses; the vault never imports a token"])
    expect(connector(env("TOKEN", refresh))).toEqual(["connector", "oauth-connection", null, null])
    // Another provider's refresh token, and the Google OAuth client pair, are as before.
    expect(pick(env("XERO_REFRESH_TOKEN", "opaque-refresh-token-value"))).toEqual({ class: "secret", kind: "api-key", provider: null, field: "key" })
    expect(pick(env("GOOGLE_CLIENT_SECRET", "GOCSPX-abcdefghijklmnopqrstuvwxyz12"))).toMatchObject({ class: "secret", kind: "oauth-client", provider: "google-oauth-client", field: "client_secret" })
  })

  it("reports a dynamic line and an empty value without adopting them", () => {
    expect(env("TOKEN", null).status).toBe("dynamic")
    expect(env("TOKEN", "").status).toBe("skipped")
  })
})
