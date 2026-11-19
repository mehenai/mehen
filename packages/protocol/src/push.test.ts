import { describe, expect, test } from "bun:test"
import { PUSH_VIA, PushDestinationSchema, formatPushDestination, parsePushDestination, pushDestinationWords, type PushDestination } from "./push.ts"
import { OAUTH_PROVIDERS, TEMPLATES } from "./templates.ts"

const ACCOUNT = "0123456789abcdef0123456789abcdef"

describe("parsePushDestination", () => {
  test("reads each form into its destination", () => {
    const cases: [string, PushDestination][] = [
      ["github:example/mehen/OPENAI_API_KEY", { provider: "github", owner: "example", repo: "mehen", store: "actions", environment: null, name: "OPENAI_API_KEY" }],
      ["github:example/mehen/env/production/OPENAI_API_KEY", { provider: "github", owner: "example", repo: "mehen", store: "environment", environment: "production", name: "OPENAI_API_KEY" }],
      ["github:example/mehen/dependabot/NPM_TOKEN", { provider: "github", owner: "example", repo: "mehen", store: "dependabot", environment: null, name: "NPM_TOKEN" }],
      ["vercel:my-app/production/OPENAI_API_KEY", { provider: "vercel", project: "my-app", team: null, target: "production", name: "OPENAI_API_KEY" }],
      ["vercel:my-app@acme/preview/OPENAI_API_KEY", { provider: "vercel", project: "my-app", team: "acme", target: "preview", name: "OPENAI_API_KEY" }],
      ["vercel:prj_AbC123@team_XyZ9/development/Key_1", { provider: "vercel", project: "prj_AbC123", team: "team_XyZ9", target: "development", name: "Key_1" }],
      [`cloudflare:${ACCOUNT}/my-worker/OPENAI_API_KEY`, { provider: "cloudflare", account: ACCOUNT, script: "my-worker", name: "OPENAI_API_KEY" }],
      ["fly:my-app/OPENAI_API_KEY", { provider: "fly", app: "my-app", name: "OPENAI_API_KEY" }],
    ]
    for (const [text, destination] of cases) expect(parsePushDestination(text), text).toEqual(destination)
  })

  test("writes the canonical case: owner, repo, environment, project, team, account, script and app lower case, a GitHub name upper case, ids as they are", () => {
    expect(parsePushDestination("GitHub:Example/Mehen/openai_api_key")).toEqual({ provider: "github", owner: "example", repo: "mehen", store: "actions", environment: null, name: "OPENAI_API_KEY" })
    const environment: PushDestination = { provider: "github", owner: "owner", repo: "repo", store: "environment", environment: "production", name: "X" }
    expect(parsePushDestination("github:Owner/Repo/ENV/Production/x")).toEqual(environment)
    expect(parsePushDestination("github:owner/repo/env/production/X")).toEqual(environment)
    expect(parsePushDestination("vercel:My-App@Acme/Production/Key")).toEqual({ provider: "vercel", project: "my-app", team: "acme", target: "production", name: "Key" })
    expect(parsePushDestination(`cloudflare:${ACCOUNT.toUpperCase()}/My-Worker/Key`)).toEqual({ provider: "cloudflare", account: ACCOUNT, script: "my-worker", name: "Key" })
    expect(parsePushDestination("FLY:My-App/Key")).toEqual({ provider: "fly", app: "my-app", name: "Key" })
  })

  test("refuses a GitHub name starting GITHUB_, in any case", () => {
    for (const text of ["github:o/r/GITHUB_TOKEN", "github:o/r/github_token", "github:o/r/env/prod/GitHub_X", "github:o/r/dependabot/GITHUB_"]) expect(parsePushDestination(text), text).toBeNull()
  })

  test("refuses anything that is not ASCII, before any case folding could turn it into ASCII", () => {
    for (const text of [
      "github:o/r/ſECRET", // the long s upper-cases to S
      "github:o/r/ıD", // the dotless i upper-cases to I
      "github:\u212Aey/r/NAME", // the Kelvin sign lower-cases to k
      "github:о/r/NAME", // Cyrillic o
      "vercel:my-app/production/NAMÉ",
      "fly:app\u200b/NAME",
      "github:o/r/NAME\n",
    ]) expect(parsePushDestination(text), JSON.stringify(text)).toBeNull()
  })

  test("refuses a segment that could move the request elsewhere, and every malformed form", () => {
    for (const text of [
      "github:o/../NAME",
      "github:o/./NAME",
      "github:o/r/env/../NAME",
      "github:o/r/env/./NAME",
      "vercel:../production/NAME",
      "vercel:..@acme/production/NAME",
      "github:o/r%2fx/NAME",
      "github:o/r/NAME/extra",
      "github:o/r/secrets/NAME",
      "github:o/r",
      "github:/r/NAME",
      "github:o//NAME",
      "github:o/r/1NAME",
      "github:o/r/NA-ME",
      `github:${"o".repeat(40)}/r/NAME`,
      `github:o/${"r".repeat(101)}/NAME`,
      `github:o/r/${"N".repeat(256)}`,
      "github:o_x/r/NAME",
      "vercel:my-app/staging/NAME",
      "vercel:my-app@/production/NAME",
      "vercel:my app/production/NAME",
      "vercel:my-app/production",
      "cloudflare:0123/my-worker/NAME",
      `cloudflare:${ACCOUNT}/-worker/NAME`,
      `cloudflare:${ACCOUNT}/${"w".repeat(64)}/NAME`,
      `cloudflare:${ACCOUNT}/my.worker/NAME`,
      "fly:my_app/NAME",
      `fly:${"a".repeat(64)}/NAME`,
      "fly:my-app/NAME/x",
      "gitlab:o/r/NAME",
      "github",
      "",
      " github:o/r/NAME",
    ]) expect(parsePushDestination(text), text).toBeNull()
  })
})

describe("formatPushDestination", () => {
  test("round trips every form through the canonical string and the schema", () => {
    for (const text of [
      "github:example/mehen/OPENAI_API_KEY",
      "github:example/mehen.js/env/production-1/OPENAI_API_KEY",
      "github:example/mehen/dependabot/NPM_TOKEN",
      "vercel:my-app/production/OPENAI_API_KEY",
      "vercel:my.app_1@acme-co/preview/openai_key",
      "vercel:prj_AbC123@team_XyZ9/development/KEY",
      `cloudflare:${ACCOUNT}/my_worker-1/OPENAI_API_KEY`,
      "fly:my-app/OPENAI_API_KEY",
    ]) {
      const destination = parsePushDestination(text)
      expect(destination, text).not.toBeNull()
      expect(formatPushDestination(destination!)).toBe(text)
      expect(parsePushDestination(formatPushDestination(destination!))).toEqual(destination)
      expect(PushDestinationSchema.parse(destination)).toEqual(destination!)
    }
  })

  test("a parsed string in another case formats to the canonical one", () => {
    expect(formatPushDestination(parsePushDestination("github:Example/Mehen/env/prod/openai")!)).toBe("github:example/mehen/env/prod/OPENAI")
  })
})

describe("PushDestinationSchema", () => {
  test("takes only a canonical destination, with no extra member", () => {
    const github = { provider: "github", owner: "example", repo: "mehen", store: "actions", environment: null, name: "OPENAI_API_KEY" }
    expect(PushDestinationSchema.safeParse(github).success).toBe(true)
    for (const bad of [
      { ...github, owner: "Example" },
      { ...github, name: "openai_api_key" },
      { ...github, name: "GITHUB_TOKEN" },
      { ...github, environment: "production" },
      { ...github, store: "environment", environment: "Production" },
      { ...github, store: "environment" },
      { ...github, store: "environment", environment: ".." },
      { ...github, repo: ".." },
      { ...github, extra: true },
      { provider: "vercel", project: "My-App", team: null, target: "production", name: "KEY" },
      { provider: "vercel", project: "my-app", target: "production", name: "KEY" },
      { provider: "cloudflare", account: ACCOUNT.toUpperCase(), script: "w", name: "KEY" },
      { provider: "fly", app: "my-app", name: "KEY", host: "evil.example" },
      { provider: "fly", app: "my-app", name: "KÉY" },
    ]) expect(PushDestinationSchema.safeParse(bad).success, JSON.stringify(bad)).toBe(false)
  })
})

describe("pushDestinationWords", () => {
  test("says where the value goes in the card's words", () => {
    const words = (text: string) => pushDestinationWords(parsePushDestination(text)!)
    expect(words("github:example/mehen/OPENAI_API_KEY")).toBe("GitHub example/mehen, Actions secret OPENAI_API_KEY")
    expect(words("github:example/mehen/env/production/OPENAI_API_KEY")).toBe("GitHub example/mehen, environment production, Actions secret OPENAI_API_KEY")
    expect(words("github:example/mehen/dependabot/NPM_TOKEN")).toBe("GitHub example/mehen, Dependabot secret NPM_TOKEN")
    expect(words("vercel:my-app/production/OPENAI_API_KEY")).toBe("Vercel my-app, production variable OPENAI_API_KEY")
    expect(words("vercel:my-app@acme/preview/OPENAI_API_KEY")).toBe("Vercel my-app in team acme, preview variable OPENAI_API_KEY")
    expect(words(`cloudflare:${ACCOUNT}/my-worker/OPENAI_API_KEY`)).toBe(`Cloudflare Worker my-worker in account ${ACCOUNT}, secret OPENAI_API_KEY`)
    expect(words("fly:my-app/OPENAI_API_KEY")).toBe("Fly app my-app, secret OPENAI_API_KEY")
  })
})

describe("PUSH_VIA", () => {
  test("names, for each provider, only templates that exist", () => {
    expect(PUSH_VIA).toEqual({ github: ["github-pat", "github-oauth"], vercel: ["vercel"], cloudflare: ["cloudflare-api-token"], fly: ["fly"] })
    for (const ids of Object.values(PUSH_VIA)) for (const id of ids) expect(TEMPLATES[id] !== undefined || OAUTH_PROVIDERS[id] !== undefined, id).toBe(true)
  })
})
