// The docs moved to the public docs site: the vault's old /docs addresses
// answer a 301 to the matching page there, signed in or not, and the
// operator runbook it keeps in the repository still names every migration.

import { env } from "cloudflare:workers"
import { describe, expect, it } from "vitest"
import { SESSION_COOKIE, newSession } from "../src/directory/session.ts"
import { accountSessionStatements } from "../src/directory/account-store.ts"
import { DOCS_REDIRECTS, DOCS_SITE } from "../src/routes/ui.ts"
import { DOCS_HOME } from "../src/ui/layout.ts"
import { randomId } from "../src/vault/core.ts"
import operationsGuide from "../../../docs/OPERATIONS.md"
import { fetchWorker } from "./helpers.ts"

async function memberCookie(): Promise<string> {
  const id = randomId("acc"), now = Date.now(), session = await newSession()
  await env.DB.batch([
    env.DB.prepare("INSERT INTO accounts(id,name,created_at) VALUES (?, 'Sam', ?)").bind(id, now),
    ...accountSessionStatements(env, session, id, now, { kind: "web", method: "passkey", passkey: null, client: "Test browser", place: null }),
  ])
  return `${SESSION_COOKIE}=${session.token}`
}

describe("the operations guide", () => {
  // OPERATIONS is the operator's map of the D1 directory: it names every
  // migration that is live and never a staging folder that is gone.
  it("names every D1 migration, under migrations/ only", () => {
    const files = Object.keys(import.meta.glob<string>("../migrations/*.sql", { query: "?raw", import: "default", eager: true })).map((p) => p.slice(p.lastIndexOf("/") + 1))
    expect(files.length).toBeGreaterThan(0)
    for (const file of files) expect(operationsGuide, file).toContain(`\`migrations/${file}\``)
    expect(operationsGuide).not.toContain("migrations-workspaces")
  })
})

describe("the old docs addresses", () => {
  const cases: [path: string, target: string][] = [
    ["/docs", `${DOCS_SITE}/`],
    ["/docs/overview", `${DOCS_SITE}/`],
    ["/docs/concepts", `${DOCS_SITE}/concepts`],
    ["/docs/agent-guide", `${DOCS_SITE}/reference/cli`],
    ["/docs/skill", `${DOCS_SITE}/skill`],
    ["/docs/integrating", `${DOCS_SITE}/guides/harnesses`],
    ["/docs/threat-model", `${DOCS_SITE}/security/threat-model`],
    // Internal now: the runbook and the plan are not published anywhere.
    ["/docs/operations", `${DOCS_SITE}/`],
    ["/docs/plan", `${DOCS_SITE}/`],
    ["/docs/nope", `${DOCS_SITE}/`],
    ["/docs/__proto__", `${DOCS_SITE}/`],
  ]

  it("redirect to the docs site for anyone, never asking to sign in", async () => {
    for (const [path, target] of cases) {
      const res = await fetchWorker(path, { redirect: "manual" })
      expect(res.status, path).toBe(301)
      expect(res.headers.get("location"), path).toBe(target)
    }
  })

  it("redirect the same way for a signed-in account", async () => {
    const cookie = await memberCookie()
    for (const [path, target] of cases) {
      const res = await fetchWorker(path, { headers: { cookie }, redirect: "manual" })
      expect(res.status, path).toBe(301)
      expect(res.headers.get("location"), path).toBe(target)
    }
  })

  it("map only to pages the docs site publishes", () => {
    expect(Object.values(DOCS_REDIRECTS)).toEqual(["/", "/concepts", "/reference/cli", "/skill", "/guides/harnesses", "/security/threat-model"])
    expect(DOCS_HOME).toBe(`${DOCS_SITE}/`)
  })
})
