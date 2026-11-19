// /signup on a vault with no account yet welcomes its owner; once an account
// exists, the same page speaks of invitations again.
import { applyD1Migrations, createExecutionContext, waitOnExecutionContext } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { expect, it } from "vitest"
import type { Env } from "../src/env.ts"
import worker from "../src/index.ts"
import { resetWorkspaceDatabase } from "./workspace-fixtures.ts"
import { ORIGIN } from "./helpers.ts"

async function signupPage(bindings: Env): Promise<string> {
  const ctx = createExecutionContext()
  const response = await worker.fetch(new Request(`${ORIGIN}/signup`, { headers: { accept: "text/html" } }), bindings, ctx)
  await waitOnExecutionContext(ctx)
  expect(response.status).toBe(200)
  return response.text()
}

it("the first visit welcomes the vault's owner, and later ones do not", async () => {
  const db = env.WORKSPACE_DB
  await resetWorkspaceDatabase(db)
  await applyD1Migrations(db, env.TEST_MIGRATIONS)
  const bindings: Env = { ...env, DB: db }
  const first = await signupPage(bindings)
  expect(first).toContain("Welcome to your vault")
  expect(first).toMatch(/data-region="signup-first-lead">/)
  expect(first).toMatch(/data-region="signup-plain-lead" hidden>/)
  await db.prepare("INSERT INTO accounts (id, name, created_at) VALUES ('acc_firstrun', 'Owner', 0)").run()
  const later = await signupPage(bindings)
  expect(later).toContain("Create your account")
  expect(later).toMatch(/data-region="signup-first-lead" hidden>/)
  expect(later).toMatch(/data-region="signup-plain-lead">/)
})
