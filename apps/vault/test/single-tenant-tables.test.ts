// A workspace made before the single-tenant OAuth connects and intakes were
// removed still has their empty tables: its next migration drops them, and
// touches nothing the workspace's own connections and requests keep.
import { expect, it } from "vitest"
import { oauthArea } from "../src/vault/areas/oauth.ts"
import { intakeArea } from "../src/vault/areas/intake.ts"
import { applyMigrations } from "../src/vault/tenant-vault.ts"
import { credentialsFixture, inAccess } from "./credentials-test-support.ts"

const tables = (sql: SqlStorage) => sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('oauth_connects','oauth_connections','oauth_clients','intakes','workspace_oauth_connections','workspace_credential_requests') ORDER BY name").toArray().map((t) => t.name)

it("drops the single-tenant OAuth and intake tables on the next migration, and keeps the workspace's own", async () => {
  const f = await credentialsFixture()
  await inAccess(f.tenant, (ctx) => {
    expect(tables(ctx.sql)).toEqual(["workspace_credential_requests", "workspace_oauth_connections"])
    // As a workspace that ran the migrations before the drop.
    for (const area of [oauthArea, intakeArea]) {
      const kept = area.migrations.slice(0, -1)
      for (const step of kept.slice(0, area.name === "oauth" ? 3 : 4)) ctx.sql.exec(step)
      ctx.sql.exec("UPDATE _migrations SET applied=? WHERE area=?", kept.length, area.name)
    }
    expect(tables(ctx.sql)).toEqual(["intakes", "oauth_clients", "oauth_connections", "oauth_connects", "workspace_credential_requests", "workspace_oauth_connections"])
    applyMigrations(ctx.sql, ctx.storage, [oauthArea, intakeArea])
    expect(tables(ctx.sql)).toEqual(["workspace_credential_requests", "workspace_oauth_connections"])
    expect(ctx.sql.exec<{ area: string; applied: number }>("SELECT area,applied FROM _migrations WHERE area IN ('oauth','intake') ORDER BY area").toArray()).toEqual([{ area: "intake", applied: intakeArea.migrations.length }, { area: "oauth", applied: oauthArea.migrations.length }])
  })
})
