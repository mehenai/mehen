import path from "node:path"
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin"
import { defineConfig } from "vitest/config"

const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"))

const legacyMigrations = migrations.filter(migration => Number(migration.name.slice(0, 4)) <= 4)

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc", environment: "test" },
      miniflare: { d1Databases: ["WORKSPACE_DB", "MIGRATION_DB"], bindings: { TEST_MIGRATIONS: migrations, TEST_LEGACY_MIGRATIONS: legacyMigrations } },
    }),
  ],
  test: {
    // The UI stylesheets as text for app.css.test.ts: vitest otherwise turns
    // every CSS import, ?raw included, into an empty string.
    css: { include: [/src\/ui\/client\/.*\.css/] },
    include: ["src/**/*.test.ts", "test/**/*.test.ts"],
    setupFiles: ["./test/apply-migrations.ts"],
    // The end-to-end scenarios sign passkeys and device proofs in workerd; on a
    // loaded CI host they have run past vitest's 5 s default without failing.
    testTimeout: 20_000,
  },
})
