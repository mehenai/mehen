import type { D1Migration } from "cloudflare:test"
import type { Env as VaultEnv } from "../src/env.ts"

declare global {
  // Vite's eager import.meta.glob, which vitest compiles; vite itself is not
  // a direct dependency, so its client types are not in scope.
  interface ImportMeta {
    glob<T>(patterns: string | string[], options: { query?: string; import?: string; eager: true }): Record<string, T>
  }
  namespace Cloudflare {
    interface Env extends VaultEnv {
      TEST_MIGRATIONS: D1Migration[]
      TEST_LEGACY_MIGRATIONS: D1Migration[]
      WORKSPACE_DB: D1Database
      MIGRATION_DB: D1Database
    }
    interface GlobalProps {
      mainModule: typeof import("../src/index.ts")
    }
  }
}
