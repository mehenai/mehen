import { expect, test } from "bun:test"
import { existsSync } from "node:fs"
import path from "node:path"

// The repository's own documents for the people who build and run Mehen
// name files in backticks. A path that no longer exists sends the operator
// to a file that is not there, so each one must resolve from the repository
// root or from the package its section is about.
const REPO_ROOT = path.resolve(import.meta.dir, "../../..")
const DOCUMENTS = ["README.md", "CONTRIBUTING.md", "docs/OPERATIONS.md", "docs/INTEGRATING.md"]
const BASES = ["", "apps/vault", "apps/cli", "apps/docs", "apps/web", "packages/protocol", "packages/client"]
// Named on purpose though absent from a checkout: local secrets files the
// operator makes and build output.
const NOT_IN_A_CHECKOUT = new Set(["apps/vault/.dev.vars.local", "apps/vault/.dev.vars", "apps/cli/dist", "apps/docs/generated"])

function namedPaths(markdown: string): string[] {
  const paths = [...markdown.matchAll(/`((?:apps|packages|tools|docs|skills|src|scripts|migrations|test)\/[A-Za-z0-9_./-]+)`/g)].map((m) => (m[1] as string).replace(/\/$/, ""))
  return [...new Set(paths)]
}

test("namedPaths takes backticked repository paths, not URLs or patterns", () => {
  expect(namedPaths("see `apps/vault/src/index.ts`, `src/ui/` and https://x/apps/y, `src/{a,b}.ts`")).toEqual(["apps/vault/src/index.ts", "src/ui"])
})

test("every file the repository's documents name exists", async () => {
  for (const document of DOCUMENTS) {
    const markdown = await Bun.file(path.join(REPO_ROOT, document)).text()
    const missing = namedPaths(markdown).filter((p) => !NOT_IN_A_CHECKOUT.has(p) && !BASES.some((base) => existsSync(path.join(REPO_ROOT, base, p))))
    expect(missing, document).toEqual([])
  }
})
