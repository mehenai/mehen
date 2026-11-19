// Every file in templates/ is one template or OAuth provider, named by its
// id and registered in TEMPLATES or OAUTH_PROVIDERS, and every registered
// id has its file: a template written but never registered, or registered
// from somewhere else, fails here.

import { describe, expect, it } from "bun:test"
import { readdirSync } from "node:fs"
import path from "node:path"
import { OAUTH_PROVIDERS, TEMPLATES } from "./templates.ts"

const DIR = path.join(import.meta.dir, "templates")
const SHARED = "shared.ts"
const entries = readdirSync(DIR)
const sources = entries.filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts") && f !== SHARED)
const ids = sources.map((f) => f.slice(0, -".ts".length))

describe("the templates folder and the index", () => {
  it("holds only TypeScript files, the shared helpers among them", () => {
    expect(entries.filter((f) => !f.endsWith(".ts"))).toEqual([])
    expect(entries).toContain(SHARED)
  })

  it("names every file by a template id", () => {
    for (const id of ids) expect({ id, valid: /^[a-z][a-z0-9-]{1,40}$/.test(id) }).toEqual({ id, valid: true })
  })

  it("registers every file's one export under its own id, as the same object", async () => {
    for (const id of ids) {
      const module = (await import(path.join(DIR, `${id}.ts`))) as Record<string, unknown>
      const exported = Object.values(module)
      expect({ id, exports: exported.length }).toEqual({ id, exports: 1 })
      const registered = Object.hasOwn(TEMPLATES, id) ? TEMPLATES[id] : Object.hasOwn(OAUTH_PROVIDERS, id) ? OAUTH_PROVIDERS[id] : undefined
      expect({ id, registered: registered !== undefined }).toEqual({ id, registered: true })
      expect({ id, same: exported[0] === registered }).toEqual({ id, same: true })
    }
  })

  it("has a file for every registered template and provider", () => {
    for (const id of [...Object.keys(TEMPLATES), ...Object.keys(OAUTH_PROVIDERS)]) expect({ id, file: ids.includes(id) }).toEqual({ id, file: true })
    expect(ids.length).toBe(Object.keys(TEMPLATES).length + Object.keys(OAUTH_PROVIDERS).length)
  })

  it("keeps a template's own test beside its file", () => {
    const tests = entries.filter((f) => f.endsWith(".test.ts")).map((f) => f.slice(0, -".test.ts".length))
    for (const id of tests) expect({ test: id, file: ids.includes(id) }).toEqual({ test: id, file: true })
  })
})
