import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { cpSync, existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs"
import path from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { parseArgs } from "../args.ts"
import { CliError } from "../errors.ts"
import { runJv, tempDir } from "../testing/run-mehen.ts"
import { templatesCommand } from "./templates.ts"
import { NEXT_TEST, addKnownPrefixes, exportName, isReservedWord, findRepoRoot, newTemplateInput, registerTemplate, templateSource, writeNewTemplate } from "./templates-new.ts"

const REPO = findRepoRoot(import.meta.dir)
if (REPO === null) throw new Error("these tests run inside the checkout")
const PROTOCOL = path.join("packages", "protocol")

function input(argv: string[]) {
  const args = parseArgs(["new", ...argv], templatesCommand.spec)
  return newTemplateInput(args.positionals[1], args)
}

function refusal(argv: string[]): { code: string; message: string } {
  try {
    input(argv)
  } catch (error) {
    if (error instanceof CliError) return { code: error.code, message: error.message }
    throw error
  }
  throw new Error(`accepted ${argv.join(" ")}`)
}

const BASE = ["acme-widgets", "--host", "api.acme-widgets.com", "--category", "productivity"]

// A copy of the layout the scaffold edits: the root package.json, the
// protocol package with its sources, and links to the installed modules,
// so the protocol's own tests and typecheck run against the copy.
async function layout(): Promise<{ root: string; remove(): Promise<void> }> {
  const dir = await tempDir()
  const root = dir.path
  writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "mehen", private: true }))
  cpSync(path.join(REPO as string, "tsconfig.base.json"), path.join(root, "tsconfig.base.json"))
  mkdirSync(path.join(root, PROTOCOL), { recursive: true })
  for (const file of ["package.json", "tsconfig.json"]) cpSync(path.join(REPO as string, PROTOCOL, file), path.join(root, PROTOCOL, file))
  for (const folder of ["src", "test"]) cpSync(path.join(REPO as string, PROTOCOL, folder), path.join(root, PROTOCOL, folder), { recursive: true })
  symlinkSync(path.join(REPO as string, PROTOCOL, "node_modules"), path.join(root, PROTOCOL, "node_modules"))
  symlinkSync(path.join(REPO as string, "node_modules"), path.join(root, "node_modules"))
  return { root, remove: dir.remove }
}

async function run(cmd: string[], cwd: string): Promise<{ code: number; out: string }> {
  const proc = Bun.spawn(cmd, { cwd, stdout: "pipe", stderr: "pipe", env: { ...process.env } })
  const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  return { code: await proc.exited, out: out + err }
}

describe("mehen templates new: the flags", () => {
  test("takes the safe defaults: Bearer in Authorization, a name from the id, no docs", () => {
    expect(input(BASE)).toEqual({
      id: "acme-widgets",
      hosts: ["api.acme-widgets.com"],
      paths: [],
      header: "Authorization",
      format: "Bearer {key}",
      docsUrl: null,
      displayName: "Acme Widgets API key",
      category: "productivity",
      prefixes: [],
    })
  })

  test("refuses an id that exists, is reserved, or does not match the pattern", () => {
    expect(refusal(["openai", "--host", "api.openai.com", "--category", "ai"]).code).toBe("conflict")
    expect(refusal(["google-gmail", "--host", "gmail.googleapis.com", "--category", "mail"]).code).toBe("conflict")
    for (const id of ["Acme", "1acme", "a", "acme_widgets", "acme.widgets", `a${"b".repeat(41)}`, "acme--widgets", "acme-", "new", "shared", "custom"]) {
      expect({ id, code: refusal([id, "--host", "api.acme.com", "--category", "ai"]).code }).toEqual({ id, code: "usage" })
    }
  })

  test("refuses a host that is not a plain lower-case DNS name", () => {
    for (const host of ["API.acme.com", "*.acme.com", "acme.com:443", "https://acme.com", "acme.com/v1", "10.0.0.1", "[::1]", "acme", "-acme.com", "acme-.com", "api.acme.test", "localhost", "acme..com", "acme.com."]) {
      const { code, message } = refusal(["acme", "--host", host, "--category", "ai"])
      expect({ host, code, plain: message.includes("plain lower-case DNS name") }).toEqual({ host, code: "usage", plain: true })
    }
    expect(refusal(["acme", "--category", "ai"]).message).toContain("--host")
    expect(refusal(["acme", "--host", "api.acme.com", "--host", "api.acme.com", "--category", "ai"]).message).toContain("twice")
  })

  test("refuses a docs URL that is not https on a public host", () => {
    for (const docs of ["http://acme.com/keys", "ftp://acme.com", "acme.com/keys", "https://user:pw@acme.com/keys", "https://acme.com:8443/keys", "https://localhost/keys", "https://10.0.0.1/keys"]) {
      expect({ docs, code: refusal([...BASE, "--docs", docs]).code }).toEqual({ docs, code: "usage" })
    }
    expect(input([...BASE, "--docs", "https://acme.com/settings/api-keys"]).docsUrl).toBe("https://acme.com/settings/api-keys")
  })

  test("refuses a reserved or malformed header, a format without exactly one {key}, and an unknown category", () => {
    for (const header of ["Host", "Cookie", "X-Forwarded-For", "cf-access", "Mehen-Proof", "X Api Key", ""]) expect({ header, code: refusal([...BASE, "--header", header]).code }).toEqual({ header, code: "usage" })
    for (const format of ["Bearer", "{token}", "{key} {key}", "{key} {other}", "Bearer {key}\r\nX: y"]) expect({ format, code: refusal([...BASE, "--format", format]).code }).toEqual({ format, code: "usage" })
    expect(refusal(["acme", "--host", "api.acme.com"]).message).toContain("--category is required")
    expect(refusal(["acme", "--host", "api.acme.com", "--category", "clients"]).code).toBe("usage")
    expect(refusal(["acme", "--host", "api.acme.com", "--category", "toys"]).code).toBe("usage")
  })

  test("refuses a path that is not a plain pattern, and a prefix that is not a short public one", () => {
    for (const p of ["v1/**", "/", "/**", "/v1/../admin", "/v1//x", "/v1/**/x", "/v1/a*", "/v1/%2e%2e"]) expect({ p, code: refusal([...BASE, "--path", p]).code }).toEqual({ p, code: "usage" })
    expect(input([...BASE, "--path", "/v1/**", "--path", "/graphql"]).paths).toEqual(["/v1/**", "/graphql"])
    for (const prefix of ["a", "_acme", "acme key", `${"a".repeat(25)}`]) expect({ prefix, code: refusal([...BASE, "--prefix", prefix]).code }).toEqual({ prefix, code: "usage" })
  })
})

describe("mehen templates new: what it writes", () => {
  test("a template with the defaults, the injection from the flags, and a field pattern from the prefixes", () => {
    const source = templateSource(input([...BASE, "--header", "X-Api-Key", "--format", "{key}", "--prefix", "aw_", "--prefix", "aw.live.", "--docs", "https://acme-widgets.com/keys"]))
    expect(source).toContain("export const acmeWidgets: Template = {")
    expect(source).toContain('policy: { default: "approve", rules: [ALLOW_READS] },')
    expect(source).toContain('ceiling: "placeholder",')
    expect(source).toContain('kind: "api-key",')
    expect(source).toContain('binding: { hosts: ["api.acme-widgets.com"] },')
    expect(source).toContain('injection: { in: "header", name: "X-Api-Key", format: "{key}" },')
    expect(source).toContain('fields: { key: { label: "API key", pattern: "^(aw_|aw\\\\.live\\\\.)" } },')
    expect(source).toContain('prefixes: ["aw_", "aw.live."],')
    expect(templateSource(input(BASE))).toContain("injection: BEARER(),")
  })

  test("registers the import in id order and the entry at the end of TEMPLATES", () => {
    const index = readFileSync(path.join(REPO as string, PROTOCOL, "src", "templates.ts"), "utf8")
    const registered = registerTemplate(index, "acme-widgets").split("\n")
    const importAt = registered.indexOf('import { acmeWidgets } from "./templates/acme-widgets.ts"')
    expect(importAt).toBeGreaterThan(-1)
    expect(registered[importAt + 1]).toBe('import { anthropic } from "./templates/anthropic.ts"')
    const open = registered.indexOf("export const TEMPLATES: Record<string, Template> = {")
    const close = registered.indexOf("}", open)
    expect(registered[close - 1]).toBe('  "acme-widgets": acmeWidgets,')
    expect(registerTemplate(index, "zed").split("\n")).toContain("  zed,")
    expect(() => registerTemplate(index, "connection-policy")).toThrow("already uses")
    expect(() => registerTemplate("export const nothing = 1", "acme")).toThrow("layout")
    expect(exportName("hubspot-private-app")).toBe("hubspotPrivateApp")
  })

  test("never exports under a reserved word: class becomes classTemplate, registered by its id", () => {
    const words = ["break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "enum", "export", "extends", "false", "finally", "for", "function", "if", "import", "in", "instanceof", "new", "null", "return", "super", "switch", "this", "throw", "true", "try", "typeof", "var", "void", "while", "with", "yield", "let", "static", "implements", "interface", "package", "private", "protected", "public", "await", "type", "arguments", "eval"]
    for (const word of words) {
      expect({ word, reserved: isReservedWord(word), name: exportName(word) }).toEqual({ word, reserved: true, name: `${word}Template` })
    }
    expect(exportName("class-act")).toBe("classAct")
    const index = readFileSync(path.join(REPO as string, PROTOCOL, "src", "templates.ts"), "utf8")
    const registered = registerTemplate(index, "class").split("\n")
    expect(registered).toContain('import { classTemplate } from "./templates/class.ts"')
    expect(registered).toContain("  class: classTemplate,")
    expect(templateSource(input(["class", "--host", "api.acme.com", "--category", "productivity"]))).toContain("export const classTemplate: Template = {")
  })

  test("adds only the prefixes the placeholder list lacks", () => {
    const placeholder = readFileSync(path.join(REPO as string, PROTOCOL, "src", "placeholder.ts"), "utf8")
    expect(addKnownPrefixes(placeholder, ["sk-", "npm_"])).toBeNull()
    expect(addKnownPrefixes(placeholder, ["sk-", "aw_"])?.split("\n")).toContain('  "aw_",')
  })
})

describe("mehen templates new: in a copy of the repository", () => {
  let copy: { root: string; remove(): Promise<void> }
  beforeEach(async () => {
    copy = await layout()
  })
  afterEach(async () => copy.remove())

  test("writes a template, its test and its registration that pass the protocol's tests and typecheck", async () => {
    const result = writeNewTemplate(copy.root, input([...BASE, "--path", "/v1/**", "--prefix", "aw_", "--docs", "https://acme-widgets.com/keys"]))
    const reserved = writeNewTemplate(copy.root, input(["class", "--host", "api.class.com", "--category", "productivity"]))
    const dir = path.join(PROTOCOL, "src", "templates")
    expect(result).toEqual({
      id: "acme-widgets",
      template: path.join(dir, "acme-widgets.ts"),
      test: path.join(dir, "acme-widgets.test.ts"),
      index: path.join(PROTOCOL, "src", "templates.ts"),
      placeholder: path.join(PROTOCOL, "src", "placeholder.ts"),
      next: NEXT_TEST,
    })
    const test = readFileSync(path.join(copy.root, result.test), "utf8")
    for (const url of ["https://api.acme-widgets.com/v1/mehen-sample", "https://api.acme-widgets.com.evil.test/v1/mehen-sample", "http://api.acme-widgets.com/v1/mehen-sample", "https://api.acme-widgets.com/mehen-other/route"]) expect(test).toContain(url)
    expect(test).toContain('action: "approve"')
    const tests = await run(["bun", "test", "./packages/protocol/src/templates.test.ts", "./packages/protocol/src/templates-registry.test.ts", "./packages/protocol/src/placeholder.test.ts", `./${result.test}`, `./${reserved.test}`], copy.root)
    expect({ code: tests.code, out: tests.code === 0 ? "" : tests.out }).toEqual({ code: 0, out: "" })
    expect(tests.out).toContain("acme-widgets")
    expect(tests.out).toContain("class.test.ts")
    const tsc = await run(["bunx", "tsc", "-p", PROTOCOL], copy.root)
    expect({ code: tsc.code, out: tsc.out }).toEqual({ code: 0, out: "" })
  }, 120_000)

  test("refuses a second run for the same id and leaves the files as they were", () => {
    writeNewTemplate(copy.root, input(BASE))
    const index = readFileSync(path.join(copy.root, PROTOCOL, "src", "templates.ts"), "utf8")
    expect(() => writeNewTemplate(copy.root, input(BASE))).toThrow("exists already")
    expect(readFileSync(path.join(copy.root, PROTOCOL, "src", "templates.ts"), "utf8")).toBe(index)
  })

  test("runs from any folder in the checkout, prints the files and the next step, and refuses outside one", async () => {
    const nested = path.join(copy.root, PROTOCOL, "src")
    const made = await runJv(["templates", "new", "acme-widgets", "--host", "api.acme-widgets.com", "--category", "productivity"], {}, undefined, nested)
    expect(made.code).toBe(EXIT.ok)
    expect(made.stdout).toContain(`wrote ${path.join(PROTOCOL, "src", "templates", "acme-widgets.ts")}`)
    expect(made.stdout).toContain(`registered acme-widgets in ${path.join(PROTOCOL, "src", "templates.ts")}`)
    expect(made.stdout).toContain(NEXT_TEST)
    expect(existsSync(path.join(copy.root, PROTOCOL, "src", "templates", "acme-widgets.test.ts"))).toBe(true)

    const outside = await tempDir()
    try {
      const refused = await runJv(["templates", "new", "acme", "--host", "api.acme.com", "--category", "ai", "--json"], {}, undefined, outside.path)
      expect(refused.code).toBe(EXIT.error)
      expect(JSON.parse(refused.stdout)).toMatchObject({ error: "not_available" })
      expect(refused.stdout).toContain("checkout of the Mehen repository")
    } finally {
      await outside.remove()
    }
  }, 60_000)

  test("finds the root only where package.json is called mehen", async () => {
    expect(findRepoRoot(path.join(copy.root, PROTOCOL, "src", "templates"))).toBe(copy.root)
    writeFileSync(path.join(copy.root, "package.json"), JSON.stringify({ name: "not-mehen" }))
    expect(findRepoRoot(path.join(copy.root, PROTOCOL))).toBeNull()
  })
})

describe("mehen templates: the flags of new belong to new", () => {
  test("a listing or a lookup with them is a usage error", async () => {
    for (const argv of [["templates", "--host", "api.acme.com"], ["templates", "openai", "--category", "ai"], ["templates", "openai", "anthropic"]]) {
      const result = await runJv([...argv, "--json"], {})
      expect({ argv, code: result.code }).toEqual({ argv, code: EXIT.usage })
    }
  })
})
