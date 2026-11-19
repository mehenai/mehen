import { beforeAll, expect, test } from "bun:test"
import { readFile } from "node:fs/promises"
import path from "node:path"
import { type LintContext, checkSite, lintContext, lintMarkdown } from "./check.ts"

const DOCS = path.resolve(import.meta.dir, "..")
const REPO = path.resolve(DOCS, "../..")
const PUBLIC = path.join(DOCS, "public")

let ctx: LintContext
beforeAll(async () => {
  ctx = (await lintContext(PUBLIC, REPO)).ctx
})

const fixture = (name: string) => readFile(path.join(import.meta.dir, "fixtures", name), "utf8")

test("each bad fixture is reported with its reason and line", async () => {
  const cases: [file: string, line: number, reason: string][] = [
    ["bad-command.md", 4, "mehen fetchh is not a command"],
    ["bad-flag.md", 3, "mehen fetch has no flag --selectt"],
    ["bad-error-code.md", 5, "binding_refuse is not an error code"],
    ["bad-tool.md", 3, "vault_fetchh is not an MCP tool"],
    ["bad-variable.md", 3, "MEHEN_CONFIG_DIRR is not a variable mehen reads"],
    ["bad-anchor.md", 3, "https://docs.mehen.dev/reference/errors.md#nope: /reference/errors has no heading #nope"],
    ["bad-internal.md", 3, "says packages/, which is internal"],
    // The global flags the special parsers refuse.
    ["bad-json-run.md", 3, "mehen run does not take --json"],
    ["bad-json-env-set.md", 6, "mehen env set does not take --json"],
    ["bad-no-qr-mcp.md", 3, "mehen mcp does not take --no-qr"],
  ]
  for (const [file, line, reason] of cases) expect(lintMarkdown(await fixture(file), "/fixture", ctx)).toEqual([{ line, reason }])
})

test("a dash from the em or en family is reported", () => {
  // Built here rather than kept in a fixture, so no file in the repository carries one.
  expect(lintMarkdown(`# Dash\n\nA credential vault ${String.fromCharCode(0x2013)} and proxy.\n`, "/fixture", ctx)).toEqual([{ line: 3, reason: "a dash from the em or en family" }])
})

test("commands, flags and codes that exist pass, globals and placeholders included", () => {
  const text = [
    "# Fine",
    "",
    "```sh",
    "mehen --json --workspace acme status",
    "mehen fetch openai-personal GET https://api.openai.com/v1/models -H 'Accept: application/json' --select data.0.id | jq .",
    "mehen run --env dev -- npm test --watch",
    "mehen --workspace acme run --env dev -- node build.js --json",
    "mehen env ls --json",
    "mehen env check --env dev --json",
    "mehen init --slug demo --env dev --json",
    "mehen --json init",
    "mehen mcp --workspace acme",
    "mehen status --no-qr",
    "mehen <command> --help",
    "```",
    "",
    "The vault answers `approval_required`; `vault_fetch` and `mehen wait <id>` follow. `MEHEN_HOME` is the home.",
  ].join("\n")
  expect(lintMarkdown(text, "/fixture", ctx)).toEqual([])
})

test("MEHEN_CONFIG_DIR is named only on the errors page and the changelog", () => {
  const text = "# Retired\n\nThe harness sets `MEHEN_CONFIG_DIR`.\n"
  expect(lintMarkdown(text, "/reference/errors", ctx)).toEqual([])
  expect(lintMarkdown(text, "/reference/cli", ctx)).toEqual([{ line: 3, reason: "MEHEN_CONFIG_DIR is retired; name it only on /changelog and /reference/errors" }])
})

test("mail links: only an address at mehen.dev", () => {
  const text = "# Mail\n\n[a](mailto:security@mehen.dev) [b](mailto:someone@example.com)\n"
  expect(lintMarkdown(text, "/fixture", ctx).map((p) => p.reason)).toEqual(["mailto:someone@example.com is not an address at mehen.dev"])
})

test("links: http, unknown hosts and the app's old docs are refused", () => {
  const text = "# Links\n\n[a](http://docs.mehen.dev/) [b](https://example.com/) [c](https://app.mehen.dev/docs/agent-guide) [d](https://docs.mehen.dev/reference/cli.md#fetch)\n"
  expect(lintMarkdown(text, "/fixture", ctx).map((p) => p.reason)).toEqual(["http://docs.mehen.dev/ is not https", "example.com is not an allowed host", "https://app.mehen.dev/docs/agent-guide: the docs are on https://docs.mehen.dev, not app.mehen.dev/docs"])
})

test("the real site passes", async () => {
  expect(await checkSite(PUBLIC, REPO)).toEqual([])
})

test("the special parsers' refused global flags are reported wherever they sit", () => {
  const text = ["# Refused", "", "```sh", "mehen --no-qr env ls", "mehen run --no-qr -- make", "mehen init --slug demo --no-qr", "mehen --json mcp", "```"].join("\n")
  expect(lintMarkdown(text, "/fixture", ctx).map((p) => p.reason)).toEqual(["mehen env does not take --no-qr", "mehen run does not take --no-qr", "mehen init does not take --no-qr", "mehen mcp does not take --json"])
})
