import { expect, test } from "bun:test"
import { editJson, editToml, parseJson, tomlRange } from "./formats.ts"

test("JSONC adds and removes just the member, preserving layout, comments and final newline choice", () => {
  for (const newline of ["\n", "\r\n"]) {
    const before = `{${newline}  // Keep this${newline}  "mcpServers": {"other":{"args":["a","b"]}, /* keep */},${newline}  "setting":true${newline}}`
    const added = editJson(before, "mcpServers", { command: "/bin/mehen", args: ["mcp"] }).text
    expect(added.replace(`${newline}    "mehen": {"command":"/bin/mehen","args":["mcp"]},`, "")).toBe(before)
    const changed = added.replace('"setting":true', '"setting":false /* edited */')
    expect(editJson(changed, "mcpServers", undefined).text).toBe(before.replace('"setting":true', '"setting":false /* edited */'))
  }
})
test("JSONC removal does not mistake strings for comments", () => {
  const text = '{"mcpServers":{"other":{},"mehen":{"env":{"URL":"https://vault.example/*path*/"}} /* keep */},"setting":true}'
  const removed = editJson(text, "mcpServers", undefined).text
  expect(removed).toBe('{"mcpServers":{"other":{} /* keep */},"setting":true}')
  expect(parseJson(removed).setting).toBe(true)
})
test("TOML owned range stops at the last key, leaving the next table's comment", () => {
  const before = 'model = "x"\n'
  const table = '[mcp_servers.mehen]\ncommand = "/bin/mehen"\nargs = ["mcp"]\n'
  const suffix = '\n# Notes about docs\n[mcp_servers.docs]\ncommand = "docs"\n'
  const added = editToml(before, table)
  expect(added).toBe(before + "\n" + table)
  const range = tomlRange(added + suffix)!
  expect((added + suffix).slice(range.start, range.end)).toBe(table)
  expect(editToml(added + suffix, null)).toBe(before + "\n" + suffix)
})

test("JSONC removes a first member without dropping the following server or its comment", () => {
  const before = '{"mcpServers":{"mehen":{"command":"/bin/mehen"}, /* other server */ "other":{"args":["x"]}}}'
  const removed = editJson(before, "mcpServers", undefined).text
  expect(removed).toContain('/* other server */')
  expect(parseJson(removed)).toEqual({ mcpServers: { other: { args: ["x"] } } })
})
