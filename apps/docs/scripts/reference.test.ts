import { expect, test } from "bun:test"
import { readFile } from "node:fs/promises"
import path from "node:path"
import { REPO_ROOT, platformReference } from "./generate.ts"
import { frontMatter } from "./pages.ts"
import { platformMarkdown, splitEntries } from "./reference.ts"

const PLATFORM_SOURCE = "docs/site/reference/platform.md"
const hand = async () => splitEntries(frontMatter(await readFile(path.join(REPO_ROOT, PLATFORM_SOURCE), "utf8"), PLATFORM_SOURCE).body, PLATFORM_SOURCE)

test("the platform reference has a section for every route, with its method, path, prose and refusals", async () => {
  const platform = platformReference()
  const page = platformMarkdown(await hand(), platform, PLATFORM_SOURCE)
  for (const route of platform.routes) {
    expect(page).toContain(`### \`${route.name}\`\n\n\`\`\`http\n${route.method} ${route.path}\n\`\`\`\n\n${route.prose}`)
    for (const code of route.refusals) expect(page).toContain(`[\`${code}\`](errors.md#${code})`)
  }
  for (const code of platform.commonRefusals) expect(page).toContain(`| [\`${code}\`](errors.md#${code}) |`)
  expect(page).toContain("| `decisionTtlSeconds` | 900 | 60 to 900 |")
})

test("a hand entry that names no route or limit, or a limit without one, fails the build", async () => {
  const source = await hand()
  const platform = platformReference()
  expect(() => platformMarkdown({ ...source, entries: [...source.entries, { key: "subjects.rename", body: "x", line: 1 }] }, platform, PLATFORM_SOURCE)).toThrow("subjects.rename is not a platform route or limit")
  expect(() => platformMarkdown({ ...source, entries: source.entries.filter((e) => e.key !== "subjects") }, platform, PLATFORM_SOURCE)).toThrow("the limit subjects needs")
})

test("a route's hand entry follows its generated facts", async () => {
  const source = await hand()
  const platform = platformReference()
  const page = platformMarkdown({ ...source, entries: [...source.entries.filter((e) => e.key !== "audit.read"), { key: "audit.read", body: "A note for the audit.", line: 1 }] }, platform, PLATFORM_SOURCE)
  const section = page.slice(page.indexOf("### `audit.read`"), page.indexOf("### `workspace.freeze`"))
  expect(section.trimEnd()).toEndWith("A note for the audit.")
})
