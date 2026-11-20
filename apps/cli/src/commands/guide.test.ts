import { afterEach, beforeEach, expect, test } from "bun:test"
import { EXIT } from "@mehen/protocol/api"
import { runJv, tempDir } from "../testing/run-mehen.ts"
import { GUIDE_TEXT, GUIDE_TOPICS, guideSection } from "./info.ts"

let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path }
})
afterEach(() => dir.remove())

const headings = () => GUIDE_TEXT.split("\n").filter((line) => line.startsWith("## ")).map((line) => line.slice(3))

test("every section of the guide is one topic, and every topic is a section", () => {
  const titles = Object.values(GUIDE_TOPICS)
  expect([...titles].sort()).toEqual([...headings()].sort())
  expect(new Set(titles).size).toBe(titles.length)
  for (const topic of Object.keys(GUIDE_TOPICS)) expect(topic).toMatch(/^[a-z]+(?:-[a-z]+)*$/)
})

test("the guide's head lists every topic for mehen guide <topic>", () => {
  const head = GUIDE_TEXT.slice(0, GUIDE_TEXT.indexOf("\n## "))
  expect(head).toContain("mehen guide <topic>")
  for (const topic of Object.keys(GUIDE_TOPICS)) expect(head).toContain(`\`${topic}\``)
})

test("mehen guide <topic> prints that section alone, and --json carries it with its topic", async () => {
  const approvals = await runJv(["guide", "approvals"], env)
  expect(approvals.code).toBe(EXIT.ok)
  expect(approvals.stdout).toStartWith("## Approvals\n")
  expect(approvals.stdout).toContain("--replaces <apr_id>")
  expect(approvals.stdout).not.toContain("## Asking less")
  expect(approvals.stdout).toBe(`${guideSection("approvals")}\n`)
  const json = await runJv(["guide", "exit-codes", "--json"], env)
  expect(json.code).toBe(EXIT.ok)
  expect(JSON.parse(json.stdout)).toMatchObject({ topic: "exit-codes", guide: guideSection("exit-codes") })
  const whole = await runJv(["guide"], env)
  expect(whole.stdout).toBe(GUIDE_TEXT.endsWith("\n") ? GUIDE_TEXT : `${GUIDE_TEXT}\n`)
})

test("an unknown topic is a usage error naming the topics there are", async () => {
  const result = await runJv(["guide", "nope", "--json"], env)
  expect(result.code).toBe(EXIT.usage)
  const error = JSON.parse(result.stdout) as { error: string; message: string }
  expect(error.error).toBe("usage")
  for (const topic of Object.keys(GUIDE_TOPICS)) expect(error.message).toContain(topic)
})

// What the skill sheet sends an agent to the guide for.
test("the rules the skill moved out are in the guide's topics", () => {
  expect(guideSection("sandbox")).toContain("Codex")
  expect(guideSection("never")).toContain("Never set auth headers")
  expect(guideSection("ask")).toContain("**Needs you in the vault:**")
  expect(guideSection("exit-codes")).toContain("outcome_unknown")
  expect(guideSection("projects")).toContain("mehen init --json")
  expect(guideSection("adopt")).toContain("mehen backup snapshot")
  expect(guideSection("mcp")).toContain("--toolsets all")
  expect(guideSection("mcp")).toContain("MEHEN_MCP_TOOLSETS")
  expect(guideSection("updating")).toContain("Never reinstall over an installed `mehen`")
  // policy-operations.ts ruleEnded: a 409 for a rule that ended asks once.
  expect(guideSection("asking-less")).toContain("A 409 saying the rule ended: send once more, which asks; never loop.")
})
