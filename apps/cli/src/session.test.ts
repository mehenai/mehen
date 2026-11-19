import { expect, test } from "bun:test"
import { notEnrolled } from "./session.ts"

// An agent whose shell lacks mehen on PATH, or an MCP client with no shell
// at all, gets the enrol command by the binary's absolute path, in the
// shape setup.md gives, and the words to hand it to a human.
test("an unenrolled machine's next step names this binary by its absolute path, with --json and no --name", () => {
  const next = notEnrolled(undefined, "/Users/sam/.local/bin/mehen").next
  expect(next?.command).toBe("/Users/sam/.local/bin/mehen enrol --workspace <slug> --json")
  expect(next?.say).toContain("`/Users/sam/.local/bin/mehen enrol --workspace <slug> --json`")
  expect(next?.say).toContain("If you cannot run commands, ask the human to run this in a terminal and open the link it prints.")
})

test("a path with a space is quoted for the shell, and a run from source names mehen", () => {
  expect(notEnrolled(undefined, "/Users/sam/My Tools/mehen").next?.command).toBe("'/Users/sam/My Tools/mehen' enrol --workspace <slug> --json")
  expect(notEnrolled(undefined, null).next?.command).toBe("mehen enrol --workspace <slug> --json")
})
