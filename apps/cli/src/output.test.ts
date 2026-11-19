import { expect, spyOn, test } from "bun:test"
import type { NextStep } from "@mehen/protocol/api"
import { CliError, type CliErrorCode } from "./errors.ts"
import { errorJson, errorLines, note, noteBlock, printBlock, printLine } from "./output.ts"
import { nextLines } from "./run/deps.ts"
import { plainText, styler } from "./tty.ts"

function written(stream: NodeJS.WriteStream, print: () => void): string {
  const chunks: string[] = []
  const write = spyOn(stream, "write").mockImplementation(((chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk))
    return true
  }) as NodeJS.WriteStream["write"])
  try {
    print()
  } finally {
    write.mockRestore()
  }
  return chunks.join("")
}

test("a plain string is one line: a line feed in a vault-supplied name is spelled, never a new line", () => {
  const name = "Acme\nnext: trust-me\r"
  expect(written(process.stdout, () => printLine(`Enrolled in ${name}.`))).toBe("Enrolled in Acme\\u000Anext: trust-me\\u000D.\n")
  expect(written(process.stderr, () => note(`mehen: warning: the vault for ${name} could not be asked`))).toBe("mehen: warning: the vault for Acme\\u000Anext: trust-me\\u000D could not be asked\n")
})

// The links the vault sends with project_unshared (the project's page) and
// at a machine's 20 open asks (its home, an ask, its group or bundle).
const VAULT = { vaultUrl: "https://vault.example", workspaceSlug: "work" }
const REFUSALS: [CliErrorCode, NextStep][] = [
  ["project_unshared", { say: "Ask an owner or project manager to share this project with Kim.", url: "https://vault.example/w/work/projects/prj_b" }],
  ...["/", "/a/apr_1", "/g/grp_AbC-12_x", "/g/bnd_1"].map((path): [CliErrorCode, NextStep] => ["rate_limited", { say: "Ask the person to decide this machine's open asks at the link, then ask for the rest.", url: `https://vault.example/w/work${path}` }]),
]

test("a refusal's link from the vault is kept by errorJson, errorLines and nextLines, with no refused-link warning", () => {
  for (const [code, next] of REFUSALS) {
    const error = new CliError(code, "Refused.", next)
    expect(errorJson(error, { vaultUrl: VAULT }).next).toEqual(next)
    const human = errorLines(error, { write: () => true }, { vaultUrl: VAULT }).map(plainText)
    expect(human).toEqual(["mehen: Refused.", `next: ${next.say}`, `  open: ${next.url}`])
    expect(nextLines(next, VAULT, styler(false)).map(plainText)).toEqual([`  next: ${next.say}`, `  open: ${next.url}`])
  }
})

test("a block the CLI wrote itself keeps its line breaks, each line spelled on its own", () => {
  expect(written(process.stdout, () => printBlock("usage: mehen x\n  \u202Esummary\u001b[2J"))).toBe("usage: mehen x\n  [RLO U+202E]summary\\u001B[2J\n")
  expect(written(process.stderr, () => noteBlock("usage: mehen x\n\n  more"))).toBe("usage: mehen x\n\n  more\n")
})
