import { expect, spyOn, test } from "bun:test"
import { note, noteBlock, printBlock, printLine } from "./output.ts"

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

test("a block the CLI wrote itself keeps its line breaks, each line spelled on its own", () => {
  expect(written(process.stdout, () => printBlock("usage: mehen x\n  \u202Esummary\u001b[2J"))).toBe("usage: mehen x\n  [RLO U+202E]summary\\u001B[2J\n")
  expect(written(process.stderr, () => noteBlock("usage: mehen x\n\n  more"))).toBe("usage: mehen x\n\n  more\n")
})
