// Every line an operator script prints crosses this, as every human line
// of the CLI crosses terminalText: the D1 text in it (account and
// workspace names chosen at sign-up, reasons, errors) was written by
// others, so it is spelled out (relay/spelling.ts spellTerminalLine).
import { spellTerminalLine } from "../src/relay/spelling.ts"

export function spelledPrint<T extends { print(line: string): void }>(io: T): T {
  return { ...io, print: (line: string) => io.print(spellTerminalLine(line)) }
}
