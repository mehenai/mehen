// A leased child's stdout and stderr pass through the protocol's streaming
// redactor before they reach the terminal. Redaction catches a value printed
// as is or in common encodings; it cannot catch one a program transforms.

import { StreamRedactor, buildNeedles, type RedactionSecret } from "@mehen/protocol"
import type { Writer } from "./deps.ts"

export async function pipeRedacted(stream: ReadableStream<Uint8Array>, out: Writer, secrets: RedactionSecret[]): Promise<void> {
  const redactor = new StreamRedactor(buildNeedles(secrets))
  const decoder = new TextDecoder()
  const reader = stream.getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    const text = redactor.push(decoder.decode(value, { stream: true }))
    if (text !== "") out.write(text)
  }
  const rest = redactor.push(decoder.decode()) + redactor.end()
  if (rest !== "") out.write(rest)
}
