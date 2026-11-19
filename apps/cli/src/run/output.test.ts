import { expect, test } from "bun:test"
import { capture } from "./fake-vault-api.ts"
import { pipeRedacted } from "./output.ts"

function streamOf(chunks: (string | Uint8Array)[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk)
      controller.close()
    },
  })
}

const secret = "pg-pass-8f3kQ9zLm2"

test("a leased value split across chunk boundaries is redacted", async () => {
  const out = capture()
  await pipeRedacted(streamOf(["connecting with pg-pa", "ss-8f3k", "Q9zLm2 now\n", "done\n"]), out, [{ label: "DATABASE_PASSWORD", value: secret }])
  expect(out.text()).toBe("connecting with [redacted:DATABASE_PASSWORD] now\ndone\n")
})

test("encoded forms and a multi-byte character split across chunks", async () => {
  const out = capture()
  const encoded = new TextEncoder().encode(`url=${encodeURIComponent(secret)} é`)
  const cut = encoded.length - 1
  await pipeRedacted(streamOf([encoded.slice(0, cut), encoded.slice(cut), `\nb64=${btoa(secret)}\n`]), out, [{ label: "P", value: secret }])
  expect(out.text()).not.toContain(secret)
  expect(out.text()).not.toContain(btoa(secret).slice(0, 16))
  expect(out.text()).toContain("url=[redacted:P] é")
})

test("a value percent-encoded as PHP's rawurlencode writes it, split inside an escape, is redacted", async () => {
  const out = capture()
  const value = "pg pass!(8f3k)*Q9"
  const rawurlencoded = "pg%20pass%21%288f3k%29%2AQ9"
  await pipeRedacted(streamOf([`url=${rawurlencoded.slice(0, 14)}`, `${rawurlencoded.slice(14)} done\n`]), out, [{ label: "P", value }])
  expect(out.text()).toBe("url=[redacted:P] done\n")
})

test("output without secrets passes through unchanged", async () => {
  const out = capture()
  await pipeRedacted(streamOf(["plain ", "output\n"]), out, [])
  expect(out.text()).toBe("plain output\n")
})
