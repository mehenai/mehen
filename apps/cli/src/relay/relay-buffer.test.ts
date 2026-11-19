// How mehen run's local relay holds a write's answer before passing it on:
// within one answer's limit and a budget shared by every answer in the
// process, released on every way out; and which answers it streams instead.

import { afterEach, describe, expect, test } from "bun:test"
import net from "node:net"
import { FakeVaultApi, withTimeout } from "../run/fake-vault-api.ts"
import { AnswerBudget, type LocalRelay, startLocalRelay } from "./relay.ts"

const opened: LocalRelay[] = []
afterEach(async () => {
  for (const relay of opened.splice(0)) await relay.close()
})

async function relayWith(api: FakeVaultApi, options: { perAnswer?: number; budget?: AnswerBudget; streamWrites?: boolean } = {}): Promise<LocalRelay> {
  const relay = await startLocalRelay({
    api,
    run: "run_buffer",
    env: "dev",
    interceptHosts: [],
    fencedHosts: [],
    baseUrls: [{ item: "llm", upstream: "https://api.example.test/v1" }],
    ca: null,
    ...(options.perAnswer !== undefined || options.budget !== undefined ? { answerLimits: { perAnswer: options.perAnswer ?? 32 * 1024 * 1024, budget: options.budget ?? new AnswerBudget(128 * 1024 * 1024) } } : {}),
    ...(options.streamWrites ? { streamWrites: true } : {}),
  })
  opened.push(relay)
  return relay
}

// An upstream answer: `first` at once, then `rest` once the gate opens, or
// an error there when `fail` is set.
function gated(first: Uint8Array, rest: Uint8Array, type: string, gate: Promise<void>, fail = false): Response {
  let step = 0
  return new Response(new ReadableStream<Uint8Array>({
    async pull(controller) {
      step++
      if (step === 1) return controller.enqueue(first)
      if (step === 2) {
        await gate
        if (fail) return controller.error(new Error("stream reset"))
        if (rest.length > 0) controller.enqueue(rest)
        return
      }
      controller.close()
    },
  }), { headers: { "Mehen-Upstream": "1", "content-type": type } })
}
function opener(): { gate: Promise<void>; open: () => void } {
  let open = () => {}
  const gate = new Promise<void>((resolve) => { open = resolve })
  return { gate, open }
}
const bytes = (n: number, fill = 0x61): Uint8Array => new Uint8Array(n).fill(fill)
async function settled(budget: AnswerBudget): Promise<void> {
  for (let i = 0; i < 100 && budget.held > 0; i++) await Bun.sleep(10)
}

describe("a write's answer held before it is passed on", () => {
  test("refuses, with a complete 424 and both no-retry headers, the answer that would take the process past its budget, while the others go through whole", async () => {
    const api = new FakeVaultApi(), budget = new AnswerBudget(2500)
    const { gate, open } = opener()
    api.relayHandler = () => gated(bytes(900), bytes(50, 0x62), "application/json", gate)
    const relay = await relayWith(api, { budget })
    const answers = [0, 1, 2].map(() => fetch(`${relay.baseUrl("llm")}/write`, { method: "POST", body: "x" }))
    // Every answer has its first 900 bytes held before any finishes.
    for (let i = 0; i < 100 && api.relayCalls.length < 3; i++) await Bun.sleep(10)
    await Bun.sleep(50)
    open()
    const responses = await withTimeout(Promise.all(answers), 5000, "three writes")
    const statuses = responses.map((r) => r.status).sort()
    expect(statuses).toEqual([200, 200, 424])
    for (const response of responses) {
      if (response.status === 424) {
        expect([response.headers.get("x-should-retry"), response.headers.get("stripe-should-retry")]).toEqual(["false", "false"])
        expect(((await response.json()) as { error: string }).error).toBe("outcome_unknown")
      } else expect((await response.arrayBuffer()).byteLength).toBe(950)
    }
    await settled(budget)
    expect(budget.held).toBe(0)
  })

  test("refuses an answer past its own limit with a complete 424 and releases what it held", async () => {
    const api = new FakeVaultApi(), budget = new AnswerBudget(10_000)
    const { gate, open } = opener()
    open()
    api.relayHandler = () => gated(bytes(600), bytes(600), "application/json", gate)
    const relay = await relayWith(api, { perAnswer: 1000, budget })
    const response = await withTimeout(fetch(`${relay.baseUrl("llm")}/write`, { method: "POST", body: "x" }), 5000, "write")
    expect(response.status).toBe(424)
    expect(((await response.json()) as { error: string }).error).toBe("outcome_unknown")
    await settled(budget)
    expect(budget.held).toBe(0)
  })

  test("releases the budget after an answer that breaks and after a client that leaves while it is held", async () => {
    const api = new FakeVaultApi(), budget = new AnswerBudget(10_000)
    const broken = opener()
    api.relayHandler = () => gated(bytes(500), bytes(0), "application/json", broken.gate, true)
    const relay = await relayWith(api, { budget })
    const answer = fetch(`${relay.baseUrl("llm")}/write`, { method: "POST", body: "x" })
    for (let i = 0; i < 100 && budget.held === 0; i++) await Bun.sleep(10)
    expect(budget.held).toBe(500)
    broken.open()
    expect((await withTimeout(answer, 5000, "broken write")).status).toBe(424)
    await settled(budget)
    expect(budget.held).toBe(0)

    const left = opener()
    api.relayHandler = () => gated(bytes(700), bytes(10), "application/json", left.gate)
    const path = new URL(relay.baseUrl("llm")).pathname
    const socket = net.connect({ host: "127.0.0.1", port: relay.port }, () => socket.write(`POST ${path}/write HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 1\r\n\r\nx`))
    for (let i = 0; i < 100 && budget.held === 0; i++) await Bun.sleep(10)
    expect(budget.held).toBe(700)
    socket.destroy()
    left.open()
    await settled(budget)
    expect(budget.held).toBe(0)
  })
})

describe("answers passed on as they come", () => {
  const STREAMED = [
    "text/event-stream",
    "application/vnd.amazon.eventstream",
    "application/grpc",
    "application/grpc+proto",
    "application/grpc-web",
    "application/grpc-web+proto",
    "application/grpc-web-text",
    "application/grpc-web-text+proto",
  ]
  async function firstChunkBeforeEnd(relay: LocalRelay, api: FakeVaultApi, type: string): Promise<string> {
    const { gate, open } = opener()
    api.relayHandler = () => gated(new TextEncoder().encode("first"), new TextEncoder().encode("rest"), type, gate)
    const response = await withTimeout(fetch(`${relay.baseUrl("llm")}/write`, { method: "POST", body: "x" }), 5000, `${type} head`)
    const reader = response.body!.getReader()
    const first = await withTimeout(reader.read(), 5000, `${type} first chunk`)
    open()
    for (;;) if ((await reader.read()).done) break
    return new TextDecoder().decode(first.value)
  }

  test.each(STREAMED)("streams a write's %s answer: its first chunk reaches the program before the end", async (type) => {
    const api = new FakeVaultApi()
    expect(await firstChunkBeforeEnd(await relayWith(api), api, type)).toBe("first")
  })

  test("streams every write's answer, JSON included, with streamWrites", async () => {
    const api = new FakeVaultApi()
    expect(await firstChunkBeforeEnd(await relayWith(api, { streamWrites: true }), api, "application/json")).toBe("first")
  })

  test("holds a write's JSON answer until its end without streamWrites", async () => {
    const api = new FakeVaultApi()
    const relay = await relayWith(api)
    const { gate, open } = opener()
    api.relayHandler = () => gated(new TextEncoder().encode("first"), new TextEncoder().encode("rest"), "application/json", gate)
    let answered = false
    const response = fetch(`${relay.baseUrl("llm")}/write`, { method: "POST", body: "x" }).then((r) => { answered = true; return r })
    await Bun.sleep(200)
    expect(answered).toBe(false)
    open()
    expect(await (await withTimeout(response, 5000, "json write")).text()).toBe("firstrest")
  })
})
