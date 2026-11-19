import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import toolsList from "../fixtures/tools-list.json"
import { MCP_PROTOCOL_VERSION } from "../../mcp.ts"
import { VERSION } from "../../version.ts"
import { TOOLS } from "../registry.ts"
import { jsonLines, runJv, tempDir } from "../../testing/run-mehen.ts"
import { ADOPT_CARD_URI, ASK_CARD_URI, CARD_FOR_TOOL, CARD_MIME_TYPE, MCP_APPS_EXTENSION, appsNegotiated, readCard } from "./cards.ts"
import { ADOPT_CARD_HTML, ASK_CARD_HTML, CARD_CSP, inlineScript } from "./documents.ts"

let dir: Awaited<ReturnType<typeof tempDir>>
let env: Record<string, string>
beforeEach(async () => {
  dir = await tempDir()
  env = { MEHEN_CONFIG_DIR: dir.path }
})
afterEach(() => dir.remove())

const UI = { extensions: { [MCP_APPS_EXTENSION]: { mimeTypes: [CARD_MIME_TYPE] } } }

type Reply = { jsonrpc: "2.0"; id: number; result?: Record<string, unknown>; error?: { code: number; message: string } }

// One server, the host's initialize first, then each request; replies by id.
async function session(capabilities: Record<string, unknown> | null, requests: { method: string; params?: unknown }[]): Promise<{ replies: Map<number, Reply>; stdout: string }> {
  const lines = [
    ...(capabilities ? [JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: MCP_PROTOCOL_VERSION, capabilities, clientInfo: { name: "host", version: "1" } } })] : []),
    ...requests.map((r, i) => JSON.stringify({ jsonrpc: "2.0", id: i + 1, method: r.method, ...(r.params === undefined ? {} : { params: r.params }) })),
  ]
  const run = await runJv(["mcp"], env, `${lines.join("\n")}\n`)
  expect(run.code).toBe(0)
  expect(run.stderr).toBe("")
  return { replies: new Map(jsonLines(run.stdout).map((m) => [(m as Reply).id, m as Reply])), stdout: run.stdout }
}

describe("negotiation", () => {
  test("the extension counts when it is named, with the card's mime type or none", () => {
    expect(appsNegotiated({ capabilities: UI })).toBe(true)
    expect(appsNegotiated({ capabilities: { extensions: { [MCP_APPS_EXTENSION]: {} } } })).toBe(true)
    expect(appsNegotiated({ capabilities: { extensions: { [MCP_APPS_EXTENSION]: { mimeTypes: ["text/html", CARD_MIME_TYPE] } } } })).toBe(true)
    expect(appsNegotiated({ capabilities: { extensions: { [MCP_APPS_EXTENSION]: { mimeTypes: ["text/html"] } } } })).toBe(false)
    expect(appsNegotiated({ capabilities: { extensions: { [MCP_APPS_EXTENSION]: { mimeTypes: CARD_MIME_TYPE } } } })).toBe(false)
    expect(appsNegotiated({ capabilities: { extensions: { [MCP_APPS_EXTENSION]: true } } })).toBe(false)
    expect(appsNegotiated({ capabilities: { extensions: {} } })).toBe(false)
    expect(appsNegotiated({ capabilities: {} })).toBe(false)
    expect(appsNegotiated({})).toBe(false)
  })

  test("a host that did not negotiate MCP Apps gets exactly what it got before the cards", async () => {
    for (const capabilities of [{}, { extensions: { [MCP_APPS_EXTENSION]: { mimeTypes: ["text/html"] } } }]) {
      const { replies, stdout } = await session(capabilities, [{ method: "tools/list" }, { method: "resources/list" }, { method: "resources/templates/list" }])
      const init = replies.get(0)?.result as Record<string, unknown>
      expect(init).toEqual({ protocolVersion: MCP_PROTOCOL_VERSION, capabilities: { tools: { listChanged: false } }, serverInfo: { name: "mehen", title: "Mehen", version: VERSION }, instructions: init.instructions })
      // Byte for byte, the captured list (mcp-tools-list.test.ts pins it without an initialize).
      expect(stdout).toContain(`${JSON.stringify({ jsonrpc: "2.0", id: 1, result: toolsList })}\n`)
      expect(replies.get(2)?.error?.code).toBe(-32601)
      expect(replies.get(3)?.error?.code).toBe(-32601)
    }
  })

  test("a host that negotiated gets the resources capability, the linked tools, the app-only tool and the two cards", async () => {
    const { replies } = await session(UI, [{ method: "tools/list" }, { method: "resources/list" }, { method: "resources/templates/list" }])
    expect(replies.get(0)?.result?.capabilities).toEqual({ tools: { listChanged: false }, resources: {} })
    const tools = replies.get(1)?.result?.tools as { name: string; description: string; inputSchema: unknown; _meta?: unknown }[]
    // The same tools in the same order, each unchanged but for the card it names.
    expect(tools.slice(0, toolsList.tools.length).map(({ _meta, ...tool }) => tool)).toEqual(toolsList.tools)
    const linked = Object.fromEntries(tools.filter((t) => t._meta).map((t) => [t.name, t._meta]))
    expect(linked).toEqual({
      vault_request: { ui: { resourceUri: ASK_CARD_URI } },
      vault_connect: { ui: { resourceUri: ASK_CARD_URI } },
      vault_pending: { ui: { resourceUri: ASK_CARD_URI } },
      vault_policy: { ui: { resourceUri: ASK_CARD_URI } },
      vault_adopt_scan: { ui: { resourceUri: ADOPT_CARD_URI } },
      vault_adopt_status: { ui: { resourceUri: ADOPT_CARD_URI } },
      vault_ask_state: { ui: { visibility: ["app"] } },
    })
    expect(tools.slice(toolsList.tools.length).map((t) => t.name)).toEqual(["vault_ask_state"])
    expect(replies.get(2)?.result).toEqual({
      resources: [
        { uri: ASK_CARD_URI, name: "mehen-ask-card", description: expect.any(String), mimeType: CARD_MIME_TYPE },
        { uri: ADOPT_CARD_URI, name: "mehen-adopt-card", description: expect.any(String), mimeType: CARD_MIME_TYPE },
      ],
    })
    expect(replies.get(3)?.result).toEqual({ resourceTemplates: [] })
  })

  test("resources/read serves each card whatever was negotiated, and an unknown uri is Resource not found", async () => {
    for (const capabilities of [null, UI]) {
      const { replies } = await session(capabilities, [
        { method: "resources/read", params: { uri: ASK_CARD_URI } },
        { method: "resources/read", params: { uri: ADOPT_CARD_URI } },
        { method: "resources/read", params: { uri: "ui://mehen/other.html" } },
        { method: "resources/read", params: {} },
        { method: "prompts/list" },
      ])
      expect(replies.get(1)?.result).toEqual({ contents: [{ uri: ASK_CARD_URI, mimeType: CARD_MIME_TYPE, text: ASK_CARD_HTML, _meta: { ui: { prefersBorder: false } } }] })
      expect(replies.get(2)?.result).toEqual({ contents: [{ uri: ADOPT_CARD_URI, mimeType: CARD_MIME_TYPE, text: ADOPT_CARD_HTML, _meta: { ui: { prefersBorder: false } } }] })
      expect(replies.get(3)?.error).toEqual({ code: -32002, message: "Resource not found" })
      expect(replies.get(4)?.error?.code).toBe(-32602)
      expect(replies.get(5)?.error?.code).toBe(-32601)
    }
  })
})

describe("the cards", () => {
  test("every linked tool is a tool, and the linking lives only in the card map", () => {
    const names = TOOLS.map((t) => t.name)
    for (const name of CARD_FOR_TOOL.keys()) expect(names).toContain(name)
    for (const tool of TOOLS) expect(tool.description).not.toContain("ui://")
  })

  test("each document is one self-contained HTML5 page that fetches nothing and keeps its script inside its script element", async () => {
    for (const html of [ASK_CARD_HTML, ADOPT_CARD_HTML]) {
      expect(html.startsWith("<!doctype html>\n<html lang=\"en\">")).toBe(true)
      expect(html).toContain('<meta charset="utf-8">')
      expect(html).toContain('<meta name="viewport"')
      expect(html).toContain(`<meta http-equiv="Content-Security-Policy" content="${CARD_CSP}">`)
      expect(html.match(/<script>/g)).toHaveLength(1)
      expect(html.match(/<\/script/gi)).toHaveLength(1)
      expect(html).not.toMatch(/<script\s+src|<link\s|@import|url\(|https?:\/\/(?!www\.w3\.org\/2000\/svg)/)
      const script = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"))
      expect(new TextEncoder().encode(script).length).toBeLessThan(25 * 1024)
      // No result value is ever put in as markup.
      expect(script).not.toContain("innerHTML")
      expect(script).not.toContain("ui/message")
    }
    expect(await readCard("ui://mehen/ask-card-v2.html")).toBeNull()
  })

  test("a bundle that holds a closing script tag or a comment opener is escaped", () => {
    expect(inlineScript('a="</script><b>";c="</SCRIPT";d="<!--"')).toBe('a="<\\/script><b>";c="<\\/SCRIPT";d="<\\!--"')
  })
})
