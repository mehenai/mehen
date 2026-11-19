// The MCP Apps cards (SEP-1865, extension io.modelcontextprotocol/ui): a
// host that negotiated the extension draws a small sandboxed HTML card next
// to the result of a linked tool. The card only shows what the result holds
// and opens the ask's link through the host; nothing in it approves, enrols,
// revokes or decides anything. A host that did not negotiate sees none of
// this, and every tool's text and structuredContent are the same either way.

export const MCP_APPS_EXTENSION = "io.modelcontextprotocol/ui"
export const CARD_MIME_TYPE = "text/html;profile=mcp-app"

// The uris are cache keys for a host: a changed card gets a new version.
export const ASK_CARD_URI = "ui://mehen/ask-card-v1.html"
export const ADOPT_CARD_URI = "ui://mehen/adopt-card-v1.html"

export type CardResource = { uri: string; name: string; description: string; mimeType: typeof CARD_MIME_TYPE }

export const CARDS: readonly CardResource[] = [
  { uri: ASK_CARD_URI, name: "mehen-ask-card", description: "The link a human must open, what to check, when it expires and its live state; approval stays on the vault's page.", mimeType: CARD_MIME_TYPE },
  { uri: ADOPT_CARD_URI, name: "mehen-adopt-card", description: "An adoption scan or batch as a readable summary: counts, folders and the next step.", mimeType: CARD_MIME_TYPE },
]

// Which card draws which tool's result: the one place this is decided.
export const CARD_FOR_TOOL: ReadonlyMap<string, string> = new Map([
  ["vault_request", ASK_CARD_URI],
  ["vault_connect", ASK_CARD_URI],
  ["vault_policy", ASK_CARD_URI],
  ["vault_pending", ASK_CARD_URI],
  ["vault_adopt_scan", ADOPT_CARD_URI],
  ["vault_adopt_status", ADOPT_CARD_URI],
])

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null
}

// Negotiated when the host's initialize names the extension, and its
// mimeTypes, when given, include the card's.
export function appsNegotiated(params: Record<string, unknown>): boolean {
  const extension = record(record(record(params.capabilities)?.extensions)?.[MCP_APPS_EXTENSION])
  if (extension === null) return false
  const types = extension.mimeTypes
  return types === undefined || (Array.isArray(types) && types.includes(CARD_MIME_TYPE))
}

export type CardContents = { contents: [{ uri: string; mimeType: typeof CARD_MIME_TYPE; text: string; _meta: { ui: { prefersBorder: false } } }] }

// resources/read for a card, or null for any other uri. The documents are
// loaded only here, so a server that is never asked for one never builds them.
export async function readCard(uri: unknown): Promise<CardContents | null> {
  if (uri !== ASK_CARD_URI && uri !== ADOPT_CARD_URI) return null
  const { ASK_CARD_HTML, ADOPT_CARD_HTML } = await import("./documents.ts")
  // No csp: the host's default allows no network at all, which is what the cards need.
  return { contents: [{ uri, mimeType: CARD_MIME_TYPE, text: uri === ASK_CARD_URI ? ASK_CARD_HTML : ADOPT_CARD_HTML, _meta: { ui: { prefersBorder: false } } }] }
}
