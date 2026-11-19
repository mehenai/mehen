// The docs search: one entry per h2 and h3 section of every page, scored by
// where the query's words fall. The Worker runs it for /search and the
// browser runs the same code over /search-index.json, so the two agree.

// One section: its URL with the anchor, the page title, the heading and the
// first characters of its text.
export type SearchEntry = { u: string; t: string; h: string; x: string }

export type SearchHit = SearchEntry & { score: number; snippet: string }

export const MAX_QUERY_CHARS = 120
export const MAX_QUERY_TOKENS = 8
const SNIPPET_CHARS = 160

// Lower case, split on anything that is not a letter or a digit, tokens of
// two characters or more, at most eight of them from the first 120
// characters. Underscores split too, so `approval_required` matches both
// words and the whole code.
export function tokenise(query: string): string[] {
  const words = query.slice(0, MAX_QUERY_CHARS).toLowerCase().split(/[^\p{L}\p{N}]+/u)
  const tokens: string[] = []
  for (const word of words) {
    if (word.length < 2 || tokens.includes(word)) continue
    tokens.push(word)
    if (tokens.length === MAX_QUERY_TOKENS) break
  }
  return tokens
}

// The query as typed, lower case and with its spaces collapsed: an exact
// phrase in the text scores extra.
function phraseOf(query: string): string {
  return query.slice(0, MAX_QUERY_CHARS).toLowerCase().trim().replace(/\s+/g, " ")
}

// A heading hit counts three, a title hit two, a text hit one, and the whole
// phrase in the heading or the text two more.
export function scoreEntry(entry: SearchEntry, tokens: string[], phrase: string): number {
  if (tokens.length === 0) return 0
  const h = entry.h.toLowerCase()
  const t = entry.t.toLowerCase()
  const x = entry.x.toLowerCase()
  let score = 0
  for (const token of tokens) {
    score += (h.includes(token) ? 3 : 0) + (t.includes(token) ? 2 : 0) + (x.includes(token) ? 1 : 0)
  }
  if (phrase.length > 1 && (x.includes(phrase) || h.includes(phrase))) score += 2
  return score
}

// The text around the first hit, on word boundaries where it can be.
export function snippetOf(text: string, tokens: string[]): string {
  const lower = text.toLowerCase()
  const at = tokens.map((token) => lower.indexOf(token)).filter((i) => i >= 0).sort((a, b) => a - b)[0] ?? 0
  if (text.length <= SNIPPET_CHARS) return text
  let start = Math.max(0, at - SNIPPET_CHARS / 4)
  if (start > 0) {
    const space = text.indexOf(" ", start)
    start = space < 0 || space > at ? start : space + 1
  }
  let end = Math.min(text.length, start + SNIPPET_CHARS)
  if (end < text.length) {
    const space = text.lastIndexOf(" ", end)
    end = space > at ? space : end
  }
  return `${start > 0 ? "… " : ""}${text.slice(start, end)}${end < text.length ? " …" : ""}`
}

// The best `limit` entries for the query, highest score first, ties in index
// order (the navigation order).
export function search(entries: readonly SearchEntry[], query: string, limit: number): SearchHit[] {
  const tokens = tokenise(query)
  if (tokens.length === 0) return []
  const phrase = phraseOf(query)
  const hits: SearchHit[] = []
  entries.forEach((entry) => {
    const score = scoreEntry(entry, tokens, phrase)
    if (score > 0) hits.push({ ...entry, score, snippet: snippetOf(entry.x, tokens) })
  })
  return hits.sort((a, b) => b.score - a.score).slice(0, limit)
}
