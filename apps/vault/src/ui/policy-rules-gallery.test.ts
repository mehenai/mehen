// The "Allowed without asking" gallery states (policy-rules-gallery.ts):
// registered in the gallery script, every swap matches its page exactly
// once, and each state shows what the pages and the client draw.
import { describe, expect, it } from "vitest"
import { renderDocument } from "./layout.ts"
import { RULES_COSIGN_CODE, RULES_COSIGN_URL, policyRulesGallery } from "./policy-rules-gallery.ts"

const GALLERY_SCRIPT = Object.values(import.meta.glob<string>("../../scripts/ui-gallery.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""

function entry(id: string) {
  const found = policyRulesGallery().find((e) => e.id === id)
  if (!found) throw new Error(`no gallery entry ${id}`)
  return found
}

// The page as the gallery shows it, after its swaps.
function shown(id: string): string {
  const { page, swap } = entry(id)
  let markup = renderDocument(page).value
  for (const [from, to] of swap ?? []) {
    const pattern = typeof from === "string" ? from : new RegExp(from.source, `${from.flags.replace("g", "")}g`)
    expect(markup.match(pattern)?.length ?? 0, id).toBe(1)
    markup = markup.replace(from, to)
  }
  return markup
}

describe("the standing rules gallery", () => {
  it("is in the gallery, with the four states the brief asks for, My rules and the credential page", () => {
    expect(GALLERY_SCRIPT).toContain('import { policyRulesGallery } from "../src/ui/policy-rules-gallery.ts"')
    expect(GALLERY_SCRIPT).toContain("...policyRulesGallery(),")
    expect(policyRulesGallery().map((e) => e.id)).toEqual(["machine-rules", "machine-rule-stopped", "machine-rule-cosign", "machine-rule-stopped-only", "ws-my-rules", "ws-my-rules-empty", "ws-my-rules-grant", "ws-credential-grants", "ws-credential-rules"])
    for (const e of policyRulesGallery()) expect(shown(e.id), e.id).toContain('<section class="card" id="policy-rules"')
  })

  it("My rules lists live rules naming their credential, and links itself from the navigation", () => {
    const mine = shown("ws-my-rules")
    expect(mine.match(/data-rule-state="active"/g)).toHaveLength(2)
    expect(mine).toContain('<a href="/w/northwind/items/openai-prod"><code>openai-prod</code></a>')
    expect(mine).toContain('<a href="/w/northwind/rules" aria-current="page"><span>My rules</span></a>')
    const empty = shown("ws-my-rules-empty")
    expect(empty).toContain("<b>No rules</b>")
    expect(empty).not.toContain('data-action="rule-stop"')
  })

  it("active, stopped, co-sign and stopped-only each show their state", () => {
    const active = shown("machine-rules")
    expect(active.match(/data-rule-state="active"/g)).toHaveLength(2)
    expect(active).toContain(">2 requests allowed without asking</a>")
    const stopped = shown("machine-rule-stopped")
    expect(stopped).toContain('data-rule-state="ended"')
    expect(stopped).toContain("Someone stopped it.")
    expect(stopped).toContain(">1 request allowed without asking</a>")
    const coSign = shown("machine-rule-cosign")
    expect(coSign).toContain(`<a href="${RULES_COSIGN_URL}">${RULES_COSIGN_URL}</a>`)
    expect(coSign).toContain(`<code>${RULES_COSIGN_CODE}</code>`)
    expect(coSign.match(/data-region="rule-extend"/g)).toHaveLength(1)
    const only = shown("machine-rule-stopped-only")
    const row = only.slice(only.indexOf('data-rule="rul_tomchat0001"'), only.indexOf("</li>", only.indexOf('data-rule="rul_tomchat0001"')))
    expect(row).toContain("You may stop this rule, but not read what it allows.")
    for (const term of ["api.openai.com", "chat/completions", "openai-shared", "Approved by"]) expect(row).not.toContain(term)
    // An admin on Tom's machine: no line, no Extend.
    expect(only).not.toContain("policy-rules-line")
    expect(only).not.toContain('data-action="rule-extend"')
  })

  it("a live task grant names its areas, its uses of how many and its end, with Stop and no Extend", () => {
    const mine = shown("ws-my-rules-grant")
    const row = mine.slice(mine.indexOf('data-rule="rul_alexgrant001"'), mine.indexOf("</li>", mine.indexOf('data-rule="rul_alexgrant001"')))
    expect(row).toContain('data-rule-kind="area"')
    expect(row).toContain('<span class="row-title">Task grant: D1 databases, DNS records</span>')
    expect(row).toContain('<dt>Credential</dt><dd><a href="/w/northwind/items/cloudflare-prod"><code>cloudflare-prod</code></a> <span class="muted small">on <code>api.cloudflare.com</code></span></dd>')
    expect(row).toMatch(/<dt>Used<\/dt><dd data-region="grant-uses">14 of 50 requests<\/dd>/)
    expect(row).toMatch(/<dt data-region="rule-ends-label">Ends<\/dt><dd data-region="rule-ends"><time /)
    expect(row).toContain('<button type="button" class="btn danger-quiet" data-action="rule-stop" data-rule="rul_alexgrant001">Stop this task grant</button>')
    expect(row).not.toContain('data-action="rule-extend"')
    expect(row).not.toContain('data-region="grant-receipt"')
    expect(mine.match(/data-rule-state="active"/g)).toHaveLength(3)
  })

  it("an ended task grant shows its receipt and how it ended", () => {
    const page = shown("ws-credential-grants")
    const ended = page.slice(page.indexOf('data-region="rules-ended"'))
    // A row runs to the </li> after its status, past its receipt's own.
    const row = (id: string) => { const start = ended.indexOf(`data-rule="${id}"`); return ended.slice(start, ended.indexOf("</li>", ended.indexOf('data-region="rule-status"', start))) }
    const spent = row("rul_alexgrant000")
    expect(spent).toContain('<span class="row-title">Task grant: D1 databases</span>')
    expect(spent).toContain('data-region="grant-uses">6 of 6 requests</dd>')
    expect(spent).toContain('<dt>Receipt</dt><dd><ul class="plain" data-region="grant-receipt"><li>6 × Creates a D1 database</li></ul></dd>')
    expect(spent).toContain("It was used as many times as it allows.")
    expect(spent).toContain('<span class="pill muted">Ended</span>')
    expect(spent).not.toContain('data-action="rule-stop"')
    const replaced = row("rul_tomgrant0001")
    expect(replaced).toContain("A newer task grant replaced it.")
    expect(replaced).toContain('data-region="grant-receipt"><li>None</li>')
  })
})
