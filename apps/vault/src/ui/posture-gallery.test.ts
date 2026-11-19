// The How careful gallery states (posture-gallery.ts): registered in the
// gallery script, and each shows what the card draws for its posture.
import { describe, expect, it } from "vitest"
import { renderDocument } from "./layout.ts"
import { postureGallery } from "./posture-gallery.ts"

const GALLERY_SCRIPT = Object.values(import.meta.glob<string>("../../scripts/ui-gallery.ts", { query: "?raw", import: "default", eager: true }))[0] ?? ""

function shown(id: string): string {
  const found = postureGallery().find((e) => e.id === id)
  if (!found) throw new Error(`no gallery entry ${id}`)
  return renderDocument(found.page).value
}
// The card alone, and the value of the level ticked in it.
function card(id: string): string {
  const page = shown(id)
  const start = page.indexOf('<section class="card" id="how-careful"')
  expect(start, id).toBeGreaterThan(-1)
  return page.slice(start, page.indexOf("</section>", start))
}
const checkedLevel = (markup: string) => /data-input="posture-level" value="(\w+)" checked/.exec(markup)?.[1]
const levels = (markup: string) => [...markup.matchAll(/data-input="posture-level" value="(\w+)"/g)].map((m) => m[1])

describe("the How careful gallery", () => {
  it("is in the gallery, above Allowed without asking", () => {
    expect(GALLERY_SCRIPT).toContain('import { postureGallery } from "../src/ui/posture-gallery.ts"')
    expect(GALLERY_SCRIPT).toContain("...postureGallery(),")
    expect(postureGallery().map((e) => e.id)).toEqual(["ws-posture-ask", "ws-posture-custom", "ws-posture-routine", "ws-posture-trust-named", "ws-posture-grown", "ws-posture-no-catalogue", "ws-posture-held", "ws-posture-with-web-pages"])
    const page = shown("ws-posture-custom")
    expect(page.indexOf('id="how-careful"')).toBeLessThan(page.indexOf('id="policy-rules"'))
  })

  it("draws In web pages, then How careful, then Allowed without asking, on a credential with all three", () => {
    const page = shown("ws-posture-with-web-pages")
    const order = ['data-region="in-web-pages"', 'id="how-careful"', 'id="policy-rules"'].map((marker) => page.indexOf(marker))
    expect(order.every((at) => at > -1), String(order)).toBe(true)
    expect([...order].sort((a, b) => a - b)).toEqual(order)
  })

  it("asks by default, with the four choices in the design's words and nothing to save", () => {
    const c = card("ws-posture-ask")
    expect(levels(c)).toEqual(["ask", "routine", "trust", "custom"])
    expect(checkedLevel(c)).toBe("ask")
    expect(c).toContain("<b>Ask for every change</b>")
    expect(c).toContain("<b>Let routine building through</b> <span class=\"muted small\">Reads, and creating or changing things in the areas below. Deletes, secrets, sending and sharing still ask.</span>")
    expect(c).toContain("<b>Trust my own machines</b> <span class=\"muted small\">Everything except deletes and other destructive changes, secrets and access, sending and sharing, payments and anything that keeps running, on machines of people who manage this credential. Other machines still ask. Includes routes nobody has reviewed.</span>")
    expect(c).toContain('<p class="small muted" data-region="posture-areas"><span class="label">Routine building covers</span> Workers scripts and deployments, ')
    expect(c).toContain('data-region="posture-machines" hidden')
    expect(c).toContain('data-region="posture-custom" hidden')
    expect(c).toContain('<button type="button" class="btn primary" data-action="posture-save" disabled>Save with passkey</button><span class="small muted" data-region="posture-nothing">Nothing to save.</span>')
    expect(c).toContain('data-item="itm_cloudflareprod" data-slug="cloudflare-prod" data-rev="0" data-level="ask" data-machines="" data-catalogue="cloudflare-api-token" data-catalogue-version="2"')
  })

  it("opens on Custom when a standing rule is live, with the credential's rules read only and where its standing rules are", () => {
    const c = card("ws-posture-custom")
    expect(checkedLevel(c)).toBe("custom")
    expect(c).toContain('<div class="stack" data-region="posture-custom">')
    expect(c).toMatch(/<ul class="plain small" data-region="posture-custom-lines"><li>On its own: [^<]+\.<\/li><li>Asks first: [^<]+\.<\/li><li>Refused: minting tokens\.<\/li><\/ul>/)
    expect(c).toContain('<p class="small">Your standing rules are in <a href="#policy-rules">Allowed without asking</a>, below.</p>')
    expect(c).toContain("An agent proposes a new rule with mehen policy propose, and you approve it with your passkey.")
    const custom = c.slice(c.indexOf('data-region="posture-custom"'), c.indexOf("</div>", c.indexOf('data-region="posture-custom"')))
    expect(custom).not.toContain("<input")
    expect(c).toContain('data-action="posture-save" disabled')
  })

  it("shows routine on every machine and trust on the machines ticked, with who set it", () => {
    const routine = card("ws-posture-routine")
    expect(checkedLevel(routine)).toBe("routine")
    expect(routine).toContain('<fieldset class="field" data-region="posture-machines"><legend class="label">On these machines</legend>')
    expect(routine).toContain('value="every" checked><span>Every eligible machine</span>')
    expect(routine).toContain('<input type="checkbox" data-input="posture-machine" value="dev_alexmbp0001" disabled><span>alex-mbp</span>')
    expect(routine).toMatch(/data-region="posture-set-by">Set by Alex, <time /)
    const trust = card("ws-posture-trust-named")
    expect(checkedLevel(trust)).toBe("trust")
    expect(trust).toContain('value="named" checked><span>Only the machines ticked</span>')
    expect(trust).toContain('<input type="checkbox" data-input="posture-machine" value="dev_alexmbp0001" checked><span>alex-mbp</span>')
    // Tom does not manage the token, so Trust would not cover his machine.
    expect(trust).toContain('<label class="tick" data-region="posture-machine-row" data-levels="routine" hidden><input type="checkbox" data-input="posture-machine" value="dev_tomlaptop01"><span>tom-laptop</span>')
    expect(routine).toContain('<label class="tick" data-region="posture-machine-row" data-levels="routine"><input type="checkbox" data-input="posture-machine" value="dev_tomlaptop01" disabled><span>tom-laptop</span>')
    expect(trust).toContain('data-machines="dev_alexmbp0001"')
  })

  it("says the reviewed list grew, with Save ready", () => {
    const c = card("ws-posture-grown")
    expect(c).toContain("Cloudflare API token&#39;s reviewed list grew. Review and save to include the new routes.")
    expect(c).toContain(" data-grown>")
    expect(c).toContain('data-action="posture-save">Save with passkey</button><span class="small muted" data-region="posture-nothing" hidden>')
  })

  it("offers only Ask and Custom with no reviewed catalogue", () => {
    const c = card("ws-posture-no-catalogue")
    expect(levels(c)).toEqual(["ask", "custom"])
    expect(c).toContain("Nobody has reviewed this service&#39;s routes, so this credential can only ask, or follow its own rules.")
    expect(c).not.toContain('data-region="posture-machines"')
    expect(c).toContain('data-catalogue="" data-catalogue-version=""')
  })

  it("lets a restricted account only ask, and says why", () => {
    const c = card("ws-posture-held")
    expect(c).toContain('value="routine" checked disabled>')
    expect(c).toContain('value="trust" disabled>')
    expect(c).not.toContain('value="ask" disabled')
    expect(c).not.toContain('value="custom" disabled')
    expect(c).toContain("Your account is restricted after a recovery or a security change, so you may only set this credential to ask for every change.")
  })
})
