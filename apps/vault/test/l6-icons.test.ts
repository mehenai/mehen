// The inline icons: every glyph and logo renders through the escaping
// template, and the brand map covers every template and provider.

import { describe, expect, it } from "vitest"
import { OAUTH_PROVIDERS, TEMPLATES } from "@mehen/protocol/templates"
import { BRAND_SLUGS, COILS, ICON_NAMES, brandFor, brandLogo, icon, kindIcon, kindTile, machineHue, machineDot, serviceTile, vaultMark } from "../src/ui/icons.ts"

const BRAND_MARKS = import.meta.glob<string>("../../../packages/brand/marks/coil*.svg", { query: "?raw", import: "default", eager: true })

function brandMark(name: "coil" | "coil-s"): string {
  return Object.entries(BRAND_MARKS).find(([file]) => file.endsWith(`/${name}.svg`))?.[1] as string
}

describe("icons", () => {
  it("renders every interface glyph as an inline svg with no script or handler", () => {
    expect(ICON_NAMES.length).toBe(48)
    for (const name of ICON_NAMES) {
      const out = icon(name).value
      expect(out.startsWith('<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor"')).toBe(true)
      expect(out).toContain('aria-hidden="true"')
      expect(out).not.toMatch(/<script|\son[a-z]+=|javascript:/i)
    }
    expect(icon("home", "inline").value).toContain('class="i inline"')
  })

  it("renders every brand logo with its title, and no attribute from outside", () => {
    expect(BRAND_SLUGS.length).toBe(42)
    for (const slug of BRAND_SLUGS) {
      const out = brandLogo(slug).value
      expect(out).toContain(`class="logo brand-${slug}"`)
      expect(out).toMatch(/aria-label="[A-Za-z ]+"/)
      expect(out).not.toMatch(/<script|\son[a-z]+=|javascript:/i)
    }
  })

  it("maps every template and provider to a logo, except the ones Simple Icons has no mark for", () => {
    const ids = [...Object.keys(TEMPLATES), ...Object.keys(OAUTH_PROVIDERS)]
    const missing = ids.filter((id) => brandFor(id) === null)
    expect(missing.sort()).toEqual(["browserbase", "fathom", "firecrawl", "fly", "groq", "heygen", "microsoft-graph", "microsoft-oauth-client", "postmark-server", "serpapi", "together", "xai"])
    expect(brandFor("google-gemini")).toBe("googlegemini")
    expect(brandFor("hubspot-private-app")).toBe("hubspot")
    expect(serviceTile({ provider: "fathom", slug: "fathom" }).value).toContain("<span>F</span>")
    expect(brandFor("google-gmail")).toBe("gmail")
    expect(brandFor("github-pat")).toBe("github")
    expect(brandFor("cloudflare-api-token")).toBe("cloudflare")
    expect(brandFor("made-up")).toBeNull()
  })

  it("falls back to an escaped letter tile when no template knows the service", () => {
    expect(serviceTile({ provider: "openai", slug: "openai-personal" }).value).toContain('class="logo brand-openai"')
    const letter = serviceTile({ provider: null, slug: '<b>weather' }, "lg").value
    expect(letter).toBe('<span class="tile letter lg" aria-hidden="true"><span>&lt;</span></span>')
    expect(serviceTile({ provider: "microsoft-graph", slug: "m365" }).value).toContain("<span>M</span>")
  })

  it("picks a kind icon for every credential kind and a machine icon from the backend and name", () => {
    expect(kindIcon("oauth-connection")).toBe("link")
    expect(kindIcon("api-key")).toBe("key")
    expect(kindIcon("project")).toBe("braces")
    expect(kindIcon("machine", "secure-enclave", "Mac mini")).toBe("desktop")
    expect(kindIcon("machine", "software", "the Linux box")).toBe("tower")
    expect(kindIcon("machine", "software", "Alex's MacBook")).toBe("laptop")
    expect(kindIcon("machine", "software", "iPhone")).toBe("phone")
    expect(kindTile("machine", "software", "sm", "the Linux box").value).toContain('class="tile kind sm"')
  })

  it("gives a machine the design direction's hue by name and falls back to the accent", () => {
    expect(machineHue("Mac Studio")).toBe("indigo")
    expect(machineHue("the Beast")).toBe("coral")
    expect(machineHue("MacBook (old)")).toBe("teal")
    expect(machineHue("Cloudflare")).toBe("ember")
    expect(machineHue("nova")).toBeNull()
    expect(machineDot("nova").value).toBe('<i class="hue-dot" aria-hidden="true"></i>')
    expect(machineDot("the Beast").value).toBe('<i class="hue-dot hue-coral" aria-hidden="true"></i>')
  })

  it("draws the mark as the brand's coil, coloured by its container", () => {
    const mark = vaultMark().value
    expect(mark.startsWith('<svg class="mark" viewBox="0 0 64 64"')).toBe(true)
    expect(mark).toContain('stroke="currentColor"')
    expect(mark).toContain('fill="var(--sun, currentColor)"')
    expect(mark).toContain('fill="var(--bg, #fff)"')
    expect(mark).not.toMatch(/fill="#|stroke="#/)
    expect(vaultMark("inline", "coil-s").value).toContain('class="mark inline"')
  })

  it("repeats the geometry of packages/brand/marks/coil.svg and coil-s.svg", () => {
    for (const variant of ["coil", "coil-s"] as const) {
      const svg = brandMark(variant)
      const geometry = COILS[variant]
      expect(svg).toContain(`stroke-width="${geometry.stroke}"`)
      expect(svg).toContain(`d="${geometry.line}"`)
      expect(svg).toContain(`transform="${geometry.head}"`)
      expect(svg).toContain(`<circle cx="32" cy="32" r="${geometry.sun}" fill="var(--sun, currentColor)"`)
      expect(vaultMark(undefined, variant).value).toContain(`d="${geometry.line}"`)
    }
  })
})
