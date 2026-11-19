// The built assets under /assets/ and the icons a browser fetches from the
// root on its own (src/index.ts), and the home-screen PNG
// scripts/touch-icon.ts draws from the brand's reduced coil at build time.
// The assets binding is stood in for, answering HEAD with the headers and no
// body as the real one does: CI runs without dist/.

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test"
import { env } from "cloudflare:workers"
import { inflateSync } from "node:zlib"
import { describe, expect, it } from "vitest"
import worker from "../src/index.ts"
import { PAGE_CSP } from "../src/ui/layout.ts"
import { PAPYRUS_ICON, TOUCH_ICON_SIZE, coilShapes, touchIconPng } from "../scripts/touch-icon.ts"
import { ORIGIN } from "./helpers.ts"

const COIL_S = Object.values(import.meta.glob<string>("../../../packages/brand/marks/coil-s.svg", { query: "?raw", import: "default", eager: true }))[0] as string

async function fetchWithAssets(path: string, method = "GET"): Promise<{ res: Response; asked: string[]; methods: string[] }> {
  const asked: string[] = []
  const methods: string[] = []
  const assets = {
    fetch: async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input)
      const url = new URL(request.url)
      asked.push(url.pathname)
      methods.push(request.method)
      const type = url.pathname.endsWith(".svg") ? "image/svg+xml" : url.pathname.endsWith(".css") ? "text/css" : "image/png"
      const headers = { "content-type": type, etag: `"${url.pathname}"`, "cache-control": "public, max-age=0, must-revalidate" }
      return new Response(request.method === "HEAD" ? null : "asset", { headers })
    },
    connect: () => {
      throw new Error("not used")
    },
  } as unknown as Fetcher
  const ctx = createExecutionContext()
  const res = await worker.fetch(new Request(`${ORIGIN}${path}`, { method }) as Request<unknown, IncomingRequestCfProperties>, { ...env, ASSETS: assets }, ctx)
  await waitOnExecutionContext(ctx)
  return { res, asked, methods }
}

// The PNG's pixels, RGB, from its one IDAT with every row unfiltered.
function pixels(png: Uint8Array): { width: number; height: number; type: number; at(x: number, y: number): number[] } {
  const view = new DataView(png.buffer, png.byteOffset, png.byteLength)
  expect([...png.subarray(0, 8)]).toEqual([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
  let offset = 8
  let width = 0
  let height = 0
  let type = -1
  const data: Uint8Array[] = []
  while (offset < png.length) {
    const length = view.getUint32(offset)
    const name = new TextDecoder().decode(png.subarray(offset + 4, offset + 8))
    const body = png.subarray(offset + 8, offset + 8 + length)
    if (name === "IHDR") {
      width = view.getUint32(offset + 8)
      height = view.getUint32(offset + 12)
      type = body[9] as number
    }
    if (name === "IDAT") data.push(body)
    offset += 12 + length
  }
  const raw = new Uint8Array(inflateSync(Buffer.concat(data)))
  const stride = 1 + width * 3
  for (let y = 0; y < height; y++) expect(raw[y * stride]).toBe(0)
  return { width, height, type, at: (x, y) => [...raw.subarray(y * stride + 1 + x * 3, y * stride + 1 + x * 3 + 3)] }
}

describe("built assets and root icons", () => {
  it("answers /favicon.ico with the favicon and both touch icon names with the built PNG", async () => {
    const favicon = await fetchWithAssets("/favicon.ico")
    expect(favicon.res.status).toBe(200)
    expect(favicon.asked).toEqual(["/assets/favicon.svg"])
    expect(favicon.res.headers.get("content-type")).toBe("image/svg+xml")
    expect(favicon.res.headers.get("x-content-type-options")).toBe("nosniff")
    for (const path of ["/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"]) {
      const touch = await fetchWithAssets(path)
      expect(touch.res.status).toBe(200)
      expect(touch.asked).toEqual(["/assets/apple-touch-icon.png"])
    }
  })

  it("answers HEAD on a built asset and on the root icons as it answers GET, with no body", async () => {
    for (const path of ["/assets/app.css", "/favicon.ico", "/apple-touch-icon.png"]) {
      const get = await fetchWithAssets(path)
      const head = await fetchWithAssets(path, "HEAD")
      expect(get.res.status).toBe(200)
      expect(head.res.status).toBe(get.res.status)
      expect(head.asked).toEqual(get.asked)
      expect(head.methods).toEqual(["HEAD"])
      expect([...head.res.headers]).toEqual([...get.res.headers])
      expect(head.res.headers.get("mehen-error")).toBeNull()
      expect((await get.res.arrayBuffer()).byteLength).toBe(5)
      expect((await head.res.arrayBuffer()).byteLength).toBe(0)
    }
  })

  it("serves nothing else from the root through the assets binding", async () => {
    for (const path of ["/favicon.png", "/apple-touch-icon-120x120.png", "/favicon.ico/x"]) {
      const { res, asked } = await fetchWithAssets(path)
      expect(res.status).toBe(404)
      expect(asked).toEqual([])
    }
    for (const path of ["/favicon.ico", "/assets/app.css"]) {
      const post = await fetchWithAssets(path, "POST")
      expect(post.asked).toEqual([])
    }
  })

  it("keeps the page CSP at 'self' for images", () => {
    expect(PAGE_CSP).toContain("img-src 'self' data:")
  })
})

describe("the touch icon", () => {
  it("is a 180 pixel opaque PNG of the brand's reduced coil on a cream tile, ink line, ember sun", () => {
    const shapes = coilShapes(COIL_S)
    const png = pixels(touchIconPng(COIL_S))
    expect(png.width).toBe(TOUCH_ICON_SIZE)
    expect(png.height).toBe(TOUCH_ICON_SIZE)
    expect(png.type).toBe(2)
    // The coil's 64 unit box fills 70 percent of the tile, centred.
    const box = TOUCH_ICON_SIZE * 0.7
    const offset = (TOUCH_ICON_SIZE - box) / 2
    const at = ([x, y]: [number, number]) => png.at(Math.floor(offset + (x / shapes.size) * box), Math.floor(offset + (y / shapes.size) * box))
    // iOS rounds the corners itself, so the corner is the tile.
    expect(png.at(0, 0)).toEqual([...PAPYRUS_ICON.tile])
    expect(png.at(TOUCH_ICON_SIZE - 1, TOUCH_ICON_SIZE - 1)).toEqual([...PAPYRUS_ICON.tile])
    expect(at(shapes.sun.at)).toEqual([...PAPYRUS_ICON.sun])
    expect(at(shapes.line[0] as [number, number])).toEqual([...PAPYRUS_ICON.ink])
    expect(at(shapes.line[Math.floor(shapes.line.length / 2)] as [number, number])).toEqual([...PAPYRUS_ICON.ink])
    // Between the sun and the innermost turn the tile shows through.
    expect(at([32, 38.5])).toEqual([...PAPYRUS_ICON.tile])
    // The head is inked (a third of the way from its base to its tip, clear
    // of the eye) and its eye is the tile.
    const [base0, tip, base1] = [shapes.head[0], shapes.head[12], shapes.head[24]] as [[number, number], [number, number], [number, number]]
    const base: [number, number] = [(base0[0] + base1[0]) / 2, (base0[1] + base1[1]) / 2]
    expect(at([base[0] + (tip[0] - base[0]) * 0.3, base[1] + (tip[1] - base[1]) * 0.3])).toEqual([...PAPYRUS_ICON.ink])
    expect(at(shapes.eye.at)).toEqual([...PAPYRUS_ICON.tile])
  })

  it("stops the build on a coil it cannot draw rather than drawing it wrong", () => {
    expect(() => touchIconPng(COIL_S.replace(/ d="M32 57[^"]*"/, ' d="M6 7C8 9 10 11 12 17"'))).toThrow(/more than M and L/)
    expect(() => touchIconPng(COIL_S.replace('<g class="head"', "<g"))).toThrow(/no <g class="head">/)
    expect(() => touchIconPng(COIL_S.replace(/<circle cx="32" cy="32"[^>]*>/, ""))).toThrow(/no <circle>|not the sun/)
  })
})
