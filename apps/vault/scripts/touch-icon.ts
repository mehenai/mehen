// The home-screen icon iOS asks for at /apple-touch-icon.png: the identity
// board's Papyrus app icon, the reduced coil from packages/brand/marks/
// coil-s.svg on a cream tile, ink line and head, ember sun, so the icon and
// the favicon share one geometry. Full bleed and opaque, as iOS wants: it
// rounds the corners itself. Built by scripts/build-ui.ts; no rasteriser
// needed.

import { deflateSync } from "node:zlib"

export const TOUCH_ICON_SIZE = 180

// The coil's 64 unit box fills this much of the tile, as the board's icon.
const COIL_SHARE = 0.7

export const PAPYRUS_ICON = { tile: [243, 234, 216], ink: [28, 25, 21], sun: [212, 80, 43] } as const satisfies Record<string, Rgb>

type Rgb = readonly [number, number, number]
type Point = [number, number]
type Circle = { at: Point; r: number }
type Shapes = { size: number; line: Point[]; halfWidth: number; head: Point[]; eye: Circle; sun: Circle }

function attr(tag: string, name: string): string {
  const match = new RegExp(`\\s${name}="([^"]*)"`).exec(tag)
  if (!match) throw new Error(`coil-s.svg: no ${name} on ${tag}`)
  return match[1] as string
}

function element(svg: string, name: string, from = 0): string {
  const match = new RegExp(`<${name}\\b[^>]*>`).exec(svg.slice(from))
  if (!match) throw new Error(`coil-s.svg: no <${name}>`)
  return match[0]
}

function numbers(text: string): number[] {
  const out = (text.match(/-?\d*\.?\d+/g) ?? []).map(Number)
  if (out.some((n) => !Number.isFinite(n))) throw new Error(`coil-s.svg: cannot read "${text}"`)
  return out
}

// The coil's line: M and L only, which is all the brand's coil uses.
// Anything else stops the build rather than drawing wrong.
function polyline(d: string): Point[] {
  if (/[^MLml\d\s.,-]/.test(d)) throw new Error(`coil-s.svg: the line "${d.slice(0, 40)}" uses more than M and L`)
  const tokens = d.match(/[MLml]|-?\d*\.?\d+/g) ?? []
  const points: Point[] = []
  let command = ""
  for (let i = 0; i < tokens.length; ) {
    const token = tokens[i] as string
    if (/^[MLml]$/.test(token)) {
      command = token
      i += 1
      continue
    }
    const [x, y] = numbers(`${tokens[i]} ${tokens[i + 1]}`)
    const last = points.at(-1) ?? [0, 0]
    points.push(command === "l" || command === "m" ? [last[0] + (x as number), last[1] + (y as number)] : [x as number, y as number])
    i += 2
  }
  if (points.length < 2) throw new Error("coil-s.svg: the line has fewer than two points")
  return points
}

// The head's outline: M, cubic C curves and Z, flattened to a polygon.
function outline(d: string): Point[] {
  if (/[^MCZmcz\d\s.,-]/.test(d)) throw new Error(`coil-s.svg: the head "${d}" uses more than M, C and Z`)
  const tokens = d.match(/[MCZmcz]|-?\d*\.?\d+/g) ?? []
  const points: Point[] = []
  let command = ""
  for (let i = 0; i < tokens.length; ) {
    const token = tokens[i] as string
    if (/^[MCZmcz]$/.test(token)) {
      command = token
      i += 1
      continue
    }
    if (command === "M") {
      const [x, y] = numbers(`${tokens[i]} ${tokens[i + 1]}`) as [number, number]
      points.push([x, y])
      i += 2
      continue
    }
    if (command === "C") {
      const [x1, y1, x2, y2, x, y] = numbers(tokens.slice(i, i + 6).join(" ")) as [number, number, number, number, number, number]
      const [x0, y0] = points.at(-1) as Point
      for (let s = 1; s <= 12; s++) {
        const t = s / 12
        const u = 1 - t
        points.push([u * u * u * x0 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t * t * t * x, u * u * u * y0 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y])
      }
      i += 6
      continue
    }
    throw new Error(`coil-s.svg: the head uses a relative ${command}`)
  }
  if (points.length < 3) throw new Error("coil-s.svg: the head is not a shape")
  return points
}

// translate(tx ty) rotate(deg) scale(s): the head's place on the coil.
function placement(transform: string): { place: (p: Point) => Point; scale: number } {
  const match = /^translate\(([^)]+)\) rotate\(([^)]+)\) scale\(([^)]+)\)$/.exec(transform)
  if (!match) throw new Error(`coil-s.svg: the head's transform "${transform}" is not translate rotate scale`)
  const [tx, ty] = numbers(match[1] as string) as [number, number]
  const [deg] = numbers(match[2] as string) as [number]
  const [scale] = numbers(match[3] as string) as [number]
  const cos = Math.cos((deg * Math.PI) / 180)
  const sin = Math.sin((deg * Math.PI) / 180)
  return { place: ([x, y]) => [tx + scale * (x * cos - y * sin), ty + scale * (x * sin + y * cos)], scale }
}

function circle(tag: string): Circle {
  return { at: [Number(attr(tag, "cx")), Number(attr(tag, "cy"))], r: Number(attr(tag, "r")) }
}

// The brand's coil: the line, then <g class="head"> holding the head's path
// and the eye (filled with --bg), then the sun (filled with --sun).
export function coilShapes(svg: string): Shapes {
  const view = numbers(attr(element(svg, "svg"), "viewBox"))
  const line = element(svg, "path")
  const headAt = svg.indexOf('<g class="head"')
  if (headAt < 0) throw new Error("coil-s.svg: no <g class=\"head\">")
  const { place, scale } = placement(attr(element(svg, "g", headAt), "transform"))
  const headPath = element(svg, "path", headAt)
  const eye = element(svg, "circle", headAt)
  if (!attr(eye, "fill").startsWith("var(--bg")) throw new Error("coil-s.svg: the head's circle is not the eye")
  const sun = element(svg, "circle", headAt + svg.slice(headAt).indexOf("</g>"))
  if (!attr(sun, "fill").startsWith("var(--sun")) throw new Error("coil-s.svg: the circle after the head is not the sun")
  return {
    size: view[2] ?? 64,
    line: polyline(attr(line, "d")),
    halfWidth: Number(attr(line, "stroke-width")) / 2,
    head: outline(attr(headPath, "d")).map(place),
    eye: { at: place(circle(eye).at), r: circle(eye).r * scale },
    sun: circle(sun),
  }
}

function segmentDistance(p: Point, a: Point, b: Point): number {
  const dx = b[0] - a[0]
  const dy = b[1] - a[1]
  const t = Math.max(0, Math.min(1, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy)))
  return Math.hypot(p[0] - (a[0] + t * dx), p[1] - (a[1] + t * dy))
}

function inCircle(p: Point, c: Circle): boolean {
  return Math.hypot(p[0] - c.at[0], p[1] - c.at[1]) <= c.r
}

function inPolygon(p: Point, polygon: Point[]): boolean {
  let inside = false
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const [xi, yi] = polygon[i] as Point
    const [xj, yj] = polygon[j] as Point
    if (yi > p[1] !== yj > p[1] && p[0] < ((xj - xi) * (p[1] - yi)) / (yj - yi) + xi) inside = !inside
  }
  return inside
}

// Which colour a point in coil space takes: the sun, the eye (the tile
// showing through the head), the line with round caps and joins, the head.
type Layer = "ink" | "sun" | "tile"

function layerAt(shapes: Shapes, p: Point): Layer {
  if (inCircle(p, shapes.sun)) return "sun"
  if (inCircle(p, shapes.eye)) return "tile"
  if (inPolygon(p, shapes.head)) return "ink"
  for (let i = 1; i < shapes.line.length; i++) {
    if (segmentDistance(p, shapes.line[i - 1] as Point, shapes.line[i] as Point) <= shapes.halfWidth) return "ink"
  }
  return "tile"
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
  return c >>> 0
})

function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff
  for (const byte of bytes) c = (CRC_TABLE[(c ^ byte) & 0xff] as number) ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

function chunk(type: string, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(12 + data.length)
  const view = new DataView(out.buffer)
  view.setUint32(0, data.length)
  out.set(new TextEncoder().encode(type), 4)
  out.set(data, 8)
  view.setUint32(8 + data.length, crc32(out.subarray(4, 8 + data.length)))
  return out
}

// 4 by 4 samples a pixel, for smooth edges.
const SAMPLES = 4

export function touchIconPng(svg: string, size = TOUCH_ICON_SIZE): Uint8Array {
  const shapes = coilShapes(svg)
  const box = size * COIL_SHARE
  const offset = (size - box) / 2
  const scale = shapes.size / box
  const raw = new Uint8Array(size * (1 + size * 3))
  for (let y = 0; y < size; y++) {
    const row = y * (1 + size * 3)
    for (let x = 0; x < size; x++) {
      const sum = [0, 0, 0]
      for (let sy = 0; sy < SAMPLES; sy++) {
        for (let sx = 0; sx < SAMPLES; sx++) {
          const p: Point = [(x + (sx + 0.5) / SAMPLES - offset) * scale, (y + (sy + 0.5) / SAMPLES - offset) * scale]
          const colour = PAPYRUS_ICON[layerAt(shapes, p)]
          for (let c = 0; c < 3; c++) sum[c] = (sum[c] as number) + (colour[c] as number)
        }
      }
      for (let c = 0; c < 3; c++) raw[row + 1 + x * 3 + c] = Math.round((sum[c] as number) / (SAMPLES * SAMPLES))
    }
  }
  const header = new Uint8Array(13)
  const view = new DataView(header.buffer)
  view.setUint32(0, size)
  view.setUint32(4, size)
  header.set([8, 2, 0, 0, 0], 8)
  const signature = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
  const parts = [signature, chunk("IHDR", header), chunk("IDAT", new Uint8Array(deflateSync(raw))), chunk("IEND", new Uint8Array(0))]
  const png = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const part of parts) {
    png.set(part, at)
    at += part.length
  }
  return png
}
