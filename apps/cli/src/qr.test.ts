import { describe, expect, test } from "bun:test"
import {
  QR_MAX_VERSION,
  QR_MIN_VERSION,
  QR_QUIET_ZONE,
  formatInformation,
  qrCapacityBytes,
  qrMatrix,
  qrSizeOf,
  qrVersionFor,
  renderQr,
  rsRemainder,
  versionInformation,
} from "./qr.ts"

// The version 1 matrix was captured from ux/capture/qr-proto.ts and decoded
// by macOS Vision, with its timing modules at (6, 8) and (8, 6) corrected.
// The Mehen URL matrices were regenerated and independently matched against
// Python qrcode in byte mode at level M, with the same mask.
const VERSION_1_FIXTURE = {
  text: "jv.je/e/K7Q2MX",
  rows: [
    "#######.#.#...#######",
    "#.....#.#.....#.....#",
    "#.###.#...##..#.###.#",
    "#.###.#.#..#..#.###.#",
    "#.###.#..#.#..#.###.#",
    "#.....#..##...#.....#",
    "#######.#.#.#.#######",
    "........#..#.........",
    "#.##.###.##.#.#..#.##",
    "##.###..#.###########",
    "##.##.##.#...#...####",
    "###..#...#.#...##..##",
    "#######....#........#",
    "........#..#....#.#..",
    "#######.#..#..###.#..",
    "#.....#.###.....###.#",
    "#.###.#..#.#.#.#####.",
    "#.###.#.#.###.....##.",
    "#.###.#.#.#.####.....",
    "#.....#..##..###....#",
    "#######.#.#....##.#..",
  ],
}

const VERSION_3_FIXTURE = {
  text: "https://app.mehen.dev/e/K7Q2MXAB",
  rows: [
    "#######.#.######..###.#######",
    "#.....#.###..#..###...#.....#",
    "#.###.#....#....#.#.#.#.###.#",
    "#.###.#.##.##.##.###..#.###.#",
    "#.###.#...##..#.#..##.#.###.#",
    "#.....#......#.#####..#.....#",
    "#######.#.#.#.#.#.#.#.#######",
    "........##.##..#####.........",
    "#.##.###..##.#.#..###.#..#.##",
    "#...##..#.######.########...#",
    ".....##......#..#....####.##.",
    ".##.....#.###...#.#######...#",
    "......###.....##.##......##..",
    "...#.#.###.#..#.####..##..###",
    ".###.##.#..###.#####.##...###",
    "..###....#.#..#.#...#...#..#.",
    "..#####...###.##.##.##..##.#.",
    ".#...#.#..#...#.#.#.#..#.###.",
    "#.#.######..####..#..##.#.#..",
    "....#....##..###.###...#..#..",
    ".##.#####.##.##.##..#######..",
    "........###.#..##...#...#####",
    "#######.##..#.#.#..##.#.##.#.",
    "#.....#.#.#####.#..##...##..#",
    "#.###.#........#....#####.##.",
    "#.###.#.#....#..#....#..##..#",
    "#.###.#.#######.#.#.#..#..#.#",
    "#.....#..#######....#..###.#.",
    "#######.#.###.########.#...#.",
  ],
}

const VERSION_3_LONG_FIXTURE = {
  text: "https://app.mehen.dev/e/K7Q2MX4D9RTV3HNB",
  rows: [
    "#######.##..#.#...###.#######",
    "#.....#.#######..##...#.....#",
    "#.###.#...######..#.#.#.###.#",
    "#.###.#.#.##..######..#.###.#",
    "#.###.#..#...##.#..##.#.###.#",
    "#.....#...#.##..####..#.....#",
    "#######.#.#.#.#.#.#.#.#######",
    "........###...#.####.........",
    "#.##.###...#.##...###.#..#.##",
    "#.#.#..####..#.##########...#",
    ".##.#.#####..#.......####.##.",
    ".##.##.#.#...#.##.#######...#",
    "###.####.#..#.#####......##..",
    "#..##...###...#.####..##..###",
    ".#..###..#..#....###.##...###",
    "##.#.#.######..#....#...#..#.",
    "###...#..#..#.#####.##..##.#.",
    "...#.#.###..#..##.#.#..#.###.",
    "#..##.##..#.####..#..##.#.#..",
    "..##.#...##..##.####...#..#..",
    ".###..####.####.##..#######..",
    "........##.....##...#...#####",
    "#######.#.....#....##.#.##.#.",
    "#.....#.####.##....##...##..#",
    "#.###.#...#.#..##...#####.###",
    "#.###.#.##..##.#.....#..##..#",
    "#.###.#.#.#...#.#.#.#..#..#.#",
    "#.....#...##.###....#..###.#.",
    "#######.###....#######.#...#.",
  ],
}

// Byte capacity at level M for versions 1 to 10, from the published tables.
const CAPACITY_M = [14, 26, 42, 62, 84, 106, 122, 152, 180, 213]

const FINDER = ["#######", "#.....#", "#.###.#", "#.###.#", "#.###.#", "#.....#", "#######"]
const ALIGNMENT = ["#####", "#...#", "#.#.#", "#...#", "#####"]

function rowsOf(matrix: boolean[][]): string[] {
  return matrix.map((row) => row.map((dark) => (dark ? "#" : ".")).join(""))
}

function versionOf(matrix: boolean[][]): number {
  return (matrix.length - 17) / 4
}

function block(matrix: boolean[][], row0: number, column0: number, size: number): string[] {
  return matrix.slice(row0, row0 + size).map((row) => row.slice(column0, column0 + size).map((dark) => (dark ? "#" : ".")).join(""))
}

function bit(matrix: boolean[][], row: number, column: number): number {
  return matrix[row]?.[column] ? 1 : 0
}

// The two copies of the format information, read from where the
// specification places them.
function formatCopies(matrix: boolean[][]): [number, number] {
  const size = matrix.length
  let first = 0
  let second = 0
  for (let i = 0; i <= 5; i++) first |= bit(matrix, i, 8) << i
  first |= bit(matrix, 7, 8) << 6
  first |= bit(matrix, 8, 8) << 7
  first |= bit(matrix, 8, 7) << 8
  for (let i = 9; i < 15; i++) first |= bit(matrix, 8, 14 - i) << i
  for (let i = 0; i < 8; i++) second |= bit(matrix, 8, size - 1 - i) << i
  for (let i = 8; i < 15; i++) second |= bit(matrix, size - 15 + i, 8) << i
  return [first, second]
}

function versionCopies(matrix: boolean[][]): [number, number] {
  const size = matrix.length
  let first = 0
  let second = 0
  for (let i = 0; i < 18; i++) {
    first |= bit(matrix, Math.floor(i / 3), size - 11 + (i % 3)) << i
    second |= bit(matrix, size - 11 + (i % 3), Math.floor(i / 3)) << i
  }
  return [first, second]
}

// Reads a half-block render back into the drawn cells, two rows per line.
function drawnCells(render: string): boolean[][] {
  const cells: boolean[][] = []
  for (const line of render.split("\n")) {
    const top: boolean[] = []
    const bottom: boolean[] = []
    for (const char of line) {
      expect(["\u2588", "\u2580", "\u2584", " "]).toContain(char)
      top.push(char === "\u2588" || char === "\u2580")
      bottom.push(char === "\u2588" || char === "\u2584")
    }
    cells.push(top, bottom)
  }
  return cells
}

describe("qrMatrix known answers", () => {
  test.each([VERSION_1_FIXTURE, VERSION_3_FIXTURE, VERSION_3_LONG_FIXTURE])("matches the independently verified matrix for $text", ({ text, rows }) => {
    expect(rowsOf(qrMatrix(text))).toEqual(rows)
  })

  test("Reed-Solomon codewords match the published 1-M vectors", () => {
    // ISO/IEC 18004 Annex I: "01234567", numeric mode, version 1-M.
    expect(rsRemainder([0x10, 0x20, 0x0c, 0x56, 0x61, 0x80, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11], 10)).toEqual([
      0xa5, 0x24, 0xd4, 0xc1, 0xed, 0x36, 0xc7, 0x87, 0x2c, 0x55,
    ])
    // "HELLO WORLD", alphanumeric mode, version 1-M, as in the thonky tutorial.
    expect(rsRemainder([32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17], 10)).toEqual([
      196, 35, 39, 119, 235, 215, 231, 226, 93, 23,
    ])
  })
})

describe("format and version information", () => {
  test("format bits for level M match the published table for every mask", () => {
    expect([0, 1, 2, 3, 4, 5, 6, 7].map(formatInformation)).toEqual([0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0])
  })

  test("version bits match the published table for versions 7 to 10", () => {
    expect([7, 8, 9, 10].map(versionInformation)).toEqual([0x07c94, 0x085bc, 0x09a99, 0x0a4d3])
  })

  test("both format copies in the matrix are the same level M codeword", () => {
    for (const text of ["mehen", VERSION_3_FIXTURE.text, "x".repeat(200)]) {
      const [first, second] = formatCopies(qrMatrix(text))
      expect(second).toBe(first)
      const masks = [0, 1, 2, 3, 4, 5, 6, 7].filter((mask) => formatInformation(mask) === first)
      expect(masks).toHaveLength(1)
    }
  })

  test("version information appears in both places from version 7 and nowhere below", () => {
    for (let version = 7; version <= QR_MAX_VERSION; version++) {
      const matrix = qrMatrix("x".repeat(qrCapacityBytes(version)))
      expect(versionOf(matrix)).toBe(version)
      expect(versionCopies(matrix)).toEqual([versionInformation(version), versionInformation(version)])
    }
    const matrix = qrMatrix("x".repeat(qrCapacityBytes(6)))
    expect(versionOf(matrix)).toBe(6)
    const [first, second] = versionCopies(matrix)
    expect(first).not.toBe(versionInformation(6))
    expect(second).not.toBe(versionInformation(6))
  })
})

describe("version selection", () => {
  test("capacity at level M matches the published table", () => {
    const versions = Array.from({ length: QR_MAX_VERSION - QR_MIN_VERSION + 1 }, (_v, i) => QR_MIN_VERSION + i)
    expect(versions.map(qrCapacityBytes)).toEqual(CAPACITY_M)
  })

  test("the smallest version that fits is chosen, at every boundary", () => {
    CAPACITY_M.forEach((capacity, i) => {
      const version = i + 1
      expect(qrVersionFor(capacity)).toBe(version)
      expect(versionOf(qrMatrix("x".repeat(capacity)))).toBe(version)
      if (version < QR_MAX_VERSION) expect(versionOf(qrMatrix("x".repeat(capacity + 1)))).toBe(version + 1)
    })
    expect(versionOf(qrMatrix(""))).toBe(1)
  })

  test("a vault link with a 32-character code fits version 4 with room to spare", () => {
    const link = `https://app.mehen.dev/e/${"K7Q2MX4D9RTV3HNB".repeat(2)}`
    expect(link).toHaveLength(56)
    expect(versionOf(qrMatrix(link))).toBe(4)
    expect(versionOf(qrMatrix(`${link}${"x".repeat(6)}`))).toBe(4)
    expect(versionOf(qrMatrix(`${link}${"x".repeat(7)}`))).toBe(5)
  })

  test("text is measured in UTF-8 bytes", () => {
    expect(versionOf(qrMatrix("\u00e9".repeat(7)))).toBe(1)
    expect(versionOf(qrMatrix("\u00e9".repeat(8)))).toBe(2)
  })

  test("refuses text longer than version 10 holds, saying how long it may be", () => {
    expect(qrMatrix("x".repeat(213)).length).toBe(qrSizeOf(10))
    expect(() => qrMatrix("x".repeat(214))).toThrow(RangeError)
    expect(() => qrMatrix("x".repeat(214))).toThrow("QR text is 214 bytes; the largest code mehen draws (version 10, level M) holds 213.")
    expect(() => renderQr("x".repeat(300), { scheme: "dark" })).toThrow("QR text is 300 bytes")
  })
})

describe("function patterns", () => {
  test("every version has its finders, timing lines, dark module and size", () => {
    for (let version = QR_MIN_VERSION; version <= QR_MAX_VERSION; version++) {
      const matrix = qrMatrix(`version ${version} ${"x".repeat(qrCapacityBytes(version) - 12)}`)
      const size = qrSizeOf(version)
      expect(matrix).toHaveLength(size)
      for (const row of matrix) expect(row).toHaveLength(size)
      expect(block(matrix, 0, 0, 7)).toEqual(FINDER)
      expect(block(matrix, 0, size - 7, 7)).toEqual(FINDER)
      expect(block(matrix, size - 7, 0, 7)).toEqual(FINDER)
      for (let i = 0; i < 8; i++) {
        expect(bit(matrix, 7, i)).toBe(0)
        expect(bit(matrix, i, 7)).toBe(0)
        expect(bit(matrix, 7, size - 1 - i)).toBe(0)
        expect(bit(matrix, size - 8, i)).toBe(0)
      }
      for (let i = 8; i < size - 8; i++) {
        expect(bit(matrix, 6, i)).toBe(i % 2 === 0 ? 1 : 0)
        expect(bit(matrix, i, 6)).toBe(i % 2 === 0 ? 1 : 0)
      }
      expect(bit(matrix, size - 8, 8)).toBe(1)
    }
  })

  test("alignment patterns sit at the published centres and skip the finders", () => {
    expect(block(qrMatrix("mehen"), 0, 0, 1)).toEqual(["#"])
    expect(block(qrMatrix("x".repeat(15)), 16, 16, 5)).toEqual(ALIGNMENT)
    const seven = qrMatrix("x".repeat(107))
    expect(versionOf(seven)).toBe(7)
    for (const [row, column] of [
      [22, 6],
      [6, 22],
      [22, 22],
      [22, 38],
      [38, 22],
      [38, 38],
    ] as const) {
      expect(block(seven, row - 2, column - 2, 5)).toEqual(ALIGNMENT)
    }
    expect(block(seven, 4, 36, 5)).not.toEqual(ALIGNMENT)
    expect(block(seven, 36, 4, 5)).not.toEqual(ALIGNMENT)
  })
})

describe("renderQr", () => {
  const text = VERSION_3_FIXTURE.text
  const size = qrSizeOf(3)
  const width = size + 2 * QR_QUIET_ZONE

  test("is two module rows per line with a four-module quiet zone all round", () => {
    for (const scheme of ["dark", "light"] as const) {
      const lines = renderQr(text, { scheme }).split("\n")
      expect(lines).toHaveLength(Math.ceil(width / 2))
      for (const line of lines) expect([...line]).toHaveLength(width)
      const cells = drawnCells(lines.join("\n"))
      const quiet = scheme === "dark"
      for (let row = 0; row < cells.length; row++) {
        for (let column = 0; column < width; column++) {
          const inside = row >= QR_QUIET_ZONE && row < QR_QUIET_ZONE + size && column >= QR_QUIET_ZONE && column < QR_QUIET_ZONE + size
          if (!inside) expect(cells[row]?.[column]).toBe(quiet)
        }
      }
    }
  })

  test("the dark scheme draws the light modules and the light scheme draws the dark ones", () => {
    const matrix = qrMatrix(text)
    for (const scheme of ["dark", "light"] as const) {
      const cells = drawnCells(renderQr(text, { scheme }))
      const seen = cells.slice(QR_QUIET_ZONE, QR_QUIET_ZONE + size).map((row) => row.slice(QR_QUIET_ZONE, QR_QUIET_ZONE + size))
      const expected = matrix.map((row) => row.map((dark) => (scheme === "dark" ? !dark : dark)))
      expect(seen).toEqual(expected)
    }
  })

  test("the two schemes are exact complements of each other", () => {
    const dark = renderQr(text, { scheme: "dark" })
    const light = renderQr(text, { scheme: "light" })
    const flipped = [...dark].map((char) => ({ "\u2588": " ", " ": "\u2588", "\u2580": "\u2584", "\u2584": "\u2580" })[char] ?? char).join("")
    expect(flipped).toBe(light)
  })

  test("a version 3 code is 19 lines by 37 columns", () => {
    const lines = renderQr(text, { scheme: "dark" }).split("\n")
    expect(lines).toHaveLength(19)
    expect([...(lines[0] ?? "")]).toHaveLength(37)
    expect(lines[0]).toBe("\u2588".repeat(37))
    expect(lines[1]).toBe("\u2588".repeat(37))
    expect(lines[2]?.startsWith("\u2588\u2588\u2588\u2588 \u2584\u2584\u2584\u2584\u2584 ")).toBe(true)
  })
})
