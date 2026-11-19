// QR codes for links printed at a terminal, so a phone camera can take the
// link off the screen. Byte mode, error correction level M, versions 1 to 10
// (up to 213 bytes), written from ISO/IEC 18004 with no library code.
// `qrMatrix` gives the module grid; `renderQr` draws it with half-block
// characters for a dark or light terminal theme.

export type QrScheme = "dark" | "light"

export type QrRenderOptions = { scheme: QrScheme }

export const QR_MIN_VERSION = 1
export const QR_MAX_VERSION = 10
export const QR_QUIET_ZONE = 4

// Level M block structure per version: error correction codewords per block,
// then the blocks as (count, data codewords each). Alignment pattern centres
// are the row and column coordinates, used for every pair not under a finder.
type VersionLayout = {
  ecPerBlock: number
  blocks: ReadonlyArray<readonly [count: number, dataCodewords: number]>
  alignment: readonly number[]
}

const LAYOUTS: readonly VersionLayout[] = [
  { ecPerBlock: 10, blocks: [[1, 16]], alignment: [] },
  { ecPerBlock: 16, blocks: [[1, 28]], alignment: [6, 18] },
  { ecPerBlock: 26, blocks: [[1, 44]], alignment: [6, 22] },
  { ecPerBlock: 18, blocks: [[2, 32]], alignment: [6, 26] },
  { ecPerBlock: 24, blocks: [[2, 43]], alignment: [6, 30] },
  { ecPerBlock: 16, blocks: [[4, 27]], alignment: [6, 34] },
  { ecPerBlock: 18, blocks: [[4, 31]], alignment: [6, 22, 38] },
  { ecPerBlock: 22, blocks: [[2, 38], [2, 39]], alignment: [6, 24, 42] },
  { ecPerBlock: 22, blocks: [[3, 36], [2, 37]], alignment: [6, 26, 46] },
  { ecPerBlock: 26, blocks: [[4, 43], [1, 44]], alignment: [6, 28, 50] },
]

const BYTE_MODE = 0b0100
const FORMAT_LEVEL_M = 0b00
const FORMAT_GENERATOR = 0x537
const FORMAT_MASK = 0x5412
const VERSION_GENERATOR = 0x1f25
const PAD_CODEWORDS = [0xec, 0x11] as const

function layoutOf(version: number): VersionLayout {
  const layout = LAYOUTS[version - QR_MIN_VERSION]
  if (!layout) throw new RangeError(`QR version ${version} is outside ${QR_MIN_VERSION} to ${QR_MAX_VERSION}`)
  return layout
}

function dataCodewordsOf(layout: VersionLayout): number {
  return layout.blocks.reduce((sum, [count, dataCodewords]) => sum + count * dataCodewords, 0)
}

export function qrSizeOf(version: number): number {
  return 17 + 4 * version
}

// Bytes of text a version holds at level M: the data codewords less the
// 4-bit mode indicator and the 8-bit length (16 bits from version 10).
export function qrCapacityBytes(version: number): number {
  const headerBits = 4 + (version >= 10 ? 16 : 8)
  return Math.floor((dataCodewordsOf(layoutOf(version)) * 8 - headerBits) / 8)
}

export function qrVersionFor(byteLength: number): number {
  for (let version = QR_MIN_VERSION; version <= QR_MAX_VERSION; version++) {
    if (qrCapacityBytes(version) >= byteLength) return version
  }
  throw new RangeError(
    `QR text is ${byteLength} bytes; the largest code mehen draws (version ${QR_MAX_VERSION}, level M) holds ${qrCapacityBytes(QR_MAX_VERSION)}. Print the link without a QR code.`,
  )
}

// GF(256) with the QR polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d).
const GF_EXP = new Uint8Array(512)
const GF_LOG = new Uint8Array(256)
for (let i = 0, x = 1; i < 255; i++) {
  GF_EXP[i] = x
  GF_LOG[x] = i
  x <<= 1
  if (x & 0x100) x ^= 0x11d
}
for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255] ?? 0

function gfMultiply(a: number, b: number): number {
  if (a === 0 || b === 0) return 0
  return GF_EXP[(GF_LOG[a] ?? 0) + (GF_LOG[b] ?? 0)] ?? 0
}

function rsGenerator(degree: number): number[] {
  let generator = [1]
  for (let root = 0; root < degree; root++) {
    const next = new Array<number>(generator.length + 1).fill(0)
    generator.forEach((coefficient, i) => {
      next[i] = (next[i] ?? 0) ^ coefficient
      next[i + 1] = (next[i + 1] ?? 0) ^ gfMultiply(coefficient, GF_EXP[root] ?? 0)
    })
    generator = next
  }
  return generator
}

// The Reed-Solomon error correction codewords for one block.
export function rsRemainder(data: readonly number[], degree: number): number[] {
  const generator = rsGenerator(degree)
  const remainder = new Array<number>(degree).fill(0)
  for (const byte of data) {
    const factor = byte ^ (remainder.shift() ?? 0)
    remainder.push(0)
    for (let i = 0; i < degree; i++) remainder[i] = (remainder[i] ?? 0) ^ gfMultiply(generator[i + 1] ?? 0, factor)
  }
  return remainder
}

// The remainder of `value` shifted by `degree` bits, modulo the BCH generator.
function bchRemainder(value: number, generator: number, degree: number): number {
  let remainder = value
  for (let i = 0; i < degree; i++) remainder = (remainder << 1) ^ ((remainder >>> (degree - 1)) * generator)
  return remainder
}

// The 15 format information bits for level M and a mask pattern.
export function formatInformation(mask: number): number {
  const data = (FORMAT_LEVEL_M << 3) | mask
  return ((data << 10) | bchRemainder(data, FORMAT_GENERATOR, 10)) ^ FORMAT_MASK
}

// The 18 version information bits, present from version 7.
export function versionInformation(version: number): number {
  return (version << 12) | bchRemainder(version, VERSION_GENERATOR, 12)
}

function dataBits(bytes: Uint8Array, version: number): number[] {
  const capacityBits = dataCodewordsOf(layoutOf(version)) * 8
  const bits: number[] = []
  const push = (value: number, length: number): void => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1)
  }
  push(BYTE_MODE, 4)
  push(bytes.length, version >= 10 ? 16 : 8)
  for (const byte of bytes) push(byte, 8)
  push(0, Math.min(4, capacityBits - bits.length))
  while (bits.length % 8 !== 0) bits.push(0)
  for (let pad = 0; bits.length < capacityBits; pad++) push(PAD_CODEWORDS[pad % 2] ?? 0, 8)
  return bits
}

function toCodewords(bits: readonly number[]): number[] {
  const codewords: number[] = []
  for (let i = 0; i < bits.length; i += 8) {
    let value = 0
    for (let bit = 0; bit < 8; bit++) value = (value << 1) | (bits[i + bit] ?? 0)
    codewords.push(value)
  }
  return codewords
}

// Split the data into blocks, add error correction to each and interleave:
// the first codeword of every block, then the second, and so on, with the
// error correction codewords after all the data.
function interleave(data: readonly number[], layout: VersionLayout): number[] {
  const blocks: number[][] = []
  let offset = 0
  for (const [count, dataCodewords] of layout.blocks) {
    for (let i = 0; i < count; i++) {
      blocks.push(data.slice(offset, offset + dataCodewords))
      offset += dataCodewords
    }
  }
  const ecBlocks = blocks.map((block) => rsRemainder(block, layout.ecPerBlock))
  const longest = Math.max(...blocks.map((block) => block.length))
  const out: number[] = []
  for (let i = 0; i < longest; i++) for (const block of blocks) if (i < block.length) out.push(block[i] ?? 0)
  for (let i = 0; i < layout.ecPerBlock; i++) for (const block of ecBlocks) out.push(block[i] ?? 0)
  return out
}

type Grid = boolean[][]

function emptyGrid(size: number): Grid {
  return Array.from({ length: size }, () => new Array<boolean>(size).fill(false))
}

function cloneGrid(grid: Grid): Grid {
  return grid.map((row) => [...row])
}

// The function patterns: finders with their separators, timing lines,
// alignment patterns, the dark module, reserved format areas and, from
// version 7, the version information. `reserved` marks every module the data
// must not touch.
function drawFunctionPatterns(version: number): { modules: Grid; reserved: Grid } {
  const size = qrSizeOf(version)
  const modules = emptyGrid(size)
  const reserved = emptyGrid(size)
  const set = (row: number, column: number, dark: boolean): void => {
    if (row < 0 || column < 0 || row >= size || column >= size) return
    const moduleRow = modules[row]
    const reservedRow = reserved[row]
    if (!moduleRow || !reservedRow) return
    moduleRow[column] = dark
    reservedRow[column] = true
  }

  const finder = (row0: number, column0: number): void => {
    for (let row = -1; row <= 7; row++) {
      for (let column = -1; column <= 7; column++) {
        const inside = row >= 0 && row <= 6 && column >= 0 && column <= 6
        const ring = row === 0 || row === 6 || column === 0 || column === 6
        const centre = row >= 2 && row <= 4 && column >= 2 && column <= 4
        set(row0 + row, column0 + column, inside && (ring || centre))
      }
    }
  }
  finder(0, 0)
  finder(0, size - 7)
  finder(size - 7, 0)

  for (let i = 8; i < size - 8; i++) {
    set(6, i, i % 2 === 0)
    set(i, 6, i % 2 === 0)
  }

  const { alignment } = layoutOf(version)
  for (const row of alignment) {
    for (const column of alignment) {
      const underFinder = (row <= 8 && column <= 8) || (row <= 8 && column >= size - 9) || (row >= size - 9 && column <= 8)
      if (underFinder) continue
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) set(row + dr, column + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1)
      }
    }
  }

  for (let i = 0; i < 9; i++) {
    if (i === 6) continue
    set(8, i, false)
    set(i, 8, false)
  }
  for (let i = 0; i < 8; i++) {
    set(8, size - 1 - i, false)
    set(size - 1 - i, 8, false)
  }
  set(size - 8, 8, true)

  if (version >= 7) {
    const bits = versionInformation(version)
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1
      set(Math.floor(i / 3), size - 11 + (i % 3), dark)
      set(size - 11 + (i % 3), Math.floor(i / 3), dark)
    }
  }
  return { modules, reserved }
}

// Codewords go into the free modules two columns at a time, zigzagging up
// and down from the right edge, skipping the vertical timing column.
function placeData(modules: Grid, reserved: Grid, codewords: readonly number[]): void {
  const size = modules.length
  let index = 0
  const totalBits = codewords.length * 8
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let step = 0; step < size; step++) {
      for (let j = 0; j < 2; j++) {
        const column = right - j
        const upward = ((right + 1) & 2) === 0
        const row = upward ? size - 1 - step : step
        if (reserved[row]?.[column]) continue
        const moduleRow = modules[row]
        if (!moduleRow) continue
        const codeword = codewords[index >>> 3] ?? 0
        moduleRow[column] = index < totalBits && ((codeword >>> (7 - (index & 7))) & 1) === 1
        index++
      }
    }
  }
}

const MASKS: ReadonlyArray<(row: number, column: number) => boolean> = [
  (row, column) => (row + column) % 2 === 0,
  (row) => row % 2 === 0,
  (_row, column) => column % 3 === 0,
  (row, column) => (row + column) % 3 === 0,
  (row, column) => (Math.floor(row / 2) + Math.floor(column / 3)) % 2 === 0,
  (row, column) => ((row * column) % 2) + ((row * column) % 3) === 0,
  (row, column) => (((row * column) % 2) + ((row * column) % 3)) % 2 === 0,
  (row, column) => (((row + column) % 2) + ((row * column) % 3)) % 2 === 0,
]

function applyMask(grid: Grid, reserved: Grid, mask: number): Grid {
  const pattern = MASKS[mask]
  if (!pattern) throw new RangeError(`QR mask ${mask} is outside 0 to 7`)
  const out = cloneGrid(grid)
  out.forEach((row, r) => {
    row.forEach((dark, c) => {
      if (!reserved[r]?.[c] && pattern(r, c)) row[c] = !dark
    })
  })
  return out
}

// Both copies of the format information, around the top-left finder and
// split between the other two, as laid out in the specification.
function writeFormatInformation(grid: Grid, mask: number): void {
  const size = grid.length
  const bits = formatInformation(mask)
  const set = (row: number, column: number, dark: boolean): void => {
    const moduleRow = grid[row]
    if (moduleRow) moduleRow[column] = dark
  }
  const bit = (i: number): boolean => ((bits >>> i) & 1) === 1
  for (let i = 0; i <= 5; i++) set(i, 8, bit(i))
  set(7, 8, bit(6))
  set(8, 8, bit(7))
  set(8, 7, bit(8))
  for (let i = 9; i < 15; i++) set(8, 14 - i, bit(i))
  for (let i = 0; i < 8; i++) set(8, size - 1 - i, bit(i))
  for (let i = 8; i < 15; i++) set(size - 15 + i, 8, bit(i))
  set(size - 8, 8, true)
}

function columnOf(grid: Grid, column: number): boolean[] {
  return grid.map((row) => row[column] ?? false)
}

// The four penalty rules of the specification: runs of five or more alike
// modules, two by two blocks, finder-like 1:1:3:1:1 patterns next to four
// light modules, and the dark module ratio away from fifty percent.
function penaltyOf(grid: Grid): number {
  const size = grid.length
  const lines = [...grid, ...grid.map((_row, column) => columnOf(grid, column))]
  let score = 0

  for (const line of lines) {
    let run = 1
    for (let i = 1; i <= line.length; i++) {
      if (i < line.length && line[i] === line[i - 1]) {
        run++
        continue
      }
      if (run >= 5) score += 3 + (run - 5)
      run = 1
    }
  }

  for (let row = 0; row < size - 1; row++) {
    for (let column = 0; column < size - 1; column++) {
      const dark = grid[row]?.[column]
      if (dark === grid[row]?.[column + 1] && dark === grid[row + 1]?.[column] && dark === grid[row + 1]?.[column + 1]) score += 3
    }
  }

  for (const line of lines) {
    const text = line.map((dark) => (dark ? "1" : "0")).join("")
    const occurrences = (needle: string): number => text.split(needle).length - 1
    score += 40 * (occurrences("10111010000") + occurrences("00001011101"))
  }

  const darkCount = grid.flat().filter(Boolean).length
  const percent = Math.floor((darkCount * 100) / (size * size))
  const deviation = Math.min(Math.abs(percent - 50), Math.abs(percent + 5 - 50), Math.abs(percent - 5 - 50))
  score += Math.floor(deviation / 5) * 10
  return score
}

// The module grid, `matrix[row][column]`, true for a dark module. No quiet
// zone: the renderer adds it.
export function qrMatrix(text: string): boolean[][] {
  const bytes = new TextEncoder().encode(text)
  const version = qrVersionFor(bytes.length)
  const layout = layoutOf(version)
  const codewords = interleave(toCodewords(dataBits(bytes, version)), layout)
  const { modules, reserved } = drawFunctionPatterns(version)
  placeData(modules, reserved, codewords)

  let best: Grid = modules
  let bestScore = Number.POSITIVE_INFINITY
  for (let mask = 0; mask < MASKS.length; mask++) {
    const candidate = applyMask(modules, reserved, mask)
    writeFormatInformation(candidate, mask)
    const score = penaltyOf(candidate)
    if (score < bestScore) {
      bestScore = score
      best = candidate
    }
  }
  return best
}

const HALF_BLOCKS = { both: "\u2588", top: "\u2580", bottom: "\u2584", neither: " " } as const

// Two module rows per text line, with a four-module quiet zone all round.
// On a dark theme the light modules are drawn with the foreground colour, so
// the code is dark on a light panel; on a light theme the dark modules are
// drawn instead. Both polarities are read by phone cameras.
export function renderQr(text: string, options: QrRenderOptions): string {
  const matrix = qrMatrix(text)
  const size = matrix.length
  const total = size + 2 * QR_QUIET_ZONE
  const drawn = (row: number, column: number): boolean => {
    const dark = matrix[row - QR_QUIET_ZONE]?.[column - QR_QUIET_ZONE] ?? false
    return options.scheme === "dark" ? !dark : dark
  }
  const lines: string[] = []
  for (let row = 0; row < total; row += 2) {
    let line = ""
    for (let column = 0; column < total; column++) {
      const top = drawn(row, column)
      const bottom = drawn(row + 1, column)
      line += top && bottom ? HALF_BLOCKS.both : top ? HALF_BLOCKS.top : bottom ? HALF_BLOCKS.bottom : HALF_BLOCKS.neither
    }
    lines.push(line)
  }
  return lines.join("\n")
}
