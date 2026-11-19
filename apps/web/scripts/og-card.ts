// Renders the social card, scripts/og-card.html, to public/og.jpg (1200 by
// 630) with the installed Google Chrome, headless, and macOS sips for the
// JPEG. A dev script for macOS: not part of build or CI, and the JPEG it
// writes is committed. Look at the image after running it.
//
//   bun scripts/og-card.ts            (from apps/web)
//   CHROME=/path/to/chrome bun scripts/og-card.ts

import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { pathToFileURL } from "node:url"

const root = path.resolve(import.meta.dir, "..")
const brand = path.resolve(root, "../../packages/brand")
const output = path.join(root, "public/og.jpg")
const chrome = process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
const WIDTH = 1200
const HEIGHT = 630

function run(command: string[]): void {
  const result = Bun.spawnSync(command, { stdout: "pipe", stderr: "pipe" })
  if (result.exitCode !== 0) throw new Error(`${path.basename(command[0] as string)} failed (${result.exitCode}): ${result.stderr.toString().trim()}`)
}

const template = await readFile(path.join(import.meta.dir, "og-card.html"), "utf8")
const mark = await readFile(path.join(brand, "marks/coil.svg"), "utf8")
const page = template
  .replace("{{TOKENS}}", pathToFileURL(path.join(brand, "tokens/papyrus.css")).href)
  .replace("{{MARK}}", mark.trim())
if (page.includes("{{")) throw new Error("og-card.html has a placeholder this script does not fill")

const scratch = await mkdtemp(path.join(tmpdir(), "mehen-og-"))
try {
  const html = path.join(scratch, "og-card.html")
  const png = path.join(scratch, "og.png")
  await writeFile(html, page)
  run([
    chrome,
    "--headless",
    `--user-data-dir=${path.join(scratch, "profile")}`,
    "--disable-gpu",
    "--hide-scrollbars",
    "--force-device-scale-factor=1",
    "--allow-file-access-from-files",
    "--virtual-time-budget=5000",
    `--window-size=${WIDTH},${HEIGHT}`,
    `--screenshot=${png}`,
    pathToFileURL(html).href,
  ])
  run(["sips", "-s", "format", "jpeg", "-s", "formatOptions", "95", png, "--out", output])
  const size = Bun.spawnSync(["sips", "-g", "pixelWidth", "-g", "pixelHeight", output]).stdout.toString()
  if (!size.includes(`pixelWidth: ${WIDTH}`) || !size.includes(`pixelHeight: ${HEIGHT}`)) throw new Error(`og.jpg is not ${WIDTH} by ${HEIGHT}:\n${size}`)
  console.log(`wrote ${path.relative(root, output)} (${WIDTH} by ${HEIGHT}, ${(await stat(output)).size} bytes)`)
} finally {
  await rm(scratch, { recursive: true, force: true })
}
