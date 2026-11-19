// Copies the brand files the lander serves from packages/brand into public/: the fonts with their
// licences and the favicon, and the installer. style.css carries the palette and the @font-face rules itself, so no
// tokens file is copied. public/fonts and public/favicon.svg are build output and gitignored.
//
//   bun scripts/build.ts

import { cp, mkdir, rm } from "node:fs/promises"
import path from "node:path"

const root = path.resolve(import.meta.dir, "..")
const brand = path.resolve(root, "../../packages/brand")
const output = path.join(root, "public")

const copies: [from: string, to: string][] = [
  ["fonts", "fonts"],
  ["marks/favicon.svg", "favicon.svg"],
]

// Build output from earlier versions of the page that nothing references any more.
const stale = ["marks", "tokens"]

for (const [from, to] of copies) {
  const target = path.join(output, to)
  await rm(target, { recursive: true, force: true })
  await mkdir(path.dirname(target), { recursive: true })
  await cp(path.join(brand, from), target, { recursive: true })
}
for (const dir of stale) await rm(path.join(output, dir), { recursive: true, force: true })

console.log(`copied ${copies.length} brand paths into ${path.relative(root, output)}/`)

// The installer is copied byte for byte from its source. The agent guides
// (setup.md, skill.md, llms.txt) live on the docs site; src/index.ts
// redirects their old addresses there.
await cp(path.resolve(root, "../..", "tools/release/install.sh"), path.join(output, "install"))
// Build output from before the guides moved, so a stale copy is never served.
for (const name of ["skill.md", "setup.md", "setup", "llms.txt"]) await rm(path.join(output, name), { recursive: true, force: true })
