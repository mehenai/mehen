// Builds the browser bundle the pages load: dist/assets/app.js and
// dist/assets/app.css, served by the ASSETS binding at /assets/*, plus
// dist/assets/theme.js (the few lines that apply a chosen appearance before
// first paint, built on their own from src/ui/client/theme.ts), and from
// packages/brand the fonts app.css names with their licences, the favicon
// and apple-touch-icon.png drawn from the reduced coil. Fixed names, no
// inline code, so the page CSP can stay at 'self'.
//
//   bun scripts/build-ui.ts

import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises"
import path from "node:path"
import { touchIconPng } from "./touch-icon.ts"

const root = path.resolve(import.meta.dir, "..")
const client = path.join(root, "src/ui/client")
const brand = path.resolve(root, "../../packages/brand")
const outdir = path.join(root, "dist/assets")

// The faces app.css names, and nothing else from the brand's font folder.
const FONTS = ["Inter-normal-100-900.woff2", "JetBrainsMono-normal-100-800.woff2", "Fraunces-normal-100-900.woff2", "OFL-inter.txt", "OFL-jetbrains-mono.txt", "OFL-fraunces.txt"]

await rm(outdir, { recursive: true, force: true })
await mkdir(path.join(outdir, "fonts"), { recursive: true })

const result = await Bun.build({
  entrypoints: [path.join(client, "main.ts"), path.join(client, "app.css")],
  outdir,
  target: "browser",
  format: "esm",
  minify: true,
  sourcemap: "none",
  naming: { entry: "app.[ext]" },
  // The fonts app.css names are served from the same static directory;
  // the bundler leaves the url() as written.
  external: ["/assets/*"],
})

if (!result.success) {
  for (const log of result.logs) console.error(log)
  process.exit(1)
}

// theme.js runs blocking in <head>, so it is a plain script, not a module.
const theme = await Bun.build({
  entrypoints: [path.join(client, "theme.ts")],
  outdir,
  target: "browser",
  format: "iife",
  minify: true,
  sourcemap: "none",
  naming: { entry: "theme.[ext]" },
})

if (!theme.success) {
  for (const log of theme.logs) console.error(log)
  process.exit(1)
}

for (const file of FONTS) await cp(path.join(brand, "fonts", file), path.join(outdir, "fonts", file))
await cp(path.join(brand, "marks/favicon.svg"), path.join(outdir, "favicon.svg"))
const touchIcon = touchIconPng(await readFile(path.join(brand, "marks/coil-s.svg"), "utf8"))
await writeFile(path.join(outdir, "apple-touch-icon.png"), touchIcon)

for (const output of [...result.outputs, ...theme.outputs]) {
  console.log(`${path.relative(root, output.path)}  ${(output.size / 1024).toFixed(1)} KB`)
}
console.log(`${FONTS.length} font files and favicon.svg copied from ${path.relative(root, brand)} to ${path.relative(root, outdir)}`)
console.log(`dist/assets/apple-touch-icon.png  ${(touchIcon.length / 1024).toFixed(1)} KB`)
