// The two card documents, each one self-contained HTML5 page: inline style,
// inline script (bundled from ask-card.ts and adopt-card.ts by the macro at
// transpile time) and a CSP that allows no network at all.

import { browserScript } from "./bundle.ts" with { type: "macro" }
import { CARD_STYLES } from "./card-styles.ts"

export const CARD_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:"

// Nothing in the bundle may close the script element or open a comment in it.
export function inlineScript(script: string): string {
  return script.replace(/<\/(script)/gi, "<\\/$1").replace(/<!--/g, "<\\!--")
}

export function cardDocument(title: string, script: string): string {
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<meta http-equiv="Content-Security-Policy" content="${CARD_CSP}">`,
    `<title>${title}</title>`,
    `<style>${CARD_STYLES}</style>`,
    "</head>",
    "<body>",
    '<main id="card"></main>',
    `<script>${inlineScript(script)}</script>`,
    "</body>",
    "</html>",
  ].join("\n")
}

export const ASK_CARD_HTML = cardDocument("Mehen ask", browserScript("./ask-card.ts"))
export const ADOPT_CARD_HTML = cardDocument("Mehen adoption", browserScript("./adopt-card.ts"))
