# @mehen/brand

The Mehen brand files the lander (`apps/web`) and the app (`apps/vault`) share. Plain files, no build step: consumers copy what they need into their own static directory.

| Path | What it is |
| --- | --- |
| `fonts/Fraunces-normal-100-900.woff2` | Fraunces, variable (wght 100 to 900, opsz, SOFT, WONK), upright. Display and headings. |
| `fonts/Fraunces-italic-100-900.woff2` | Fraunces italic, variable. The lander's closing line. |
| `fonts/Inter-normal-100-900.woff2` | Inter, variable. Body and UI. |
| `fonts/JetBrainsMono-normal-100-800.woff2` | JetBrains Mono, variable. Code, eyebrows and labels. |
| `fonts/OFL-*.txt` | The SIL Open Font License 1.1 notice for each family. Ship it next to the fonts. |
| `marks/coil.svg` | The primary mark: one line spirals in to a serpent head looking at the sun. Line in `currentColor`, sun `var(--sun)`, eye `var(--bg)`. 28 px and up. |
| `marks/coil-s.svg` | The reduced coil for 16 to 24 px. |
| `marks/crossing.svg` | The companion mark, a crescent holding the sun. Status dots, bullets, the approval badge, the 404. Never the main logo. |
| `marks/sprite.svg` | The three marks as `<symbol>`s (`m-coil`, `m-coil-s`, `m-crossing`) for inlining at the top of a page and using with `<use href="#m-coil">`. |
| `marks/favicon.svg` | The reduced coil in gold with an apricot sun on a midnight rounded square: reads on light and dark tabs. |
| `tokens/lapis.css` | The dark palette ("Lapis and gold") as custom properties on `:root`, with the `@font-face` rules. The old dark lander's palette; nothing imports it now. |
| `tokens/papyrus.css` | The light palette ("Papyrus") as custom properties on `:root`, with the `@font-face` rules. The app's default, and the lander's palette. |

The `@font-face` rules in the token files point at `../fonts/`, so a consumer that copies `tokens/` and `fonts/` side by side needs no edits.
