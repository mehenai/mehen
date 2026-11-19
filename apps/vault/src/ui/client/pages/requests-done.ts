// The "done" card the link-landed pages reveal once the request is decided,
// filled in, or rejected.

import { must } from "../dom.ts"

export function showDone(region: string, heading: string | null, text: string | null, hide: HTMLElement | null): void {
  const done = must(`[data-region="${region}"]`)
  if (heading !== null) must(`[data-region="${region}-heading"]`, done).textContent = heading
  if (text !== null) must(`[data-region="${region}-text"]`, done).textContent = text
  if (hide) hide.hidden = true
  done.hidden = false
  done.scrollIntoView({ block: "start", behavior: "smooth" })
}
