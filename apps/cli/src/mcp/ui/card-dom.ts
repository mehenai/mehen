// DOM helpers both cards share. Every string from a result goes in through
// textContent; the only markup made here is fixed SVG built with DOM calls.

import type { Bridge, HostContext } from "./bridge.ts"

type Child = Node | string | null | false

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: { class?: string; text?: string; attrs?: Record<string, string> } = {}, children: Child[] = []): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  if (props.class) node.className = props.class
  if (props.text !== undefined) node.textContent = props.text
  for (const [name, value] of Object.entries(props.attrs ?? {})) node.setAttribute(name, value)
  for (const child of children) if (child !== null && child !== false) node.append(child)
  return node
}

const SVG = "http://www.w3.org/2000/svg"

// A small stroked icon from fixed path data.
function icon(paths: string[]): SVGSVGElement {
  const svg = document.createElementNS(SVG, "svg")
  svg.setAttribute("viewBox", "0 0 16 16")
  svg.setAttribute("fill", "none")
  svg.setAttribute("stroke", "currentColor")
  svg.setAttribute("stroke-width", "1.6")
  svg.setAttribute("stroke-linecap", "round")
  svg.setAttribute("stroke-linejoin", "round")
  svg.setAttribute("aria-hidden", "true")
  for (const d of paths) {
    const path = document.createElementNS(SVG, "path")
    path.setAttribute("d", d)
    svg.append(path)
  }
  return svg
}

export const externalIcon = () => icon(["M9 3h4v4", "M13 3 7.5 8.5", "M11 9.5V12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h2.5"])
export const shieldIcon = () => icon(["M8 1.8 3 3.7v3.8c0 3 2.1 5.6 5 6.7 2.9-1.1 5-3.7 5-6.7V3.7z", "m5.9 8 1.5 1.5 2.8-3"])

const VARIABLE = /^--[a-z0-9-]{1,64}$/

// The host's theme and style variables on the root element; with no theme
// the system's colour scheme applies.
export function applyHostContext(context: HostContext): void {
  const root = document.documentElement
  for (const [name, value] of Object.entries(context.styles?.variables ?? {})) {
    if (VARIABLE.test(name) && typeof value === "string") root.style.setProperty(name, value)
  }
  if (context.theme === "light" || context.theme === "dark") root.dataset.theme = context.theme
}

export function footer(): HTMLElement {
  return el("p", { class: "footer" }, [shieldIcon(), el("span", { text: "Approval happens on the vault page with a passkey; nothing in this chat can approve it." })])
}

// "Open in vault" through the host, or the link as selectable text when the
// host cannot open links or did not open this one.
export function openControl(bridge: Bridge, url: string, openable: boolean, size: "primary" | "secondary"): HTMLElement {
  const box = el("div", { class: "actions" })
  const asText = (label: string) => box.replaceChildren(el("div", { class: "url-box" }, [el("p", { class: "url-label", text: label }), el("code", { class: "url", text: url })]))
  if (!openable) {
    asText("This link cannot be opened from here. Check it, then open it in a browser:")
    return box
  }
  if (!bridge.capabilities.openLinks) {
    asText("Open this link in your browser:")
    return box
  }
  const button = el("button", { class: size, attrs: { type: "button" } }, [el("span", { text: "Open in vault" }), externalIcon()])
  button.addEventListener("click", () => {
    bridge.openLink(url).then(
      (opened) => {
        if (!opened) asText("Your app did not open the link. Open it in a browser:")
      },
      () => asText("Your app did not open the link. Open it in a browser:"),
    )
  })
  box.append(button)
  return box
}
