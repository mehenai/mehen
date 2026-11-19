import { expect, test } from "bun:test"
import type { MandateCoverHint } from "@mehen/protocol/mandate-terms"
import { checkedMandateCover, mandateCoverText, readMandateCover } from "./mandate-cover.ts"

const vault = { vaultUrl: "https://vault.example", workspaceSlug: "space" }
const page = "https://vault.example/w/space/mandates/mdt_live"
const hint = (state: MandateCoverHint["state"], extra: Partial<MandateCoverHint> = {}): MandateCoverHint => ({ classes: ["send", "read"], state, mandate: state === "none" ? null : "mdt_live", url: state === "none" ? null : page, ...extra })

test("each state says one line: propose for none, with the flags propose takes; the page to pass on for the rest", () => {
  expect(mandateCoverText(hint("none"), "cli")).toBe('A mandate could let this machine make requests like this without asking. If this kind of ask keeps coming, propose one: `mehen mandate propose --classes read,send --note "<why>"`.')
  expect(mandateCoverText(hint("none"), "mcp")).toBe('A mandate could let this machine make requests like this without asking. If this kind of ask keeps coming, propose one: vault_mandate { "action": "propose", "classes": ["read", "send"], "note": "<why>" }.')
  expect(mandateCoverText(hint("paused"), "mcp")).toBe(mandateCoverText(hint("paused"), "cli"))
  expect(mandateCoverText(hint("paused"), "cli")).toBe(`This machine's mandate is paused; the person who signed it can resume it at ${page}.`)
  expect(mandateCoverText(hint("tripped"), "cli")).toBe(`This machine's mandate is tripped; the person who signed it can resume it at ${page}.`)
  expect(mandateCoverText(hint("ended"), "cli")).toBe(`This machine's mandate has ended; its signer can sign it again at ${page}, or propose a new one.`)
  expect(mandateCoverText(hint("outside_schedule"), "cli")).toBe(`This machine's mandate does not cover this time; it covers its hours only (${page}).`)
  expect(mandateCoverText(hint("unticked"), "cli")).toBe("This machine's mandate does not name this kind of request or this credential; if this keeps asking, propose wider terms.")
  expect(mandateCoverText(hint("not_covering"), "cli")).toBe(`This machine's mandate is not covering requests right now; its signer can see why at ${page}.`)
  expect(mandateCoverText(hint("paused", { url: null }), "cli")).toBe("This machine's mandate is paused; the person who signed it can resume it on its page.")
  expect(mandateCoverText(hint("outside_schedule", { url: null }), "cli")).toBe("This machine's mandate does not cover this time; it covers its hours only.")
})

test("refusal/the link is this vault's page for the hint's own mandate, else rebuilt from its id, else none", () => {
  expect(checkedMandateCover(hint("paused"), vault).url).toBe(page)
  for (const url of ["https://evil.example/w/space/mandates/mdt_live", "https://vault.example/w/space/mandates/mdt_other", "https://vault.example/w/other/mandates/mdt_live", "https://vault.example/w/space/a/apr_1", null]) {
    expect(checkedMandateCover(hint("paused", { url }), vault).url, String(url)).toBe(page)
  }
  expect(checkedMandateCover(hint("paused"), { vaultUrl: "https://vault.example", workspaceSlug: null }).url).toBeNull()
  expect(checkedMandateCover(hint("paused"), null).url).toBeNull()
  expect(checkedMandateCover(hint("none", { url: page }), vault).url).toBeNull()
})

test("refusal/a hint that is not one is dropped whole", () => {
  expect(readMandateCover(hint("paused"))).toEqual(hint("paused"))
  for (const raw of [undefined, null, "none", { ...hint("paused"), state: "lapsed" }, { ...hint("paused"), classes: [] }, { ...hint("paused"), classes: ["publish"] }, { ...hint("paused"), mandate: "rul_live" }, { classes: ["send"], state: "none" }]) {
    expect(readMandateCover(raw), JSON.stringify(raw)).toBeNull()
  }
})
