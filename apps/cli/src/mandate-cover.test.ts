import { expect, test } from "bun:test"
import type { MandateCoverHint } from "@mehen/protocol/mandate-terms"
import { type MandateCover, checkedMandateCover, mandateCoverText, readMandateCover } from "./mandate-cover.ts"

const vault = { vaultUrl: "https://vault.example", workspaceSlug: "space" }
const page = "https://vault.example/w/space/mandates/mdt_live"
const hint = (state: MandateCoverHint["state"], extra: Partial<MandateCover> = {}): MandateCover => ({ classes: ["send", "read"], state, mandate: state === "none" ? null : "mdt_live", url: state === "none" ? null : page, ...extra })

test("each state says one line: propose for none, with the flags propose takes; the page to pass on for the rest", () => {
  const gmail = { items: ["gmail-support"] }
  expect(mandateCoverText(hint("none", gmail), "cli")).toBe('A mandate could let this machine make requests like this without asking. If this kind of ask keeps coming, propose one for only this credential and these kinds: `mehen mandate propose --items gmail-support --classes read,send --note "<why>"`.')
  expect(mandateCoverText(hint("none", gmail), "mcp")).toBe('A mandate could let this machine make requests like this without asking. If this kind of ask keeps coming, propose one for only this credential and these kinds: vault_mandate { "action": "propose", "items": ["gmail-support"], "classes": ["read", "send"], "note": "<why>" }.')
  expect(mandateCoverText(hint("none"), "cli")).toContain('`mehen mandate propose --items <slug> --classes read,send --note "<why>"`')
  expect(mandateCoverText(hint("paused"), "mcp")).toBe(mandateCoverText(hint("paused"), "cli"))
  expect(mandateCoverText(hint("paused"), "cli")).toBe(`This machine's mandate is paused; the person who signed it can resume it at ${page}.`)
  expect(mandateCoverText(hint("tripped"), "cli")).toBe(`This machine's mandate is tripped; the person who signed it can resume it at ${page}.`)
  expect(mandateCoverText(hint("ended"), "cli")).toBe(`This machine's mandate has ended; its signer can sign it again at ${page}, or propose a new one.`)
  expect(mandateCoverText(hint("outside_schedule"), "cli")).toBe(`This machine's mandate does not cover this time; it covers its hours only (${page}).`)
  expect(mandateCoverText(hint("unticked", gmail), "cli")).toBe("This machine's mandate does not name read, send requests with gmail-support; if this keeps asking, propose its terms again with only those added (`mehen mandate show mdt_live` lists them).")
  expect(mandateCoverText(hint("unticked"), "mcp")).toBe('This machine\'s mandate does not name read, send requests with this credential; if this keeps asking, propose its terms again with only those added (vault_mandate { "action": "show", "id": "mdt_live" } lists them).')
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
  expect(readMandateCover(hint("none"), "gmail-support")).toEqual(hint("none", { items: ["gmail-support"] }))
  expect(readMandateCover({ ...hint("none"), items: ["all"] })).toEqual(hint("none"))
  for (const raw of [undefined, null, "none", { ...hint("paused"), state: "lapsed" }, { ...hint("paused"), classes: [] }, { ...hint("paused"), classes: ["publish"] }, { ...hint("paused"), mandate: "rul_live" }, { classes: ["send"], state: "none" }]) {
    expect(readMandateCover(raw), JSON.stringify(raw)).toBeNull()
  }
})
