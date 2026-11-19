// The adoption review page's rules: which rows start ticked, how rows
// group, the decisions the passkey signs (every row once, a ticked row
// only into a home this person may choose), the bar's counts, and the rows
// an all-or-nothing refusal names; for a compare row, the actions it may
// take, the one it starts with, and the name a copy is proposed under.

import { describe, expect, it } from "vitest"
import { adoptionDigest } from "@mehen/protocol/adopt"
import { canonicalJson } from "@mehen/protocol/canonical-json"
import { sha256B64 } from "@mehen/protocol/bytes"
import { GALLERY_ADOPTION, GALLERY_CONFLICT_ADOPTION } from "../src/ui/workspace-asks-gallery.ts"
import { CHANGED_SINCE_SHOWN } from "../src/ui/client/workspace-logic.ts"
import { ADOPTION_HOLDER_GONE } from "../src/adoption-words.ts"
import { type AdoptionChoice, ADOPTION_DECISION_NEEDED, adoptionKeepOpenWords, adoptionKeepOpenShown, adoptionApproveAction, adoptionKeepVaultRefs, adoptionShownRefusal, adoptionUndecided, adoptionUndecidedWords, ADOPTION_HOME_NEEDED, ADOPTION_RENAME_INVALID, NO_REPO_WORDS, adoptionActions, adoptionApproveLabel, adoptionDecisions, adoptionDefaultAction, adoptionGroups, adoptionHomeCounts, adoptionRefusals, adoptionRenameSlug, adoptionStartHome, adoptionTickedByDefault } from "../src/ui/client/pages/workspace-adopt-logic.ts"

const ITEMS = GALLERY_ADOPTION.items
const item = (ref: string) => ITEMS.find((i) => i.ref === ref) as (typeof ITEMS)[number]

describe("the rows that start ticked", () => {
  it("leave out a custom destination, a stale source and a row with a problem", () => {
    expect(ITEMS.filter(adoptionTickedByDefault).map((i) => i.ref)).toEqual(["a001", "a004"])
  })

  it("keep a row ticked when a fresh file holds the same value as its stale copy", () => {
    const fresh = item("a001")
    const both = { ...fresh, sources: [...fresh.sources, ...item("a003").sources] }
    expect(adoptionTickedByDefault(both)).toBe(true)
    expect(adoptionTickedByDefault({ ...fresh, sources: item("a003").sources })).toBe(false)
  })

  it("start a row whose proposed home is refused with no home chosen", () => {
    expect(adoptionStartHome(item("a005"))).toBeNull()
    expect(adoptionStartHome(item("a001"))).toEqual({ kind: "project", project: "prj_platform01" })
  })
})

describe("the groups", () => {
  it("are by repository, then by the folder of the first source, rows by ref", () => {
    expect(adoptionGroups(ITEMS).map((g) => [g.repo, g.folders.map((f) => [f.folder, f.items.map((i) => i.ref)])])).toEqual([
      [NO_REPO_WORDS, [["/Users/alex/.config/scripts", ["a004"]]]],
      ["github.com/northwind/platform, environment dev", [["/Users/alex/code/platform", ["a001", "a002", "a003"]]]],
      ["github.com/northwind/website", [["/Users/alex/code/website", ["a005"]]]],
    ])
  })
})

describe("the decisions the passkey signs", () => {
  it("carry every row once, a ticked row stored explicitly; an unticked row keeps its proposed home", () => {
    const built = adoptionDecisions(GALLERY_ADOPTION.adoption, ITEMS, new Map([["a001", { include: true, home: "workspace" }], ["a005", { include: false, home: "" }]]))
    expect(built).toEqual({
      ok: true,
      decisions: [
        { ref: "a001", include: true, home: { kind: "workspace" }, action: "store" },
        { ref: "a002", include: false, home: item("a002").home },
        { ref: "a003", include: false, home: item("a003").home },
        { ref: "a004", include: false, home: item("a004").home },
        { ref: "a005", include: false, home: item("a005").home },
      ],
    })
  })

  it("refuse a ticked row without a home this person may choose", () => {
    expect(adoptionDecisions(GALLERY_ADOPTION.adoption, ITEMS, new Map([["a005", { include: true, home: "" }]]))).toEqual({ ok: false, error: ADOPTION_HOME_NEEDED("openai-website") })
    expect(adoptionDecisions(GALLERY_ADOPTION.adoption, ITEMS, new Map([["a005", { include: true, home: "project:prj_website01" }]]))).toEqual({ ok: false, error: ADOPTION_HOME_NEEDED("openai-website") })
  })

  it("sign another digest when a row is unticked or rehomed", async () => {
    const decide = async (choices: [string, { include: boolean; home: string }][]) => {
      const built = adoptionDecisions(GALLERY_ADOPTION.adoption, ITEMS, new Map(choices))
      if (!built.ok) throw new Error(built.error.message)
      return adoptionDigest(GALLERY_ADOPTION.adoption, ITEMS, built.decisions)
    }
    const ticked = await decide([["a001", { include: true, home: "workspace" }]])
    expect(await decide([["a001", { include: false, home: "workspace" }]])).not.toBe(ticked)
    expect(await decide([["a001", { include: true, home: "member:mem_alex0001" }]])).not.toBe(ticked)
    expect(await decide([["a001", { include: true, home: "workspace" }]])).toBe(ticked)
  })
})

describe("a row with no compare view", () => {
  it("is only stored, and signs the bytes a store-only page signed before actions existed", async () => {
    for (const i of [...ITEMS, ...CONFLICT.filter((c) => c.compare === null && c.problem === null)]) expect(adoptionActions(i, GALLERY_CONFLICT_ADOPTION.adoption), i.ref).toEqual(["store"])
    const built = adoptionDecisions(GALLERY_ADOPTION.adoption, ITEMS, new Map([["a001", { include: true, home: "workspace" }], ["a004", { include: true, home: "member:mem_alex0001" }]]))
    if (!built.ok) throw new Error(built.error.message)
    const stored = (i: (typeof ITEMS)[number], home: object) => ({ ref: i.ref, include: true, slug: i.slug, kind: i.kind, provider: i.provider, binding: i.binding.value, injection: i.injection.value, home, tags: [...i.tags].sort(), publicFields: i.publicFields, secrets: i.secrets.map((s) => ({ name: s.name, length: s.length, prefix: s.prefix, fingerprint: s.fingerprint, box: s.box })) })
    const before = { adoption: GALLERY_ADOPTION.adoption, items: ITEMS.map((i) => (i.ref === "a001" ? stored(i, { kind: "workspace" }) : i.ref === "a004" ? stored(i, { kind: "member", member: "mem_alex0001" }) : { ref: i.ref, include: false })) }
    expect(await adoptionDigest(GALLERY_ADOPTION.adoption, ITEMS, built.decisions)).toBe(await sha256B64(canonicalJson(before)))
  })
})

const CONFLICT = GALLERY_CONFLICT_ADOPTION.items
const conflict = (ref: string) => CONFLICT.find((i) => i.ref === ref) as (typeof CONFLICT)[number]
const ADOPTION = GALLERY_CONFLICT_ADOPTION.adoption

describe("a compare row's actions", () => {
  it("keep the vault's value or keep both always; replace only with a fingerprint for every field and a holder of the same kind; never store", () => {
    expect(CONFLICT.filter((i) => i.compare !== null).map((i) => [i.ref, adoptionActions(i, ADOPTION)])).toEqual([
      ["c001", ["map", "replace", "rename"]],
      ["c002", ["map", "replace", "rename"]],
      ["c003", ["rename"]],
      ["c004", ["map", "rename"]],
    ])
    const c002 = conflict("c002")
    const compare = c002.compare!
    expect(adoptionActions({ ...c002, compare: { ...compare, holder: { ...compare.holder, kind: "bearer-token" } } }, ADOPTION)).toEqual(["map", "rename"])
  })

  it("against a row of this same batch, keeps its value or replaces it", () => {
    const c003 = conflict("c003")
    const compare = c003.compare!
    expect(adoptionActions({ ...c003, compare: { ...compare, holder: { ...compare.holder, id: `${ADOPTION}/c009` } } }, ADOPTION)).toEqual(["map", "replace", "rename"])
  })

  it("start at keep the vault's value when every field is the same value, and undecided otherwise", () => {
    expect(CONFLICT.map((i) => [i.ref, adoptionDefaultAction(i, ADOPTION)])).toEqual([["c001", "map"], ["c002", null], ["c003", null], ["c004", null], ["c005", null], ["c006", "store"]])
  })

  it("propose keeping a copy as <slug>-<env>, else <slug>-<machine>, clear of every name in the batch", () => {
    expect(adoptionRenameSlug(conflict("c002"), new Set())).toBe("anthropic-platform-dev")
    expect(adoptionRenameSlug(conflict("c003"), new Set())).toBe("github-pat-gh-linuxbox")
    expect(adoptionRenameSlug(conflict("c002"), new Set(["anthropic-platform-dev", "anthropic-platform-dev-2"]))).toBe("anthropic-platform-dev-3")
    expect(adoptionRenameSlug({ ...conflict("c003"), sources: [{ ...conflict("c003").sources[0]!, machine: "Alex's MacBook Pro" }] }, new Set())).toBe("github-pat-gh-alex-s-macbook-pro")
  })

  it("send an explicit action on every ticked compare row, and refuse to sign one left undecided", () => {
    const choices = new Map<string, AdoptionChoice>([
      ["c001", { include: true, home: "workspace", action: "map" as const }],
      ["c002", { include: true, home: "workspace", action: "replace" as const }],
      ["c003", { include: true, home: "workspace", action: "rename" as const, slug: "github-pat-gh-linuxbox" }],
      ["c004", { include: false, home: "workspace", action: null }],
      ["c006", { include: true, home: "workspace" }],
    ])
    const built = adoptionDecisions(ADOPTION, CONFLICT, choices)
    expect(built).toEqual({
      ok: true,
      decisions: [
        { ref: "c001", include: true, home: { kind: "workspace" }, action: "map" },
        { ref: "c002", include: true, home: { kind: "workspace" }, action: "replace" },
        { ref: "c003", include: true, home: { kind: "workspace" }, action: "rename", slug: "github-pat-gh-linuxbox" },
        { ref: "c004", include: false, home: conflict("c004").home },
        { ref: "c005", include: false, home: conflict("c005").home },
        { ref: "c006", include: true, home: { kind: "workspace" }, action: "store" },
      ],
    })
    expect(adoptionDecisions(ADOPTION, CONFLICT, new Map([...choices, ["c004", { include: true, home: "workspace", action: null }]]))).toEqual({ ok: false, error: ADOPTION_DECISION_NEEDED("stripe-test") })
    // An action the row cannot take is no decision either.
    expect(adoptionDecisions(ADOPTION, CONFLICT, new Map([...choices, ["c003", { include: true, home: "workspace", action: "map" as const }]]))).toEqual({ ok: false, error: ADOPTION_DECISION_NEEDED("github-pat-gh") })
    expect(adoptionDecisions(ADOPTION, CONFLICT, new Map([...choices, ["c001", { include: true, home: "workspace", action: "store" as const }]]))).toEqual({ ok: false, error: ADOPTION_DECISION_NEEDED("openai-platform") })
  })

  it("keep a copy only under a valid name no other row of the batch has", () => {
    const rename = (slug: string, extra: [string, { include: boolean; home: string; action: "rename"; slug: string }][] = []) => adoptionDecisions(ADOPTION, CONFLICT, new Map([["c003", { include: true, home: "workspace", action: "rename" as const, slug }], ...extra]))
    for (const slug of ["", "Github", "github--copy", "github-pat-gh", "openai-platform", "x"]) expect(rename(slug), slug).toEqual({ ok: false, error: ADOPTION_RENAME_INVALID("github-pat-gh") })
    expect(rename("gh-copy", [["c002", { include: true, home: "workspace", action: "rename", slug: "gh-copy" }]])).toEqual({ ok: false, error: ADOPTION_RENAME_INVALID("anthropic-platform") })
    expect(rename(" gh-copy ")).toMatchObject({ ok: true, decisions: expect.arrayContaining([{ ref: "c003", include: true, home: { kind: "workspace" }, action: "rename", slug: "gh-copy" }]) })
  })

  it("repoint, for a kept copy only, the variables the holder's affected references name, sorted as the digest signs them", async () => {
    const prod = { project: "platform", env: "prod", variable: "ANTHROPIC_API_KEY" }, dev = { project: "platform", env: "dev", variable: "ANTHROPIC_API_KEY" }
    const built = (choice: Partial<AdoptionChoice>) => adoptionDecisions(ADOPTION, CONFLICT, new Map([["c002", { include: true, home: "workspace", action: "rename" as const, slug: "anthropic-platform-dev", ...choice }]]))
    const c002 = (choice: Partial<AdoptionChoice>) => { const b = built(choice); if (!b.ok) throw new Error(b.error.message); return b.decisions.find((d) => d.ref === "c002") }
    expect(c002({ repoint: [prod, dev] })).toEqual({ ref: "c002", include: true, home: { kind: "workspace" }, action: "rename", slug: "anthropic-platform-dev", repoint: [dev, prod] })
    // None ticked sends none; one the holder's references do not name is never sent.
    expect(c002({ repoint: [] })).not.toHaveProperty("repoint")
    expect(c002({ repoint: [{ project: "platform", env: "prod", variable: "OPENAI_API_KEY" }, prod] })).toMatchObject({ repoint: [prod] })
    expect(c002({ action: "replace", repoint: [prod] })).not.toHaveProperty("repoint")
    const b = built({ repoint: [prod, dev] })
    if (!b.ok) throw new Error(b.error.message)
    expect(await adoptionDigest(ADOPTION, CONFLICT, b.decisions)).not.toBe(await adoptionDigest(ADOPTION, CONFLICT, b.decisions.map((d) => (d.ref === "c002" ? { ...d, repoint: [dev] } : d))))
  })

  it("sign the action, the holder and, for a replace, the fingerprints under the holder", async () => {
    const digest = async (action: "map" | "replace") => {
      const built = adoptionDecisions(ADOPTION, CONFLICT, new Map([["c002", { include: true, home: "workspace", action }]]))
      if (!built.ok) throw new Error(built.error.message)
      return adoptionDigest(ADOPTION, CONFLICT, built.decisions)
    }
    expect(await digest("map")).not.toBe(await digest("replace"))
  })
})

describe("a compare row whose holder is gone or hidden from this reviewer", () => {
  const gone = conflict("c005")

  it("starts unticked and undecided, and may only keep a copy under another name", () => {
    expect([gone.compare, gone.problem]).toEqual([null, ADOPTION_HOLDER_GONE])
    expect(adoptionTickedByDefault(gone)).toBe(false)
    expect(adoptionActions(gone, ADOPTION)).toEqual(["rename"])
    expect(adoptionDefaultAction(gone, ADOPTION)).toBeNull()
    expect(adoptionUndecided(ADOPTION, CONFLICT, new Map([["c005", { include: true, home: "workspace", action: null }]]))).toBe(1)
    expect(adoptionKeepVaultRefs(ADOPTION, CONFLICT, new Map())).not.toContain("c005")
  })

  it("never builds a store decision: ticked, it is renamed or refused", () => {
    const decide = (choice: AdoptionChoice) => adoptionDecisions(ADOPTION, CONFLICT, new Map([["c005", choice]]))
    for (const action of [null, "store", "map", "replace"] as const) expect(decide({ include: true, home: "workspace", action }), String(action)).toEqual({ ok: false, error: ADOPTION_DECISION_NEEDED("weather-api") })
    expect(decide({ include: true, home: "workspace", action: "rename", slug: "weather-api" })).toEqual({ ok: false, error: ADOPTION_RENAME_INVALID("weather-api") })
    const renamed = decide({ include: true, home: "workspace", action: "rename", slug: "weather-api-linuxbox", repoint: [{ project: "platform", env: "dev", variable: "WEATHER_KEY" }] })
    if (!renamed.ok) throw new Error(renamed.error.message)
    expect(renamed.decisions.find((d) => d.ref === "c005")).toEqual({ ref: "c005", include: true, home: { kind: "workspace" }, action: "rename", slug: "weather-api-linuxbox" })
    expect(decide({ include: false, home: "workspace" })).toMatchObject({ ok: true, decisions: expect.arrayContaining([{ ref: "c005", include: false, home: gone.home }]) })
  })
})

describe("the undecided rows", () => {
  const start = () => new Map<string, AdoptionChoice>(CONFLICT.map((i) => [i.ref, { include: adoptionTickedByDefault(i), home: "workspace", action: adoptionDefaultAction(i, ADOPTION) }]))

  it("count every ticked compare row with no action it may take, and block approval while any is left", () => {
    const choices = start()
    expect(adoptionUndecided(ADOPTION, CONFLICT, choices)).toBe(3)
    expect(adoptionUndecidedWords(3)).toBe("3 rows need a decision before you approve.")
    expect(adoptionUndecidedWords(1)).toBe("1 row needs a decision before you approve.")
    choices.set("c004", { ...choices.get("c004")!, include: false })
    choices.set("c003", { ...choices.get("c003")!, action: "map" })
    expect(adoptionUndecided(ADOPTION, CONFLICT, choices)).toBe(2)
    choices.set("c003", { ...choices.get("c003")!, action: "rename", slug: "gh-copy" })
    choices.set("c002", { ...choices.get("c002")!, action: "replace" })
    expect(adoptionUndecided(ADOPTION, CONFLICT, choices)).toBe(0)
  })

  it("keep the vault's value for every remaining one sets map only on undecided rows that may keep it", () => {
    const choices = start()
    choices.set("c002", { ...choices.get("c002")!, action: "rename", slug: "gh-copy" })
    expect(adoptionKeepVaultRefs(ADOPTION, CONFLICT, choices)).toEqual(["c004"])
    expect(adoptionKeepVaultRefs(ADOPTION, CONFLICT, start())).toEqual(["c002", "c004"])
  })
})

describe("the action the passkey signs", () => {
  const decisions = () => {
    const built = adoptionDecisions(ADOPTION, CONFLICT, new Map([["c002", { include: true, home: "workspace", action: "replace" as const }], ["c006", { include: true, home: "workspace" }]]))
    if (!built.ok) throw new Error(built.error.message)
    return built.decisions
  }

  it("is adoption.approve over the protocol's digest, with the variables it repoints", async () => {
    expect(await adoptionApproveAction(ADOPTION, CONFLICT, decisions())).toEqual({ type: "adoption.approve", adoption: ADOPTION, digest: await adoptionDigest(ADOPTION, CONFLICT, decisions()), repoints: 0 })
    const repointed = decisions().map((d) => (d.ref === "c002" ? { ...d, action: "rename" as const, slug: "c002-kept", repoint: [{ project: "prj_x", env: "dev", variable: "OPENAI_API_KEY" }] } : d))
    expect(await adoptionApproveAction(ADOPTION, CONFLICT, repointed)).toMatchObject({ repoints: 1 })
  })

  it("is refused unless the batch read again is open and gives the same action and rows", async () => {
    const expected = await adoptionApproveAction(ADOPTION, CONFLICT, decisions())
    const again = (view: typeof GALLERY_CONFLICT_ADOPTION) => adoptionShownRefusal(expected, CONFLICT, view, decisions())
    expect(await again(GALLERY_CONFLICT_ADOPTION)).toBeNull()
    expect(await again({ ...GALLERY_CONFLICT_ADOPTION, status: "approved" })).toEqual(CHANGED_SINCE_SHOWN)
    const c002 = conflict("c002")
    const moved = (change: Partial<(typeof CONFLICT)[number]>) => ({ ...GALLERY_CONFLICT_ADOPTION, items: CONFLICT.map((i) => (i.ref === "c002" ? { ...i, ...change } : i)) })
    // The holder rotated since the page showed it: another target version.
    const holder = c002.compare!.holder
    if (holder.type !== "stored") throw new Error("c002 is held by a stored item")
    expect(await again(moved({ compare: { ...c002.compare!, holder: { ...holder, version: 8 } } }))).toEqual(CHANGED_SINCE_SHOWN)
    // A new fingerprint under the holder.
    expect(await again(moved({ compare: { ...c002.compare!, fields: [{ name: "key", result: "differs", fingerprint: "Moved" }] } }))).toEqual(CHANGED_SINCE_SHOWN)
    // Nothing signed changed, but a row did.
    expect(await again(moved({ sources: [] }))).toEqual(CHANGED_SINCE_SHOWN)
    const affected = c002.compare!.affected!
    expect(await again(moved({ compare: { ...c002.compare!, affected: { ...affected, references: affected.references.slice(1) } } }))).toEqual(CHANGED_SINCE_SHOWN)
    // Someone used the credential while it was reviewed: it was read and leased again.
    expect(await again(moved({ compare: { ...c002.compare!, holder: { ...holder, lastUsedAt: new Date(Date.parse(holder.lastUsedAt ?? "2026-11-04T00:00:00.000Z") + 60_000).toISOString() } } }))).toBeNull()
    expect(await again(moved({ compare: { ...c002.compare!, affected: { ...affected, leasingDevices: affected.leasingDevices + 2 } } }))).toBeNull()
  })
})

describe("keep open", () => {
  it("is offered while the batch can still be kept open longer, and never by a vault that does not say how long", () => {
    expect(adoptionKeepOpenShown(GALLERY_CONFLICT_ADOPTION)).toBe(true)
    expect(adoptionKeepOpenShown({ ...GALLERY_CONFLICT_ADOPTION, expiresAt: GALLERY_CONFLICT_ADOPTION.maxExpiresAt! })).toBe(false)
    expect(adoptionKeepOpenShown(GALLERY_ADOPTION)).toBe(false)
  })

  it("is not offered once a click would add less than a minute, so the label never claims more than it adds", () => {
    const left = (ms: number) => ({ expiresAt: GALLERY_CONFLICT_ADOPTION.expiresAt, maxExpiresAt: new Date(Date.parse(GALLERY_CONFLICT_ADOPTION.expiresAt) + ms).toISOString() })
    expect(adoptionKeepOpenShown(left(59_000))).toBe(false)
    expect(adoptionKeepOpenShown(left(60_000))).toBe(true)
    expect(adoptionKeepOpenWords(left(60_000))).toBe("Keep open 1 more minute")
  })

  it("says how much one click adds: 3 more days, or what is left before the longest the batch may stay open", () => {
    const left = (ms: number) => adoptionKeepOpenWords({ expiresAt: GALLERY_CONFLICT_ADOPTION.expiresAt, maxExpiresAt: new Date(Date.parse(GALLERY_CONFLICT_ADOPTION.expiresAt) + ms).toISOString() })
    expect(adoptionKeepOpenWords(GALLERY_CONFLICT_ADOPTION)).toBe("Keep open 3 more days")
    expect(left(6 * 86_400_000)).toBe("Keep open 3 more days")
    expect(left(3 * 86_400_000)).toBe("Keep open 3 more days")
    expect(left(2 * 86_400_000)).toBe("Keep open 2 more days")
    expect(left(86_400_000)).toBe("Keep open 1 more day")
    expect(left(30 * 3_600_000 + 59_000)).toBe("Keep open 30 more hours")
    expect(left(3_600_000)).toBe("Keep open 1 more hour")
    expect(left(90_000)).toBe("Keep open 1 more minute")
  })
})

describe("the decision bar", () => {
  it("counts the ticked rows by home, in the order the homes are offered", () => {
    const homes = [["workspace", "Whole workspace"], ["member:mem_alex0001", "Only me"]] as const
    expect(adoptionHomeCounts([{ include: true, home: "member:mem_alex0001" }, { include: true, home: "workspace" }, { include: true, home: "workspace" }, { include: false, home: "workspace" }], homes)).toBe("2 to Whole workspace, 1 to Only me")
    expect(adoptionHomeCounts([{ include: true, home: "" }], homes)).toBe("1 with no home chosen")
    expect(adoptionApproveLabel(1)).toBe("Approve 1 credential")
    expect(adoptionApproveLabel(12)).toBe("Approve 12 credentials")
  })

  it("marks the rows an all-or-nothing refusal names", () => {
    expect(adoptionRefusals({ error: "conflict", message: "One credential in this batch cannot be stored, so nothing was stored.", refused: [{ ref: "a002", reason: "This name is no longer available." }] })).toEqual(new Map([["a002", "This name is no longer available."]]))
    expect(adoptionRefusals({ error: "conflict", message: "This batch changed; reload it." }).size).toBe(0)
  })
})
