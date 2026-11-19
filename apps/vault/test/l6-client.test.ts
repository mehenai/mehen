// The browser's pure logic, checked against the server's own digest code.
// Runs under `bun test` (vitest imports map to bun:test) and inside workerd
// with the rest of the server suite.

import { describe, expect, it } from "vitest"
import { canonicalJson } from "@mehen/protocol/api"
import { sha256B64 } from "@mehen/protocol/bytes"
import { fingerprintGroupCheck } from "@mehen/protocol/fingerprint"
import { importSealPrivateKey, importSealPublicKey, openText, seal } from "@mehen/protocol/seal"
import {
  type IntakeBoot,
  buildIntakeSubmission,
  intakeDigest,
  environmentChangeDigest,
  setupStepStates,
  missesFieldShape,
  parseList,
  typedGroupState,
} from "../src/ui/client/logic.ts"
import { escapeHtml, html, isVaultPath, nativeAppHref, safeHref } from "../src/ui/html.ts"
import { RING_DANGER_SECONDS, RING_WARN_SECONDS, ringOffset, ringState, ringText } from "../src/ui/client/countdown.ts"
import { ringOffset as serverRingOffset } from "../src/ui/components.ts"
import { safeNext } from "../src/ui/wording.ts"
import { IntakeSubmission, intakeSubmitDigest } from "../src/vault/areas/intake.ts"
import { environmentChangeDigest as serverEnvironmentDigest } from "../src/vault/areas/projects.ts"

// The test seal key from wrangler.jsonc (env "test"); worthless elsewhere.
const SEAL_PRIVATE = {
  kty: "EC",
  crv: "P-256",
  x: "IFu5oTRAkuJbqGAyU-XhbZTUbMDuWlA_VPjMvHboOiA",
  y: "Kq34ITAoveGw9XtQyZoqkyIEDbgU_4alhSi115VpVDQ",
  d: "54ec9Zobfk7EdlSkw65vyEMdu1lFOvoP5FWX83K6qHA",
}
const SEAL_PUBLIC = { kty: "EC", crv: "P-256", x: SEAL_PRIVATE.x, y: SEAL_PRIVATE.y }
const KEY = "sk-proj-Hx4Lq9Wd2RmT7vZc"

const intakeBoot = (overrides: Partial<IntakeBoot> = {}): IntakeBoot => ({
  intake: "int_abcdefgh1234",
  slug: "openai-personal",
  binding: { hosts: ["api.openai.com"] },
  verified: true,
  rotates: false,
  tags: [],
  fields: [
    { name: "username", label: "Username", secret: false, required: true, multiline: false },
    { name: "key", label: "API key", secret: true, required: true, multiline: false },
    { name: "note", label: "Note", secret: true, required: false, multiline: true },
  ],
  ...overrides,
})

async function sealer() {
  const key = await importSealPublicKey(SEAL_PUBLIC)
  return (value: string, context: string) => seal(key, value, context)
}

describe("intake submission", () => {
  it("seals secrets with the intake context, keeps public fields plain, and never carries plaintext", async () => {
    const built = await buildIntakeSubmission(intakeBoot(), { username: "  alex  ", key: `  ${KEY}\n`, note: "" }, false, await sealer())
    if (!built.ok) throw new Error(built.problems.join())
    const { submission } = built.value
    expect(submission.publicFields).toEqual({ username: "alex" })
    expect(Object.keys(submission.sealed)).toEqual(["key"])
    expect(JSON.stringify(submission)).not.toContain(KEY)
    const priv = await importSealPrivateKey(SEAL_PRIVATE)
    expect(await openText(priv, submission.sealed.key as never, "intake/int_abcdefgh1234/key")).toBe(KEY)
    await expect(openText(priv, submission.sealed.key as never, "intake/int_other/key")).rejects.toThrow()
  })

  it("computes the same digest as the server, before and after the server parses the body, over the sorted tags", async () => {
    const built = await buildIntakeSubmission(intakeBoot({ tags: ["work", "ci"] }), { username: "alex", key: KEY }, false, await sealer())
    if (!built.ok) throw new Error(built.problems.join())
    const { submission, digest } = built.value
    expect(submission.tags).toEqual(["work", "ci"])
    const parsed = IntakeSubmission.parse(JSON.parse(JSON.stringify(submission)))
    expect(digest).toBe(await intakeSubmitDigest(parsed))
    expect(digest).toBe(
      await sha256B64(canonicalJson({ slug: submission.slug, binding: submission.binding, publicFields: submission.publicFields, sealed: submission.sealed, tags: ["ci", "work"] })),
    )
    expect(await intakeDigest(submission)).toBe(digest)
    expect(await intakeDigest({ ...submission, tags: ["work"] })).not.toBe(digest)
  })

  it("refuses missing required fields and an unaccepted agent destination", async () => {
    const unverified = intakeBoot({ verified: false, binding: { hosts: ["api.example.com"] } })
    const built = await buildIntakeSubmission(unverified, { username: "", key: "   " }, false, await sealer())
    expect(built.ok).toBe(false)
    if (built.ok) return
    expect(built.problems).toEqual([
      "Tick the box to accept the destination the agent proposed, after checking every host.",
      "Fill in Username.",
      "Fill in API key.",
    ])
    const accepted = await buildIntakeSubmission(unverified, { username: "a", key: KEY }, true, await sealer())
    expect(accepted.ok).toBe(true)
  })

  it("does not ask to accept the destination when rotating an existing item", async () => {
    const rotation = intakeBoot({ verified: false, rotates: true, fields: [{ name: "key", label: "API key", secret: true, required: true, multiline: false }] })
    const built = await buildIntakeSubmission(rotation, { key: KEY }, false, await sealer())
    expect(built.ok).toBe(true)
  })
})

describe("guided setup steps", () => {
  const google = [null, null, null, "client_id", "client_secret"]

  it("tick as the fields fill, with the next step current, and never gate anything", () => {
    expect(setupStepStates(google, new Set())).toEqual(["current", "todo", "todo", "todo", "todo"])
    expect(setupStepStates(google, new Set(["client_id"]))).toEqual(["done", "done", "done", "done", "current"])
    expect(setupStepStates(google, new Set(["client_id", "client_secret"]))).toEqual(["done", "done", "done", "done", "done"])
    // A later field filled first still marks everything before it done.
    expect(setupStepStates(google, new Set(["client_secret"]))).toEqual(["done", "done", "done", "done", "done"])
    expect(setupStepStates([], new Set(["client_id"]))).toEqual([])
  })
})

describe("the field shape warning", () => {
  const openai = { at: "start", literals: ["sk-"] } as const
  const github = { at: "start", literals: ["github_pat_", "ghp_"] } as const
  const googleId = { at: "end", literals: [".apps.googleusercontent.com"] } as const

  it("flags a value that cannot start with the prefix, typed or left, and passes one that does", () => {
    expect(missesFieldShape(openai, "not-a-key", false)).toBe(true)
    expect(missesFieldShape(openai, "not-a-key", true)).toBe(true)
    expect(missesFieldShape(openai, "sk-proj-abc", true)).toBe(false)
    expect(missesFieldShape(openai, "  sk-proj-abc \n", true)).toBe(false)
    expect(missesFieldShape(github, "ghp_abc", true)).toBe(false)
    expect(missesFieldShape(github, "gho_abc", false)).toBe(true)
  })

  it("waits while a prefix is still being typed, but not once the field is left", () => {
    expect(missesFieldShape(openai, "s", false)).toBe(false)
    expect(missesFieldShape(openai, "sk", false)).toBe(false)
    expect(missesFieldShape(openai, "sk", true)).toBe(true)
    expect(missesFieldShape(github, "github", false)).toBe(false)
  })

  it("judges an ending only once the field is left, and never an empty field", () => {
    expect(missesFieldShape(googleId, "1234-abc", false)).toBe(false)
    expect(missesFieldShape(googleId, "1234-abc", true)).toBe(true)
    expect(missesFieldShape(googleId, "1234-abc.apps.googleusercontent.com", true)).toBe(false)
    expect(missesFieldShape(openai, "   ", true)).toBe(false)
    expect(missesFieldShape(googleId, "", true)).toBe(false)
  })
})

describe("projects", () => {
  it("signs environment changes with the server's digest", async () => {
    const change = { project: "prj_1", env: "prod", protected: false, fences: ["db.example.com"] }
    expect(await environmentChangeDigest(change)).toBe(serverEnvironmentDigest(change))
  })
})

describe("enrol: the typed hidden group", () => {
  const code = "K7PQ2M4D"

  it("approve enables only when the typed group matches the check, read as the protocol reads it", async () => {
    const check = await fingerprintGroupCheck(code, "9RTV")
    expect(await typedGroupState(code, check, "9RTV")).toEqual({ state: "matches", group: "9RTV" })
    // Case, spaces and hyphens, and the lookalikes the alphabet maps: l and I as 1, o and O as 0.
    expect(await typedGroupState(code, check, " 9r-tv ")).toEqual({ state: "matches", group: "9RTV" })
    const ones = await fingerprintGroupCheck(code, "1A0B")
    expect(await typedGroupState(code, ones, "laob")).toEqual({ state: "matches", group: "1A0B" })
    expect(await typedGroupState(code, ones, "IAOB")).toEqual({ state: "matches", group: "1A0B" })
    // A valid group that is not the hidden one: wrong, and the typed group is what the slot shows.
    expect(await typedGroupState(code, check, "9RTW")).toEqual({ state: "wrong", group: "9RTW" })
    // The same group under another link's code hashes differently, so a check never travels between links.
    expect(await typedGroupState("OTHER1", check, "9RTV")).toEqual({ state: "wrong", group: "9RTV" })
    // An empty check (a page without one) never matches.
    expect(await typedGroupState(code, "", "9RTV")).toEqual({ state: "wrong", group: "9RTV" })
  })

  it("refuses a U with its own state, and tells partial from invalid input", async () => {
    const check = await fingerprintGroupCheck(code, "9RTV")
    expect(await typedGroupState(code, check, "")).toEqual({ state: "empty", group: "" })
    expect(await typedGroupState(code, check, "   ")).toEqual({ state: "empty", group: "" })
    expect(await typedGroupState(code, check, "9rt")).toEqual({ state: "partial", group: "9RT" })
    expect(await typedGroupState(code, check, "9RTU")).toEqual({ state: "no-u", group: "9RTU" })
    expect(await typedGroupState(code, check, "u")).toEqual({ state: "no-u", group: "U" })
    expect(await typedGroupState(code, check, "9RTVX")).toEqual({ state: "invalid", group: "9RTVX" })
    expect(await typedGroupState(code, check, "9R*V")).toEqual({ state: "invalid", group: "9R*V" })
  })
})

describe("small helpers", () => {
  it("only ever continues to a path on this vault", () => {
    expect(safeNext("/i/int_1?x=1")).toBe("/i/int_1?x=1")
    for (const bad of ["//evil.example.com", "https://evil.example.com", "/\\evil.example.com", "javascript:alert(1)", "", null, "/a\nb"]) expect(safeNext(bad)).toBe("/")
  })

  it("escapes every interpolation and neuters script links", () => {
    const hostile = `<script>alert("x")</script>'&\``
    expect(escapeHtml(hostile)).toBe("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&#39;&amp;&#96;")
    expect(html`<p title="${hostile}">${[hostile, html`<b>${hostile}</b>`]}</p>`.value).not.toContain("<script>")
    expect(safeHref("javascript:alert(1)")).toBe("#")
    expect(safeHref("data:text/html,hi")).toBe("#")
    expect(safeHref("//evil.example.com")).toBe("#")
    expect(safeHref("/i/x")).toBe("/i/x")
    expect(safeHref("https://app.mehen.dev/a/apr_1")).toBe("https://app.mehen.dev/a/apr_1")
    expect(safeHref("jeff://ask?text=try%20again")).toBe("#")
  })

  it("links into a native app only from the fixed set the vault builds, never from a string", () => {
    expect(nativeAppHref("ask-again")).toMatch(/^jeff:\/\//)
    expect(nativeAppHref("open-app")).toBe("jeff://")
    expect(isVaultPath("/items/x")).toBe(true)
    expect(isVaultPath("/a/apr_1?x=1#truth")).toBe(true)
    for (const bad of ["javascript:alert(1)", "jeff://ask", "//evil.example.com", "/\\evil.example.com", "https://app.mehen.dev/", "items/x", "", "/a\nb", "/a\u0000b"]) {
      expect(isVaultPath(bad), bad).toBe(false)
    }
  })

  it("turns time left into a ring offset and the warn and danger thresholds", () => {
    const now = Date.parse("2026-10-24T18:30:00Z")
    const full = ringState(now + 900_000, 900, now)
    expect(full).toEqual({ left: 900, fraction: 1, tone: null, expired: false })
    expect(ringOffset(full.fraction)).toBe(0)
    expect(ringOffset(0)).toBe(56.55)
    expect(ringOffset(0.5)).toBe(28.27)
    expect(ringOffset(2)).toBe(0)
    expect(ringOffset(-1)).toBe(56.55)
    for (const f of [0, 0.25, 0.6, 1]) expect(ringOffset(f)).toBe(serverRingOffset(f))
    expect(ringState(now + RING_WARN_SECONDS * 1000, 900, now).tone).toBe("warn")
    expect(ringState(now + (RING_WARN_SECONDS + 1) * 1000, 900, now).tone).toBeNull()
    expect(ringState(now + RING_DANGER_SECONDS * 1000, 900, now).tone).toBe("danger")
    expect(ringState(now + 500, 900, now)).toEqual({ left: 1, fraction: 1 / 900, tone: "danger", expired: false })
    expect(ringState(now, 900, now)).toEqual({ left: 0, fraction: 0, tone: "danger", expired: true })
    expect(ringState(now - 5000, 900, now).expired).toBe(true)
    expect(ringState(now + 60_000, 0, now).fraction).toBe(0)
    expect(ringText(5400)).toBe("1 h 30 min")
    expect(ringText(540)).toBe("9 min")
    expect(ringText(54)).toBe("54 s")
  })

  it("splits lists on commas and newlines without repeats", () => {
    expect(parseList(" a, b\nb ,,c ")).toEqual(["a", "b", "c"])
  })
})
