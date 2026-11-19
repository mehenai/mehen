import { afterEach, describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir, userInfo } from "node:os"
import { join } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { CliError, exitCodeFor } from "./errors.ts"
import {
  DeviceScopeSchema, parseVaultContexts, assertVaultPinAdmitted, assertVaultCatalogue, scopeEqual,
  assertLocalVaultIdentity, assertAuthenticatedVaultScope, assertAuthenticatedVaultEnrolment, assertManagedVaultSelection,
  assertVaultEnvProject, buildVaultChildEnv, verifyVaultDirectory, verifyVaultPrivateFile,
  readVaultContextsFile, readManagedVaultMarker, defaultOwnerRoot,
  passwdHomeFromGetent, passwdHomeFromPasswdFile, passwdHomeFromDscacheutil, passwdSources, systemPasswdHome, untrustedPasswdHome, setPasswdHomeLookupForTests,
  type VaultContextPin, type VaultContexts, type VaultFileOptions, type PasswdLookupIo, type PasswdHomeResult, type CommandOutcome, type FileOutcome,
} from "./agent-profiles.ts"
import { managedHost, resolveHome } from "./home.ts"
import { runJv } from "./testing/run-mehen.ts"

// Frozen UTF-8 bytes, shared verbatim with the other repository. No trailing newline.
const DEVICE_SCOPE_CORPUS = String.raw`{"name":"device-scope-v2","cases":[{"name":"minimal","valid":true,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"empty broad lists remain server-valid","valid":true,"scope":{"tags":[],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"mode relay","valid":true,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"mode sign","valid":true,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["sign"],"privateCredentials":false}},{"name":"mode mint","valid":true,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["mint"],"privateCredentials":false}},{"name":"mode placeholder","valid":true,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["placeholder"],"privateCredentials":false}},{"name":"mode lease","valid":true,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["lease"],"privateCredentials":false}},{"name":"all modes","valid":true,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay","sign","mint","placeholder","lease"],"privateCredentials":false}},{"name":"reveal","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["reveal"],"privateCredentials":false}},{"name":"empty modes","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":[],"privateCredentials":false}},{"name":"six modes","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay","relay","relay","relay","relay","relay"],"privateCredentials":false}},{"name":"unknown mode","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["execute"],"privateCredentials":false}},{"name":"missing modes","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","privateCredentials":false}},{"name":"tag length 40","valid":true,"scope":{"tags":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"32 tags","valid":true,"scope":{"tags":["a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"tag alphabet","valid":true,"scope":{"tags":["a0:b_c-d"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"empty tag","valid":false,"scope":{"tags":[""],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"tag length 41","valid":false,"scope":{"tags":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"33 tags","valid":false,"scope":{"tags":["a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"uppercase tag","valid":false,"scope":{"tags":["Personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"tag slash","valid":false,"scope":{"tags":["a/b"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"tag leading punctuation","valid":false,"scope":{"tags":["_a"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"tag newline","valid":false,"scope":{"tags":["a\n"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"one character project","valid":true,"scope":{"tags":["personal"],"projects":["x"],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"64 character project","valid":true,"scope":{"tags":["personal"],"projects":["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"32 projects","valid":true,"scope":{"tags":["personal"],"projects":["x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x"],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"broad server project alphabet","valid":true,"scope":{"tags":["personal"],"projects":["not an id / project"],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"empty project","valid":false,"scope":{"tags":["personal"],"projects":[""],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"65 character project","valid":false,"scope":{"tags":["personal"],"projects":["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"33 projects","valid":false,"scope":{"tags":["personal"],"projects":["x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x","x"],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"protected","valid":true,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"protected","modes":["relay"],"privateCredentials":false}},{"name":"unknown environment","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"production","modes":["relay"],"privateCredentials":false}},{"name":"unknown scope field","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"unknown":true,"privateCredentials":false}},{"name":"missing tags","valid":false,"scope":{"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"wrong type tags","valid":false,"scope":{"tags":42,"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"missing projects","valid":false,"scope":{"tags":["personal"],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"wrong type projects","valid":false,"scope":{"tags":["personal"],"projects":42,"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"missing maxEnvironment","valid":false,"scope":{"tags":["personal"],"projects":[],"modes":["relay"],"privateCredentials":false}},{"name":"wrong type maxEnvironment","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":42,"modes":["relay"],"privateCredentials":false}},{"name":"missing modes","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","privateCredentials":false}},{"name":"wrong type modes","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":42,"privateCredentials":false}},{"name":"private credentials on","valid":true,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":true}},{"name":"private credentials off","valid":true,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":false}},{"name":"missing privateCredentials","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"]}},{"name":"wrong type privateCredentials","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":"true"}},{"name":"null privateCredentials","valid":false,"scope":{"tags":["personal"],"projects":[],"maxEnvironment":"unprotected","modes":["relay"],"privateCredentials":null}}]}`
const DEVICE_SCOPE_SHA256 = "9f9365b12792fc91c6bf8ccbaf83b0ce278d7795415a0461b3eb63b3f80041cd"

type ScopeCase = { name: string; valid: boolean; scope: unknown }
const corpus = JSON.parse(DEVICE_SCOPE_CORPUS) as { name: string; cases: ScopeCase[] }
const scope = { tags: ["personal"], projects: [], maxEnvironment: "unprotected" as const, modes: ["relay" as const], privateCredentials: false }
function pin(patch: Partial<VaultContextPin> = {}): VaultContextPin {
  return { agentDir: "/owner/claude", configDir: "/owner/vault-personal", origin: "https://vault.example.test", tenant: "tn_12345678", device: "dev_12345678", scope: structuredClone(scope), ...patch }
}
function text(value: unknown = { version: 3, contexts: { personal: pin() } }): string { return JSON.stringify(value) }
function local(value = pin()) { return { vault: value.origin, tenant: value.tenant, device: value.device! } }
function status(value = pin()) { return { vault: value.origin, tenant: value.tenant, device: value.device!, scope: value.scope } }

describe("device-scope-v2 frozen parity", () => {
  test("UTF-8 corpus SHA-256", () => {
    expect(corpus.name).toBe("device-scope-v2")
    expect(createHash("sha256").update(DEVICE_SCOPE_CORPUS, "utf8").digest("hex")).toBe(DEVICE_SCOPE_SHA256)
  })
  for (const fixture of corpus.cases) test(fixture.name, () => {
    expect(DeviceScopeSchema.safeParse(fixture.scope).success).toBe(fixture.valid)
  })
})

// Pins stay on the device-scope-v2 corpus (above, byte for byte) until
// device-scope-v3 lands in mehen and the managed harness together. A
// pin naming fill, or a vault status naming fill for a pinned profile,
// fails verification: closed, never widened.
describe("a scope with fill is refused for a pin until device-scope-v3", () => {
  const filling = { ...scope, modes: ["relay", "fill"] }
  test("the pin scope schema refuses fill, alone or among others", () => {
    expect(DeviceScopeSchema.safeParse(filling).success).toBe(false)
    expect(DeviceScopeSchema.safeParse({ ...scope, modes: ["fill"] }).success).toBe(false)
  })
  test("a pin map naming fill fails verification", () => {
    expect(() => parseVaultContexts(text({ version: 3, contexts: { personal: { ...pin(), scope: filling } } }))).toThrow("Vault pin verification failed")
  })
  test("a vault status or enrolment naming fill fails the pinned profile's check", () => {
    expect(() => assertAuthenticatedVaultScope(pin(), { ...status(), scope: filling })).toThrow("Vault pin verification failed")
    expect(() => assertAuthenticatedVaultEnrolment(pin(), { ...status(), scope: filling })).toThrow("Vault pin verification failed")
  })
})

describe("version-3 pins (design 9.7)", () => {
  const v2 = { version: 2, contexts: { personal: { ...pin(), scope: { tags: ["personal"], projects: [], maxEnvironment: "unprotected", modes: ["relay"] } } } }
  test("a version-2 map is pin_outdated with the owner review, rewrite and status next; nothing is inferred", () => {
    let thrown: unknown
    try { parseVaultContexts(text(v2), { path: "/owner/config/pins/contexts.json" }) } catch (error) { thrown = error }
    expect(thrown).toBeInstanceOf(CliError)
    const error = thrown as CliError
    expect(error.code).toBe("pin_outdated")
    expect(exitCodeFor(error.code)).toBe(EXIT.usage)
    expect(error.next).toEqual({
      command: "mehen status --json",
      say: "The owner reviews this machine's scope on /w/<slug>/devices/dev_12345678 and rewrites the pin in /owner/config/pins/contexts.json as version 3 with privateCredentials set to what that page shows, then run mehen status --json to verify.",
    })
    expect(error.message).not.toContain("true")
    expect(error.message).not.toContain("false")
  })
  test("a version-2 map without exactly one device names the page generically", () => {
    const outdated = { version: 2, contexts: { a: pin(), b: pin({ device: "dev_87654321" }) } }
    let thrown: unknown
    try { parseVaultContexts(text(outdated)) } catch (error) { thrown = error }
    expect((thrown as CliError).code).toBe("pin_outdated")
    expect((thrown as CliError).next?.say).toMatch(/\/w\/<slug>\/devices\/<device> and rewrites the pin in the pin map as version 3/)
  })
  test("a version-3 scope without privateCredentials is refused, never defaulted", () => {
    const { privateCredentials: _tick, ...missing } = scope
    expect(() => parseVaultContexts(text({ version: 3, contexts: { personal: { ...pin(), scope: missing } } }))).toThrow("Vault pin verification failed")
    expect(DeviceScopeSchema.safeParse(missing).success).toBe(false)
  })
  test("an explicit tick round-trips and is part of scope equality", () => {
    const ticked = pin({ scope: { ...scope, privateCredentials: true } })
    expect(parseVaultContexts(text({ version: 3, contexts: { personal: ticked } })).contexts.personal).toEqual(ticked)
    assertAuthenticatedVaultScope(ticked, status(ticked))
    expect(scopeEqual(ticked.scope, scope)).toBe(false)
    expect(scopeEqual(ticked.scope, { ...scope, privateCredentials: true })).toBe(true)
    expect(() => assertAuthenticatedVaultScope(ticked, status())).toThrow()
    expect(() => assertAuthenticatedVaultScope(pin(), status(ticked))).toThrow()
    const { privateCredentials: _tick, ...statusWithoutTick } = status().scope
    expect(() => assertAuthenticatedVaultScope(pin(), { ...status(), scope: statusWithoutTick })).toThrow()
  })
  test("catalogue groups by origin and workspace: the same id at another origin is another group", () => {
    const narrow = pin(), broad = pin({ origin: "https://other.example.test", scope: { ...scope, tags: ["personal", "shared"] } })
    const map: VaultContexts = { version: 3, contexts: { narrow, broad } }
    assertVaultCatalogue(map)
    expect(() => assertVaultCatalogue({ version: 3, contexts: { narrow, broad: { ...broad, origin: narrow.origin } } })).toThrow()
  })
})

describe("strict v3 map", () => {
  test("valid non-pi profile, server-minted base64url project ids and same-tenant disjoint contexts", () => {
    const contexts = { personal: pin({ envProjects: ["prj_Zx9_ab-CD"] }), work: pin({ device: "dev_87654321", configDir: "/owner/vault-work", scope: { ...scope, tags: ["company:tools"] } }) }
    expect(parseVaultContexts(text({ version: 3, contexts })).contexts).toEqual(contexts)
    assertVaultCatalogue({ version: 3, contexts })
    assertVaultPinAdmitted(contexts.personal)
  })
  const invalid: [string, unknown][] = [
    ["old version", { version: 1, contexts: {} }],
    ["unknown map key", { version: 3, contexts: {}, secret: "synthetic" }],
    ["unknown pin key", { version: 3, contexts: { personal: { ...pin(), name: "Sam" } } }],
    ["bad context key", { version: 3, contexts: { Personal: pin() } }],
    ["overlong context key", { version: 3, contexts: { ["a".repeat(33)]: pin() } }],
    ...[pin({ tenant: "tn_short" }), pin({ device: "dev_short" }), pin({ tenant: "tn_" + "a".repeat(41) }), pin({ device: "dev_" + "a".repeat(41) }), pin({ agentDir: "relative" }), pin({ configDir: "/a/../b" }), pin({ envProjects: ["prj_a", "prj_a"] }), pin({ envProjects: ["prj_" + "a".repeat(61)] }), pin({ envProjects: ["project"] }), pin({ envProjects: Array.from({length:33}, (_, i) => "prj_" + i) })].map((value): [string, unknown] => ["invalid pin " + JSON.stringify(value), { version: 3, contexts: { personal: value } }]),
  ]
  for (const [name, value] of invalid) test(name, () => { expect(() => parseVaultContexts(text(value))).toThrow() })
  test("key and id upper boundaries", () => {
    parseVaultContexts(text({ version: 3, contexts: { ["a".repeat(32)]: pin({ tenant: "tn_" + "a".repeat(40), device: "dev_" + "a".repeat(40), envProjects: Array.from({length:32}, (_, i) => "prj_" + i) }) } }))
  })
  for (const input of ['{', text() + 'x', '{"version":3,"version":3,"contexts":{}}', '{"version":3,"contexts":{"a":' + JSON.stringify(pin()) + String.raw`,"\u0061":` + JSON.stringify(pin()) + '}}', text().replace('"tags":["personal"]', '"tags":["personal"],"tags":["work"]')]) {
    test("malformed or duplicate JSON " + input.slice(0, 45), () => { expect(() => parseVaultContexts(input)).toThrow() })
  }
  test("32 KiB UTF-8 limit including multi-byte characters", () => {
    const valid = text()
    parseVaultContexts(valid + " ".repeat(32768 - Buffer.byteLength(valid)))
    expect(() => parseVaultContexts(valid + " ".repeat(32769 - Buffer.byteLength(valid)))).toThrow()
    expect(() => parseVaultContexts(' '.repeat(32766) + 'éé')).toThrow()
  })
  for (const origin of ["http://vault.example.test", "https://VAULT.example.test", "https://vault.example.test/", "https://vault.example.test:443", "https://user@vault.example.test", "https://vault.example.test/path", "https://vault.example.test?x", "https://vault.example.test#x"]) {
    test("non-canonical origin " + origin, () => { expect(() => parseVaultContexts(text({ version: 3, contexts: { personal: pin({ origin }) } }))).toThrow() })
  }
  test("HTTP loopback is explicit synthetic-only", () => {
    const input = text({ version: 3, contexts: { personal: pin({ origin: "http://127.0.0.1:1234" }) } })
    expect(() => parseVaultContexts(input)).toThrow()
    parseVaultContexts(input, { allowLoopbackHttpForTests: true })
    expect(() => parseVaultContexts(text({version:3, contexts:{personal:pin({origin:"http://external.test"})}}), {allowLoopbackHttpForTests:true})).toThrow()
  })
  test("schema permits pre-enrolment intent and broad tags; admission never does", () => {
    const pending = pin({ device: null })
    parseVaultContexts(text({ version: 3, contexts: { pending } }))
    expect(() => assertVaultPinAdmitted(pending)).toThrow()
    const broad = pin({ scope: { ...scope, tags: [] } })
    parseVaultContexts(text({ version: 3, contexts: { broad } }))
    expect(() => assertVaultPinAdmitted(broad)).toThrow()
    assertVaultPinAdmitted(pin())
  })
  for (const tags of [["personal"], ["personal", "private"], ["private", "personal"]]) {
    test("same-tenant identical tag sets are accepted: " + tags.join(","), () => {
      const first = tags.length === 1 ? ["personal"] : ["personal", "private"]
      const map: VaultContexts = { version: 3, contexts: { app: pin({ scope: { ...scope, tags: first } }), telegram: pin({ device: "dev_87654321", scope: { ...scope, tags } }) } }
      assertVaultCatalogue(map)
      expect(parseVaultContexts(text(map)).contexts).toEqual(map.contexts)
    })
  }
  test("same-tenant disjoint tag sets are accepted", () => {
    const map: VaultContexts = { version: 3, contexts: { personal: pin(), work: pin({ scope: { ...scope, tags: ["work", "company:tools"] } }) } }
    assertVaultCatalogue(map)
    expect(parseVaultContexts(text(map)).contexts).toEqual(map.contexts)
  })
  test("same-tenant partial overlap refuses in either order", () => {
    const narrow = pin(), broad = pin({ scope: { ...scope, tags: ["personal", "shared"] } })
    for (const contexts of [{ narrow, broad }, { broad, narrow }]) {
      const map: VaultContexts = { version: 3, contexts }
      expect(() => assertVaultCatalogue(map)).toThrow()
      expect(() => parseVaultContexts(text(map))).toThrow()
    }
  })
  test("same tags in different tenants are accepted", () => {
    const map: VaultContexts = { version: 3, contexts: { personal: pin(), other: pin({ tenant: "tn_87654321" }) } }
    assertVaultCatalogue(map)
    expect(parseVaultContexts(text(map)).contexts).toEqual(map.contexts)
  })
  test("duplicate pin tags refuse even without another context", () => {
    const map: VaultContexts = { version: 3, contexts: { personal: pin({ scope: { ...scope, tags: ["personal", "personal"] } }) } }
    expect(() => assertVaultCatalogue(map)).toThrow()
    expect(() => parseVaultContexts(text(map))).toThrow()
  })
})

describe("injected identity, authenticated scope and child env", () => {
  test("local config compares only its existing vault, tenant and device fields", () => {
    assertLocalVaultIdentity(pin(), { ...local(), backend: "software" })
    for (const field of ["vault", "tenant", "device"] as const) expect(() => assertLocalVaultIdentity(pin(), { ...local(), [field]: "changed" })).toThrow()
    expect(() => assertLocalVaultIdentity(pin(), null)).toThrow()
  })
  test("scope is injected authenticated evidence, never config scope or a learnt pin", () => {
    assertAuthenticatedVaultScope(pin(), status())
    const expected = pin({scope:{tags:["personal", "private"],projects:["alpha", "beta"],maxEnvironment:"protected",modes:["relay", "sign"],privateCredentials:false}})
    assertAuthenticatedVaultScope(expected, {...status(expected),scope:{...expected.scope,tags:["private", "personal"],projects:["beta", "alpha"],modes:["sign", "relay"]}})
    for (const evidence of [null, undefined, {}, {...status(),vault:"https://other.test"}, {...status(),tenant:"tn_87654321"}, {...status(),device:"dev_87654321"}, {...status(),scope:{...scope,tags:["work"]}}, {...status(),scope:{...scope,projects:["project"]}}, {...status(),scope:{...scope,maxEnvironment:"protected"}}, {...status(),scope:{...scope,modes:["lease"]}}, {...status(),scope:{...scope,unknown:true}}]) expect(() => assertAuthenticatedVaultScope(pin(), evidence)).toThrow()
    expect(() => assertAuthenticatedVaultScope(pin({device:null}), status())).toThrow()
  })
  test("authenticated enrolment compares owner intent without finalising or admitting it", () => {
    const pending=pin({device:null})
    const matching=status()
    assertAuthenticatedVaultEnrolment(pending,matching)
    assertAuthenticatedVaultEnrolment(pin(),matching)
    assertAuthenticatedVaultEnrolment(pin(),{...matching,scope:{...scope,tags:["personal","personal"],modes:["relay","relay"]}})
    expect(pending.device).toBe(null)
    expect(() => assertVaultPinAdmitted(pending)).toThrow()
    expect(() => assertLocalVaultIdentity(pending,local())).toThrow()
    for (const evidence of [null,{}, {...matching,vault:"https://other.test"}, {...matching,vault:matching.vault+"/"}, {...matching,tenant:"tn_87654321"}, {...matching,scope:{...scope,tags:["personal","work"]}}, {...matching,scope:{...scope,tags:[]}}, {...matching,device:"invalid"}, {...matching,vault:undefined}]) expect(() => assertAuthenticatedVaultEnrolment(pending,evidence)).toThrow()
    expect(() => assertAuthenticatedVaultEnrolment(pin(),{...matching,device:"dev_87654321"})).toThrow()
    assertAuthenticatedVaultEnrolment(pending,{...matching,device:"dev_87654321"})
  })
  test("explicit managed map is own-key only and non-default", () => {
    const map = parseVaultContexts(text())
    const env = { MEHEN_CONFIG_DIR: pin().configDir, MEHEN_MANAGED_CONTEXT: "personal" }
    assertManagedVaultSelection(map, "personal", env, "/owner/default")
    for (const override of [{ MEHEN_CONFIG_DIR: undefined }, { MEHEN_CONFIG_DIR: "" }, { MEHEN_CONFIG_DIR: "/owner/default" }, { MEHEN_CONFIG_DIR: "/owner/other" }, { MEHEN_MANAGED_CONTEXT: undefined }, { MEHEN_MANAGED_CONTEXT: "work" }]) expect(() => assertManagedVaultSelection(map, "personal", {...env,...override}, "/owner/default")).toThrow()
    expect(() => assertManagedVaultSelection({version:3,contexts:{...map.contexts,work:pin({scope:{...scope,tags:["work"]}})}}, "personal", env, "/owner/default")).toThrow()
  })
  test("absent and empty ENV lists mean none, listed ids alone pass", () => {
    for (const value of [pin(),pin({envProjects:[]}),pin({envProjects:["prj_other"]})]) expect(() => assertVaultEnvProject(value,"prj_example")).toThrow()
    assertVaultEnvProject(pin({envProjects:["prj_example"]}), "prj_example")
  })
  test("child env strips URL, refuses conflicts and sets verified values without mutating inputs", () => {
    const parent = { PATH: "/synthetic/bin", MEHEN_VAULT_URL: "https://attacker.test", MEHEN_SESSION: "untrusted-label" }
    const result = buildVaultChildEnv(parent, "personal", pin())
    expect(result).toEqual({PATH:"/synthetic/bin",MEHEN_SESSION:"untrusted-label",MEHEN_CONFIG_DIR:pin().configDir,MEHEN_MANAGED_CONTEXT:"personal"})
    expect(parent.MEHEN_VAULT_URL).toBe("https://attacker.test")
    expect(buildVaultChildEnv(result,"personal",pin())).toEqual(result)
    for (const extra of [{MEHEN_CONFIG_DIR:""},{MEHEN_CONFIG_DIR:"/other"},{MEHEN_MANAGED_CONTEXT:""},{MEHEN_MANAGED_CONTEXT:"work"}]) expect(() => buildVaultChildEnv({...parent,...extra},"personal",pin())).toThrow()
    expect(() => buildVaultChildEnv(parent,"personal",pin({device:null}))).toThrow()
    expect(() => buildVaultChildEnv(parent,"Invalid",pin())).toThrow()
  })
})

function withFiles(run: (root: string, options: VaultFileOptions) => void): void {
  const root = realpathSync(mkdtempSync(join(userInfo().homedir, ".a0-profile-")))
  try { chmodSync(root,0o700); run(root,{ownerRoot:root}) } finally { rmSync(root,{recursive:true,force:true}) }
}
function fixture(root: string) {
  const catalogue = join(root,"config","pins")
  mkdirSync(catalogue,{recursive:true,mode:0o700})
  chmodSync(join(root,"config"),0o755)
  const agentDir = join(root,"claude-profile"), configDir = join(root,"mehen-personal")
  mkdirSync(agentDir,{mode:0o700});mkdirSync(configDir,{mode:0o700})
  const value = pin({agentDir,configDir})
  const path = join(catalogue,"contexts.json")
  writeFileSync(path,text({version:3,contexts:{personal:value}}),{mode:0o600})
  return { path, catalogue, value }
}

describe("synthetic filesystem verification", () => {
  afterEach(() => setPasswdHomeLookupForTests(null))
  // The passwd lookup is a stand-in (root plays the passwd home), so no test
  // here reads this user's real marker path.
  test("every default owner root uses the passwd home, not HOME", () => withFiles((root) => {
    const f = fixture(root)
    const empty = join(root, "empty-home")
    mkdirSync(empty, { mode: 0o700 })
    const previous = process.env.HOME
    try {
      setPasswdHomeLookupForTests(() => ({ kind: "found", home: root }))
      process.env.HOME = empty
      expect(defaultOwnerRoot()).toBe(root)
      verifyVaultDirectory(f.value.agentDir)
      verifyVaultDirectory(f.value.configDir)
      verifyVaultPrivateFile(f.path)
      expect(readVaultContextsFile(f.path).contexts.personal).toEqual(f.value)
      const marker = join(f.catalogue, "managed-agents")
      writeFileSync(marker, "", { mode: 0o600 })
      expect(readManagedVaultMarker(marker)).toBe(true)
      // Bun's os.userInfo() and os.homedir() both follow HOME; pin the forbidden
      // source-level fallbacks and any environment read.
      const source = readFileSync(new URL("./agent-profiles.ts", import.meta.url), "utf8")
      expect(source).not.toMatch(/\bhomedir\s*\(/)
      expect(source).not.toMatch(/userInfo\(\)\.homedir/)
      expect(source).not.toMatch(/process\.env/)
      expect(source).not.toMatch(/MEHEN_TEST_PASSWD_HOME/)
    } finally { if (previous === undefined) delete process.env.HOME; else process.env.HOME = previous }
  }))
  test("real private non-pi profile, map and config with 0755 intermediate directory", () => withFiles((root,options) => {
    const f = fixture(root)
    expect(readVaultContextsFile(f.path,options).contexts.personal).toEqual(f.value)
    verifyVaultDirectory(f.value.agentDir, options);verifyVaultDirectory(f.value.configDir, options)
    expect(readManagedVaultMarker(join(f.catalogue,"absent"),options)).toBe(false)
    const marker=join(f.catalogue,"managed-agents");writeFileSync(marker,"",{mode:0o600})
    expect(readManagedVaultMarker(marker,options)).toBe(true)
  }))
  test("bad permissions refuse, restored permissions pass", () => withFiles((root,options) => {
    const f=fixture(root)
    for (const [path,unsafe,safe] of [[f.path,0o644,0o600],[f.catalogue,0o755,0o700],[f.value.configDir,0o755,0o700],[f.value.agentDir,0o750,0o700],[join(root,"config"),0o775,0o755]] as const) {
      chmodSync(path,unsafe)
      expect(() => path===f.value.configDir || path===f.value.agentDir ? verifyVaultDirectory(path,options) : readVaultContextsFile(f.path,options)).toThrow()
      chmodSync(path,safe)
      readVaultContextsFile(f.path,options);verifyVaultDirectory(f.value.configDir,options);verifyVaultDirectory(f.value.agentDir,options)
    }
  }))
  test("symlinked map, target and intermediate components refuse", () => withFiles((root,options) => {
    const f=fixture(root)
    const fileLink=join(f.catalogue,"link.json");symlinkSync(f.path,fileLink)
    expect(() => readVaultContextsFile(fileLink,options)).toThrow()
    const dirLink=join(root,"link");symlinkSync(f.catalogue,dirLink)
    expect(() => readVaultContextsFile(join(dirLink,"contexts.json"),options)).toThrow()
    const targetLink=join(root,"profile-link");symlinkSync(f.value.agentDir,targetLink)
    expect(() => verifyVaultDirectory(targetLink,options)).toThrow()
    readVaultContextsFile(f.path,options);verifyVaultDirectory(f.value.agentDir,options)
  }))
  test("foreign uid is simulated with injected lstat, not real chown", () => withFiles((root,options) => {
    const f=fixture(root)
    for (const foreign of [f.path,f.catalogue,f.value.agentDir,join(root,"config")]) {
      const injected = {...options,lstat:(path:string) => {const stat=lstatSync(path);return path===foreign?{...stat,uid:userInfo().uid+1,isDirectory:()=>stat.isDirectory(),isFile:()=>stat.isFile(),isSymbolicLink:()=>stat.isSymbolicLink()}:stat}}
      expect(() => foreign===f.value.agentDir?verifyVaultDirectory(foreign,injected):readVaultContextsFile(f.path,injected)).toThrow()
    }
    readVaultContextsFile(f.path,options)
  }))
  test("outside owner root, non-canonical path, wrong file kind and unreadable marker refuse", () => withFiles((root,options) => {
    const f=fixture(root)
    expect(() => verifyVaultDirectory(tmpdir(),options)).toThrow()
    expect(() => verifyVaultDirectory(f.value.configDir + "/../mehen-personal",options)).toThrow()
    expect(() => verifyVaultPrivateFile(f.catalogue,options)).toThrow()
    expect(() => readManagedVaultMarker(f.catalogue,options)).toThrow()
    const marker=join(f.catalogue,"managed-agents");writeFileSync(marker,"",{mode:0o644})
    expect(() => readManagedVaultMarker(marker,options)).toThrow()
    chmodSync(marker,0o600)
    expect(() => readManagedVaultMarker(marker,{...options,readFile:()=>{throw new Error("injected unreadable")}})).toThrow()
    expect(readManagedVaultMarker(marker,options)).toBe(true)
    symlinkSync(join(root,"missing"),join(f.catalogue,"dangling"))
    expect(() => readManagedVaultMarker(join(f.catalogue,"dangling"),options)).toThrow()
  }))
  test("unsafe ancestors above owner root refuse with injected metadata", () => withFiles((root,options) => {
    const f=fixture(root)
    const injected = {...options,lstat:(path:string) => {const stat=lstatSync(path);return path==="/"?{...stat,mode:stat.mode|0o020,isDirectory:()=>true,isFile:()=>false,isSymbolicLink:()=>false}:stat}}
    expect(() => readVaultContextsFile(f.path,injected)).toThrow()
    readVaultContextsFile(f.path,options)
  }))
  test("marker discovery ignores HOME and safely missing parents mean absence", () => withFiles((root,options) => {
    expect(readManagedVaultMarker(undefined,options)).toBe(false)
    mkdirSync(join(root,".config","mehen"),{recursive:true,mode:0o700})
    const marker=join(root,".config","mehen","managed-agents")
    writeFileSync(marker,"",{mode:0o600})
    const previous=process.env.HOME
    try {
      const empty=join(root,"empty-home");mkdirSync(empty,{mode:0o700});process.env.HOME=empty
      expect(readManagedVaultMarker(undefined,options)).toBe(true)
    } finally { if(previous===undefined) delete process.env.HOME; else process.env.HOME=previous }
    chmodSync(join(root,".config"),0o775)
    expect(() => readManagedVaultMarker(undefined,options)).toThrow()
    chmodSync(join(root,".config"),0o755)
    expect(readManagedVaultMarker(undefined,options)).toBe(true)
  }))
  test("oversized or invalid UTF-8 map refuses; regular valid map passes", () => withFiles((root,options) => {
    const f=fixture(root)
    writeFileSync(f.path," ".repeat(32769))
    expect(() => readVaultContextsFile(f.path,options)).toThrow()
    writeFileSync(f.path,Buffer.from([0x22,0xff,0x22]))
    expect(() => readVaultContextsFile(f.path,options)).toThrow()
    writeFileSync(f.path,text({version:3,contexts:{personal:f.value}}))
    readVaultContextsFile(f.path,options)
  }))

})

// MK: the managed-host marker is read under the passwd home, looked up by uid.
// Bun's os.userInfo() reports the process's initial HOME as the home, so
// `HOME=/elsewhere mehen ...` used to move marker discovery and escape rule 0.
// Every test injects the lookup (or runs the CLI through the test entry, whose
// stand-in passwd home is MEHEN_TEST_PASSWD_HOME), so none reads this user's
// real marker path; markers are only ever written below a temporary root.
// The lookup output is parsed strictly, the passwd home's own path is
// verified before it is trusted or cached, and only a proved
// absence of the uid's entry means "not managed".
describe("passwd home resolution (MK)", () => {
  afterEach(() => setPasswdHomeLookupForTests(null))
  const uid = process.getuid!()
  const record = (patch: Record<string, string> = {}) => {
    const fields: Record<string, string> = { name: "sam", password: "********", uid: "503", gid: "20", dir: "/Users/sam", shell: "/bin/zsh", gecos: "Sam", ...patch }
    return ["name", "password", "uid", "gid", "dir", "shell", "gecos"].map((key) => `${key}: ${fields[key]}`).join("\n") + "\n\n"
  }
  const passwdText = ["root:x:0:0:root:/root:/bin/bash", "other:x:5031:5031::/home/other:/bin/sh", "nohome:x:7:7:::/bin/sh", "sam:x:503:20:Sam:/home/sam:/bin/zsh", "later:x:503:20::/home/later:/bin/sh", ""].join("\n")
  const bytes = (text: string) => new TextEncoder().encode(text)
  const invalidUtf8 = new Uint8Array([0x6a, 0x3a, 0xff, 0x0a])
  const malformed = expect.objectContaining({ kind: "malformed" })
  const lookupError = expect.objectContaining({ kind: "error" })

  function refusal(run: () => unknown): CliError {
    try { run() } catch (error) { if (error instanceof CliError) return error; throw error }
    throw new Error("expected a CliError")
  }
  function marker(home: string): void {
    mkdirSync(join(home, ".config", "mehen"), { recursive: true, mode: 0o700 })
    writeFileSync(join(home, ".config", "mehen", "managed-agents"), "", { mode: 0o600 })
  }
  function homes(root: string, ...names: string[]): string[] {
    return names.map((name) => { const path = join(root, name); mkdirSync(path, { mode: 0o700 }); return path })
  }
  async function withRoot(run: (root: string) => Promise<void>): Promise<void> {
    const root = realpathSync(mkdtempSync(join(userInfo().homedir, ".a0-profile-")))
    try { chmodSync(root, 0o700); await run(root) } finally { rmSync(root, { recursive: true, force: true }) }
  }
  function withEnv(patch: Record<string, string>, run: () => void): void {
    const previous = Object.fromEntries(Object.keys(patch).map((key) => [key, process.env[key]]))
    try { Object.assign(process.env, patch); run() } finally {
      for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value }
    }
  }
  type Body = { error: string; message: string; next?: { say?: string } }
  type Io = { run?: Record<string, CommandOutcome>; files?: Record<string, FileOutcome> }
  function io(answers: Io, calls: string[][] = []): PasswdLookupIo {
    return {
      run: (binary, args) => { calls.push([binary, ...args]); return answers.run?.[binary] ?? { kind: "absent" } },
      readFile: (path) => { calls.push(["read", path]); return answers.files?.[path] ?? { kind: "absent" } },
    }
  }
  const exited = (code: number, stdout: string | Uint8Array = ""): CommandOutcome => ({ kind: "exited", code, stdout: typeof stdout === "string" ? bytes(stdout) : stdout })
  const read = (text: string | Uint8Array): FileOutcome => ({ kind: "read", bytes: typeof text === "string" ? bytes(text) : text })

  test("getent's answer is exactly one complete record for the uid", () => {
    const good = "sam:x:503:20:Sam:/home/sam:/bin/zsh"
    expect(passwdHomeFromGetent(good + "\n", 503)).toEqual({ kind: "found", home: "/home/sam" })
    expect(passwdHomeFromGetent(good, 503)).toEqual({ kind: "found", home: "/home/sam" })
    for (const text of [
      "me:x:503:20:Name\nforged:x:503:20::/forged/home:/bin/sh\n:/real/home:/bin/sh\n", // newline fragments around an injected record
      good + "\nforged:x:503:20::/forged/home:/bin/sh\n", // an extra record
      good + "\n\n",
      "sam:x:503:20:Sam: the second:/home/sam:/bin/zsh\n", // a colon in gecos changes the field count
      "sam:x:503:20:Sam:/home/sam:/bin/zsh:extra\n",
      "other:x:5031:5031::/home/other:/bin/sh\n", // another uid
      "sam:x:503:20:Sam::/bin/zsh\n", // empty home
      ":x:503:20:Sam:/home/sam:/bin/zsh\n", // no name
      "sam:x:0503:20:Sam:/home/sam:/bin/zsh\n", "sam:x:503:staff:Sam:/home/sam:/bin/zsh\n",
      "sam:x:503:20:Sam:/home/sam\r:/bin/zsh\n", "sam:x:503:20:Sam:/home/sa m:/bin/zsh\n", "",
    ]) expect(passwdHomeFromGetent(text, 503)).toEqual(malformed)
    // A relative home is the record's answer; the resolver refuses it.
    expect(passwdHomeFromGetent("sam:x:503:20::home/sam:/bin/sh\n", 503)).toEqual({ kind: "found", home: "home/sam" })
  })

  test("/etc/passwd is read as a database: every record valid, the first for the uid wins", () => {
    expect(passwdHomeFromPasswdFile(passwdText, 503)).toEqual({ kind: "found", home: "/home/sam" })
    expect(passwdHomeFromPasswdFile(passwdText, 0)).toEqual({ kind: "found", home: "/root" })
    expect(passwdHomeFromPasswdFile(passwdText, 5031)).toEqual({ kind: "found", home: "/home/other" })
    expect(passwdHomeFromPasswdFile(passwdText, 50)).toEqual({ kind: "none" })
    expect(passwdHomeFromPasswdFile("\n" + passwdText + "\n\n", 503)).toEqual({ kind: "found", home: "/home/sam" })
    for (const text of [
      "root:x:0:0:root:/root:/bin/bash\nme:x:503:20:Name\nforged:x:503:20::/forged/home:/bin/sh\n:/real/home:/bin/sh\n",
      "sam:x:503:20:Sam: colon:/home/sam:/bin/zsh\nlater:x:503:20::/home/later:/bin/sh\n", // malformed requested uid, then another match
      passwdText + "+::::::\n", // a NIS compat line is not a record here
      passwdText + "broken:x:9\n", // a malformed unrelated record after the match
      "nohome:x:7:7:::/bin/sh\n", // the uid's own record without a home
      "sam:x:503:20:Sam:/home/sam\r:/bin/zsh\n",
    ]) expect(passwdHomeFromPasswdFile(text, text.startsWith("nohome") ? 7 : 503)).toEqual(malformed)
  })

  test("dscacheutil's answer is exactly one record of the seven native properties", () => {
    expect(passwdHomeFromDscacheutil(record(), 503)).toEqual({ kind: "found", home: "/Users/sam" })
    expect(passwdHomeFromDscacheutil(record({ gecos: "Sam: the second" }), 503)).toEqual({ kind: "found", home: "/Users/sam" })
    expect(passwdHomeFromDscacheutil(record({ gecos: "" }), 503)).toEqual({ kind: "found", home: "/Users/sam" })
    expect(passwdHomeFromDscacheutil(record({ uid: "-2" }).replace("uid: -2", "uid: 4294967294"), 4294967294)).toEqual({ kind: "found", home: "/Users/sam" })
    expect(passwdHomeFromDscacheutil("", 503)).toEqual({ kind: "none" })
    const valid = record()
    const lines = valid.slice(0, -2).split("\n")
    for (const text of [
      record({ gecos: "Name\ndir: /forged/home" }), // a duplicate dir injected through gecos
      record({ shell: "/bin/zsh\nuid: 503" }).replace("uid: 503\n", "uid: 504\n"), // a duplicate uid injected through shell
      record({ uid: "504", dir: "/other/home" }) + record(), // an unrelated block, then the uid's
      record() + record(), // two records
      record({ gecos: "Name\n\nname: me" }), // an inserted blank-line block
      valid.slice(0, -1) + "garbage\n\n", // a malformed line after otherwise valid properties
      lines.filter((line) => !line.startsWith("dir:")).join("\n") + "\n\n", // a missing property
      lines.filter((line) => !line.startsWith("gecos:")).join("\n") + "\nhome: /forged\n\n", // an unknown property
      lines.filter((line) => !line.startsWith("gecos:")).join("\n") + "\ndir: /forged/home\n\n", // seven lines, dir twice
      valid.replace("uid: 503", " uid: 503"), valid.replace("uid: 503", "UID: 503"), valid.replace("uid: 503", "uid:503"),
      "garbage\nuid: 503\ndir: /forged/home\n",
      valid.slice(0, -1), // no closing blank line
      record({ uid: "504" }), record({ uid: "0503" }), record({ gid: "staff" }), record({ name: "" }),
      record({ dir: "" }), record({ dir: "/Users/je\0ff" }), record({ dir: "/Users/sam\r" }), record({ dir: "/Users/sam\n" }),
    ]) expect(passwdHomeFromDscacheutil(text, 503)).toEqual(malformed)
    expect(passwdHomeFromDscacheutil(record({ dir: "Users/sam" }), 503)).toEqual({ kind: "found", home: "Users/sam" })
  })

  test("nsswitch.conf's passwd sources, with a missing file or line meaning files", () => {
    expect(passwdSources(null)).toEqual(["files"])
    expect(passwdSources("# nothing\ngroup: files\n")).toEqual(["files"])
    expect(passwdSources("passwd: files\n")).toEqual(["files"])
    expect(passwdSources("passwd:   files [NOTFOUND=return] sss # comment\n")).toEqual(["files", "sss"])
    expect(passwdSources("passwd: files systemd\n")).toEqual(["files", "systemd"])
    expect(passwdSources("passwd: files\npasswd: ldap\n")).toBe(null)
    expect(passwdSources("passwd: files [ NOTFOUND=return ]\n")).toBe(null)
  })

  test("macOS: one dscacheutil call by uid; no record and every failure are errors, never proof of none", () => {
    const calls: string[][] = []
    const darwin = (outcome: CommandOutcome) => systemPasswdHome(503, "darwin", io({ run: { "/usr/bin/dscacheutil": outcome } }, calls))
    expect(darwin(exited(0, record()))).toEqual({ kind: "found", home: "/Users/sam" })
    expect(calls.splice(0)).toEqual([["/usr/bin/dscacheutil", "-q", "user", "-a", "uid", "503"]])
    for (const outcome of [exited(0, ""), exited(0, record({ gecos: "Name\ndir: /forged/home" })), exited(0, invalidUtf8), exited(1, record()), { kind: "failed", reason: "stopped by SIGTERM" } as const, { kind: "absent" } as const]) {
      expect(darwin(outcome)).toEqual(lookupError)
    }
    expect(calls.every((call) => call[0] === "/usr/bin/dscacheutil")).toBe(true)
  })

  test("Linux: getent's success is final, a malformed one never falls back; /etc/passwd is the fallback; none is proved only with files alone", () => {
    const getentRecord = exited(0, "sam:x:503:20::/srv/sam:/bin/sh\n")
    const etc = (passwd: FileOutcome, nsswitch?: FileOutcome) => ({ "/etc/passwd": passwd, ...(nsswitch ? { "/etc/nsswitch.conf": nsswitch } : {}) })
    const linux = (answers: Io, calls: string[][] = []) => systemPasswdHome(503, "linux", io(answers, calls))
    let calls: string[][] = []
    expect(linux({ run: { "/usr/bin/getent": getentRecord }, files: etc(read(passwdText)) }, calls)).toEqual({ kind: "found", home: "/srv/sam" })
    expect(calls).toEqual([["/usr/bin/getent", "passwd", "503"]])
    // A malformed success refuses and reads nothing else.
    for (const stdout of ["me:x:503:20:Name\nforged:x:503:20::/forged/home:/bin/sh\n:/real/home:/bin/sh\n", "sam:x:503:20::/srv/sam:/bin/sh\nmore:x:503:20::/x:/bin/sh\n", "", invalidUtf8]) {
      calls = []
      expect(linux({ run: { "/usr/bin/getent": exited(0, stdout) }, files: etc(read(passwdText)) }, calls)).toEqual(lookupError)
      expect(calls).toEqual([["/usr/bin/getent", "passwd", "503"]])
    }
    // getent missing or failed: /etc/passwd's first record for the uid.
    for (const getent of [{ kind: "absent" } as const, { kind: "failed", reason: "stopped by SIGTERM" } as const, exited(1)]) {
      calls = []
      expect(linux({ run: { "/usr/bin/getent": getent }, files: etc(read(passwdText)) }, calls)).toEqual({ kind: "found", home: "/home/sam" })
      expect(calls).toEqual([["/usr/bin/getent", "passwd", "503"], ["read", "/etc/passwd"]])
    }
    // getent found none but the file has one: they disagree.
    expect(linux({ run: { "/usr/bin/getent": exited(2) }, files: etc(read(passwdText)) })).toEqual(lookupError)
    // The fallback itself refuses when it is missing, unreadable, malformed or not UTF-8.
    for (const passwd of [{ kind: "absent" } as const, { kind: "failed", reason: "EACCES" } as const, read("me:x:503:20:Name\nforged:x:503:20::/forged/home:/bin/sh\n:/real/home:/bin/sh\n"), read(invalidUtf8)]) {
      expect(linux({ run: { "/usr/bin/getent": { kind: "absent" } }, files: etc(passwd, read("passwd: files\n")) })).toEqual(lookupError)
    }
    // Proved absence: getent found none (or is missing), the file has none, files is the only source.
    const none = read("root:x:0:0:root:/root:/bin/sh\n")
    for (const getent of [exited(2), { kind: "absent" } as const]) {
      for (const nsswitch of [read("passwd: files\n"), { kind: "absent" } as const, read("hosts: files dns\n")]) {
        calls = []
        expect(linux({ run: { "/usr/bin/getent": getent }, files: etc(none, nsswitch) }, calls)).toEqual({ kind: "not-found" })
        expect(calls).toEqual([["/usr/bin/getent", "passwd", "503"], ["read", "/etc/passwd"], ["read", "/etc/nsswitch.conf"]])
      }
    }
    // Anything else is not proof: another source, an unreadable switch, a getent that failed.
    for (const nsswitch of [read("passwd: files sss\n"), read("passwd: files systemd\n"), read("passwd: compat\n"), read("passwd: files\npasswd: ldap\n"), read(invalidUtf8), { kind: "failed", reason: "EACCES" } as const]) {
      expect(linux({ run: { "/usr/bin/getent": exited(2) }, files: etc(none, nsswitch) })).toEqual(lookupError)
    }
    for (const getent of [{ kind: "failed", reason: "stopped by SIGTERM" } as const, exited(1), exited(3)]) {
      expect(linux({ run: { "/usr/bin/getent": getent }, files: etc(none, read("passwd: files\n")) })).toEqual(lookupError)
    }
    for (const platform of ["freebsd", "win32"] as const) {
      calls = []
      expect(systemPasswdHome(503, platform, io({ run: { "/usr/bin/getent": getentRecord } }, calls))).toEqual(lookupError)
      expect(calls).toEqual([])
    }
  })

  test("the system lookup ignores HOME, USER and PATH: a child with them changed resolves the same home", async () => {
    const here = systemPasswdHome(uid)
    expect(here.kind).toBe("found")
    const script = `import { systemPasswdHome } from ${JSON.stringify(join(import.meta.dir, "agent-profiles.ts"))}; console.log(JSON.stringify(systemPasswdHome(${uid})))`
    const child = Bun.spawn([process.execPath, "--eval", script], { env: { HOME: "/elsewhere", USER: "nobody", LOGNAME: "nobody", PATH: "/nonexistent" }, stdout: "pipe", stderr: "pipe", timeout: 10_000 })
    const [stdout, code] = await Promise.all([new Response(child.stdout).text(), child.exited])
    expect(code).toBe(0)
    expect(JSON.parse(stdout)).toEqual(here)
    expect(here).not.toEqual({ kind: "found", home: "/elsewhere" })
  })

  test("the passwd home's own path is walked without following links: ownership and modes as the marker walk requires", () => withFiles((root) => {
    expect(untrustedPasswdHome(root, uid)).toBe(null)
    const fake = (patch: (path: string) => Partial<{ uid: number; mode: number }>) => (path: string) => {
      const stat = lstatSync(path)
      const change = patch(path)
      return { ...stat, uid: change.uid ?? stat.uid, mode: change.mode ?? stat.mode, isDirectory: () => stat.isDirectory(), isFile: () => stat.isFile(), isSymbolicLink: () => stat.isSymbolicLink() }
    }
    const parent = join(root, "..")
    expect(untrustedPasswdHome(root, uid, fake((path) => path === realpathSync(parent) ? { uid: uid + 1 } : {}))).toBe(`${realpathSync(parent)} is not owned by this user or root`)
    expect(untrustedPasswdHome(root, uid, fake((path) => path === root ? { uid: uid + 1 } : {}))).toBe(`${root} is not owned by this user`)
    if (uid !== 0) expect(untrustedPasswdHome(root, uid, fake((path) => path === root ? { uid: 0 } : {}))).toBe(`${root} is not owned by this user`)
    expect(untrustedPasswdHome(root, uid, fake((path) => path === realpathSync(parent) ? { uid: 0 } : {}))).toBe(null)
    expect(untrustedPasswdHome(root, uid, fake((path) => path === "/" ? { mode: 0o40777 } : {}))).toBe("/ can be written by group or others")
    expect(untrustedPasswdHome(join(root, "missing"), uid)).toBe(`${join(root, "missing")} does not exist or cannot be read`)
  }))

  test("the default owner root is the verified passwd home for this process's uid, looked up once; HOME and MEHEN_HOME afterwards change nothing", () => withFiles((root) => {
    const seen: number[] = []
    setPasswdHomeLookupForTests((asked) => { seen.push(asked); return { kind: "found", home: root } })
    expect(defaultOwnerRoot()).toBe(root)
    withEnv({ HOME: join(root, "elsewhere"), MEHEN_HOME: join(root, "moved") }, () => {
      expect(defaultOwnerRoot()).toBe(root)
      expect(readManagedVaultMarker()).toBe(false)
      expect(managedHost()).toBe(false)
    })
    expect(seen).toEqual([uid])
  }))

  test("HOME pointing elsewhere still finds the marker under the passwd home, and a marker under HOME alone is not one", () => withFiles((root) => {
    const [passwdHome, elsewhere, plain] = homes(root, "passwd-home", "elsewhere", "plain")
    marker(passwdHome!)
    setPasswdHomeLookupForTests(() => ({ kind: "found", home: passwdHome! }))
    withEnv({ HOME: elsewhere! }, () => {
      expect(readManagedVaultMarker()).toBe(true)
      expect(managedHost()).toBe(true)
    })
    setPasswdHomeLookupForTests(() => ({ kind: "found", home: plain! }))
    withEnv({ HOME: passwdHome! }, () => {
      expect(readManagedVaultMarker()).toBe(false)
      expect(managedHost()).toBe(false)
    })
  }))

  test("a changed MEHEN_HOME does not move marker discovery", () => withFiles((root) => {
    const [passwdHome, elsewhere, plain] = homes(root, "passwd-home", "elsewhere", "plain")
    const moved = join(elsewhere!, "root")
    marker(passwdHome!)
    setPasswdHomeLookupForTests(() => ({ kind: "found", home: passwdHome! }))
    // Managed: the launcher's claim stands whatever MEHEN_HOME says.
    expect(resolveHome({ HOME: elsewhere!, MEHEN_HOME: moved, MEHEN_MANAGED_CONTEXT: "work" })).toEqual({ root: moved, source: "MEHEN_HOME" })
    // A marker under MEHEN_HOME (either spelling) or HOME makes nothing managed.
    marker(moved)
    marker(elsewhere!)
    writeFileSync(join(moved, "managed-agents"), "", { mode: 0o600 })
    setPasswdHomeLookupForTests(() => ({ kind: "found", home: plain! }))
    const claimed = refusal(() => resolveHome({ HOME: elsewhere!, MEHEN_HOME: moved, MEHEN_MANAGED_CONTEXT: "work" }))
    expect(claimed.code).toBe("workspace_mismatch")
    expect(claimed.message).toContain("no managed-host marker")
  }))

  function expectRefused(says: string, root: string): void {
    const refused = refusal(() => readManagedVaultMarker())
    expect(refused.code).toBe("key_insecure")
    expect(exitCodeFor(refused.code)).toBe(EXIT.identity)
    expect(refused.message).toContain(`the passwd home of uid ${uid}`)
    expect(refused.message).toContain(says)
    expect(refused.message).toContain("whether this host is managed cannot be verified")
    expect(refused.next?.say).toContain("HOME and MEHEN_HOME do not move where the managed-host marker is read")
    for (const run of [() => managedHost(), () => resolveHome({ HOME: root }), () => verifyVaultDirectory(root)]) expect(refusal(run).code).toBe("key_insecure")
  }

  test("a failed lookup or an untrusted passwd home refuses key_insecure by name and caches nothing", () => withFiles((root) => {
    const [real, safe] = homes(root, "real", "safe")
    const file = join(root, "file"); writeFileSync(file, "", { mode: 0o600 })
    const link = join(root, "link-home"); symlinkSync(real!, link)
    const linkedParent = join(root, "linked-parent"); symlinkSync(root, linkedParent)
    const shared = join(root, "shared"); mkdirSync(shared, { mode: 0o700 }); chmodSync(shared, 0o777)
    const sharedHome = join(shared, "home"); mkdirSync(sharedHome, { mode: 0o700 })
    const sharedLink = join(shared, "link"); symlinkSync(safe!, sharedLink)
    // A forged home, real and markerless, as a malformed directory service answer would name it.
    const forged = systemPasswdHome(uid, "darwin", io({ run: { "/usr/bin/dscacheutil": exited(0, record({ uid: String(uid), dir: real!, gecos: `Name\ndir: ${safe!}` })) } }))
    expect(forged.kind).toBe("error")
    const cases: [PasswdHomeResult, string][] = [
      [{ kind: "error", reason: "injected failure" }, "cannot be resolved (injected failure)"],
      [forged, "cannot be resolved (dscacheutil answered 8 lines"],
      [{ kind: "found", home: "relative/home" }, "is not a canonical absolute path"],
      [{ kind: "found", home: `${real!}/` }, "is not a canonical absolute path"],
      [{ kind: "found", home: `${real!}/../safe` }, "is not a canonical absolute path"],
      [{ kind: "found", home: "" }, "is not a canonical absolute path"],
      [{ kind: "found", home: join(root, "missing") }, `${join(root, "missing")} does not exist or cannot be read`],
      [{ kind: "found", home: file }, `${file} is not a directory`],
      [{ kind: "found", home: link }, `${link} is a symlink`],
      [{ kind: "found", home: join(linkedParent, "real") }, `${linkedParent} is a symlink`],
      [{ kind: "found", home: sharedHome }, `${shared} can be written by group or others`],
      [{ kind: "found", home: sharedLink }, `${shared} can be written by group or others`],
    ]
    if (uid !== 0) cases.push([{ kind: "found", home: "/usr" }, "/usr is not owned by this user"])
    try {
      for (const [answer, says] of cases) {
        setPasswdHomeLookupForTests(() => answer)
        expectRefused(says, root)
        // A failed lookup asks for a passwd entry; an untrusted home for a safe path.
        expect(refusal(() => readManagedVaultMarker()).next?.say).toContain(answer.kind === "error" ? `Give uid ${uid} a passwd entry` : "not below a world-writable one such as /tmp")
      }
    } finally { chmodSync(shared, 0o700) }
  }))

  test("a home symlink retargeted between lookups never gives managed then unmanaged: both refuse", () => withFiles((root) => {
    const [marked, markerless] = homes(root, "marked", "markerless")
    marker(marked!)
    const link = join(root, "home-link")
    symlinkSync(marked!, link)
    setPasswdHomeLookupForTests(() => ({ kind: "found", home: link }))
    expectRefused(`${link} is a symlink`, root)
    rmSync(link); symlinkSync(markerless!, link)
    expectRefused(`${link} is a symlink`, root)
  }))

  test("a refusal is never cached: one lookup recovers without the setter, then its answer is cached", () => withFiles((root) => {
    const [home] = homes(root, "home")
    const file = join(root, "file"); writeFileSync(file, "", { mode: 0o600 })
    const link = join(root, "link"); symlinkSync(home!, link)
    const answers: PasswdHomeResult[] = [{ kind: "error", reason: "injected failure" }, { kind: "found", home: join(root, "missing") }, { kind: "found", home: file }, { kind: "found", home: link }, { kind: "found", home: home! }]
    let calls = 0
    setPasswdHomeLookupForTests(() => answers[Math.min(calls++, answers.length - 1)]!)
    for (let i = 0; i < 4; i++) expect(refusal(() => readManagedVaultMarker()).code).toBe("key_insecure")
    expect(calls).toBe(4)
    expect(readManagedVaultMarker()).toBe(false)
    expect(defaultOwnerRoot()).toBe(home!)
    expect(managedHost()).toBe(false)
    expect(calls).toBe(5)
  }))

  test("a proved absence of the uid's passwd entry is not managed: no marker anywhere counts, the launcher's claim still refuses, pins cannot be verified", () => withFiles((root) => {
    const [elsewhere] = homes(root, "elsewhere")
    marker(elsewhere!)
    let calls = 0
    setPasswdHomeLookupForTests(() => { calls++; return { kind: "not-found" } })
    withEnv({ HOME: elsewhere! }, () => {
      expect(readManagedVaultMarker()).toBe(false)
      expect(managedHost()).toBe(false)
      expect(resolveHome({ HOME: elsewhere! })).toEqual({ root: join(elsewhere!, ".config", "mehen"), source: "default" })
      const claimed = refusal(() => resolveHome({ HOME: elsewhere!, MEHEN_MANAGED_CONTEXT: "work" }))
      expect(claimed.code).toBe("workspace_mismatch")
      expect(claimed.message).toContain("no managed-host marker")
    })
    // With no owner root, nothing can be verified as the owner's.
    expect(() => defaultOwnerRoot()).toThrow("Vault pin verification failed")
    expect(() => verifyVaultDirectory(elsewhere!)).toThrow("Vault pin verification failed")
    expect(() => readManagedVaultMarker(join(elsewhere!, ".config", "mehen", "managed-agents"))).toThrow("Vault pin verification failed")
    expect(calls).toBe(1)
  }))

  test("through mehen: HOME and MEHEN_HOME elsewhere still refuse on a managed host; a failed lookup is key_insecure; no entry runs unmanaged", () => withRoot(async (root) => {
    const [passwdHome, elsewhere] = homes(root, "passwd-home", "elsewhere")
    marker(passwdHome!)
    const commands = [["status", "--json"], ["workspace", "list", "--json"]]
    for (const env of [{ HOME: elsewhere! }, { HOME: elsewhere!, MEHEN_HOME: join(elsewhere!, "root") }] as Record<string, string>[]) {
      for (const args of commands) {
        const result = await runJv(args, { ...env, MEHEN_TEST_PASSWD_HOME: passwdHome! })
        expect(result.code).toBe(EXIT.usage)
        const body = JSON.parse(result.stdout) as Body
        expect(body.error).toBe("workspace_mismatch")
        expect(body.message).toContain("This host is managed")
      }
    }
    for (const args of commands) {
      const result = await runJv(args, { HOME: elsewhere!, MEHEN_TEST_PASSWD_HOME: "" })
      expect(result.code).toBe(EXIT.identity)
      const body = JSON.parse(result.stdout) as Body
      expect(body.error).toBe("key_insecure")
      expect(body.message).toContain(`the passwd home of uid ${uid} cannot be resolved`)
    }
    // No passwd entry: the marker under HOME counts for nothing and commands run.
    marker(elsewhere!)
    const list = await runJv(["workspace", "list", "--json"], { HOME: elsewhere!, MEHEN_TEST_PASSWD_HOME: "none" })
    expect(list.code).toBe(0)
    // Spanning status answers unmanaged: nothing enrolled, the enrol step next.
    const status = await runJv(["status", "--json"], { HOME: elsewhere!, MEHEN_TEST_PASSWD_HOME: "none" })
    expect(status.code).toBe(EXIT.ok)
    expect(JSON.parse(status.stdout)).toMatchObject({ workspaces: [], next: { command: "mehen enrol --workspace <slug> --json" } })
    const claimed = await runJv(["status", "--json"], { HOME: elsewhere!, MEHEN_TEST_PASSWD_HOME: "none", MEHEN_MANAGED_CONTEXT: "work" })
    expect((JSON.parse(claimed.stdout) as Body).message).toContain("no managed-host marker")
  }))

  // The one test that runs the production entry: it reads the real passwd
  // home's marker path (read-only; no marker is written there) to show the
  // test entry's variable is inert outside src/testing/main-under-test.ts.
  test("the real src/main.ts ignores MEHEN_TEST_PASSWD_HOME", () => withRoot(async (root) => {
    const [standIn, home] = homes(root, "stand-in", "home")
    marker(standIn!)
    const run = async (main: string, env: Record<string, string>) => {
      const child = Bun.spawn([process.execPath, main, "status", "--json"], { env: { PATH: process.env.PATH ?? "", ...env }, stdout: "pipe", stderr: "pipe", timeout: 20_000 })
      const [stdout, code] = await Promise.all([new Response(child.stdout).text(), child.exited])
      return { code, stdout }
    }
    const production = join(import.meta.dir, "main.ts")
    const env = { HOME: home!, MEHEN_MANAGED_CONTEXT: "work" }
    const withoutVariable = await run(production, env)
    for (const value of [standIn!, "none", ""]) expect(await run(production, { ...env, MEHEN_TEST_PASSWD_HOME: value })).toEqual(withoutVariable)
    // The same variable through the test entry does make the host managed.
    const underTest = await runJv(["status", "--json"], { ...env, MEHEN_TEST_PASSWD_HOME: standIn! })
    expect((JSON.parse(underTest.stdout) as Body).message).toContain("This host is managed")
    expect(underTest.stdout).not.toBe(withoutVariable.stdout)
  }))
})
