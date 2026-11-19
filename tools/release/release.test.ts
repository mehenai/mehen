import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { type Manifest, RELEASE_BINARIES, ReleaseError, assembleRelease, cliVersion, notarise, parseReleaseArgs, uploadCommands } from "./release.ts"
import { RELEASE_KEYS } from "../../apps/cli/src/release-keys.ts"

let root: string
let dist: string
let out: string

const hex = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex")

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "mehen-release-"))
  dist = join(root, "dist")
  out = join(root, "out")
  await mkdir(dist)
  for (const binary of RELEASE_BINARIES) await writeFile(join(dist, binary.name), `#!/bin/sh\necho ${binary.name}\n`.repeat(50))
})
afterEach(async () => rm(root, { recursive: true, force: true }))

const input = () => ({ dist, out, version: "0.2.0", commit: "a53a3de", builtAt: "2026-10-27T13:00:00.000Z", baseUrl: "https://mehen.dev/dl" })

describe("assembleRelease", () => {
  test("writes v<version>/<name>.gz, manifest.json and latest.json with both checksums", async () => {
    const manifest = await assembleRelease(input())
    expect(manifest.version).toBe("0.2.0")
    expect(manifest.commit).toBe("a53a3de")
    expect(manifest.builtAt).toBe("2026-10-27T13:00:00.000Z")
    expect(manifest.files.map((f) => f.name)).toEqual(RELEASE_BINARIES.map((b) => b.name))
    expect((await readdir(join(out, "v0.2.0"))).sort()).toEqual([...RELEASE_BINARIES.map((b) => `${b.name}.gz`), "manifest.json"].sort())
    for (const file of manifest.files) {
      const raw = new Uint8Array(await readFile(join(dist, file.name)))
      const gz = new Uint8Array(await readFile(join(out, "v0.2.0", `${file.name}.gz`)))
      expect(file.url).toBe(`https://mehen.dev/dl/v0.2.0/${file.name}.gz`)
      expect(file).toMatchObject({ sha256: hex(raw), size: raw.length, gzSha256: hex(gz), gzSize: gz.length })
      expect(Bun.gunzipSync(gz)).toEqual(raw)
    }
    expect(manifest.files.find((f) => f.name === "mehen-se")).toMatchObject({ os: "darwin", arch: "universal" })
    expect(manifest.files.find((f) => f.name === "mehen-linux-arm64")).toMatchObject({ os: "linux", arch: "arm64" })
    const written = JSON.parse(await readFile(join(out, "v0.2.0", "manifest.json"), "utf8")) as Manifest
    expect(written).toEqual(manifest)
    expect(await readFile(join(out, "latest.json"), "utf8")).toBe(await readFile(join(out, "v0.2.0", "manifest.json"), "utf8"))
  })

  test("refuses a version that already exists in --out, and leaves it alone", async () => {
    await assembleRelease(input())
    const before = await readFile(join(out, "v0.2.0", "manifest.json"), "utf8")
    await expect(assembleRelease({ ...input(), commit: "b00b1e5" })).rejects.toThrow(/already exists: version 0.2.0 was released/)
    expect(await readFile(join(out, "v0.2.0", "manifest.json"), "utf8")).toBe(before)
  })

  test("refuses a missing binary and leaves no v<version> behind", async () => {
    await rm(join(dist, "mehen-se"))
    await expect(assembleRelease(input())).rejects.toThrow(/mehen-se was not built/)
    expect(await readdir(out).catch(() => [])).not.toContain("v0.2.0")
    expect(await readdir(out).catch(() => [])).not.toContain("latest.json")
  })

  test("refuses a version that is not 1.2.3 shaped", async () => {
    await expect(assembleRelease({ ...input(), version: "../x" })).rejects.toThrow(ReleaseError)
  })
})

describe("uploadCommands", () => {
  test("every versioned file first, then its manifest, then latest.json; nothing is run", async () => {
    const manifest = await assembleRelease(input())
    const commands = uploadCommands(out, manifest)
    expect(commands).toHaveLength(RELEASE_BINARIES.length + 2)
    expect(commands[0]).toBe(`wrangler r2 object put mehen-releases/v0.2.0/mehen-darwin-arm64.gz --file ${join(out, "v0.2.0", "mehen-darwin-arm64.gz")} --content-type application/gzip --remote`)
    expect(commands.at(-2)).toContain("mehen-releases/v0.2.0/manifest.json")
    expect(commands.at(-1)).toBe(`wrangler r2 object put mehen-releases/latest.json --file ${join(out, "latest.json")} --content-type application/json --remote`)
  })
})

describe("notarise", () => {
  test("is a no-op that says why unless MEHEN_NOTARY_PROFILE is set", async () => {
    const ran: string[][] = []
    const result = await notarise(dist, {}, async (cmd) => void ran.push(cmd))
    expect(result).toEqual({ notarised: false, reason: expect.stringContaining("MEHEN_NOTARY_PROFILE is not set") })
    expect(ran).toEqual([])
  })

  test("with a profile, submits every macOS binary to notarytool", async () => {
    const ran: string[][] = []
    const result = await notarise(dist, { MEHEN_NOTARY_PROFILE: "mehen-notary" }, async (cmd) => void ran.push(cmd))
    expect(result.notarised).toBe(true)
    const submitted = ran.filter((cmd) => cmd[0] === "xcrun").map((cmd) => cmd[3])
    expect(submitted).toEqual(["mehen-darwin-arm64", "mehen-darwin-x64", "mehen-se"].map((name) => join(dist, `${name}.notarise.zip`)))
    for (const cmd of ran.filter((c) => c[0] === "xcrun")) expect(cmd.slice(4)).toEqual(["--keychain-profile", "mehen-notary", "--wait"])
  })
})

describe("parseReleaseArgs and the version", () => {
  test("--out is required; unknown flags and plain http are refused", () => {
    expect(() => parseReleaseArgs([])).toThrow(/--out <dir> is required/)
    expect(() => parseReleaseArgs(["--out", "x", "--push"])).toThrow(/unknown argument --push/)
    expect(() => parseReleaseArgs(["--out", "x", "--base-url", "http://mehen.dev/dl"])).toThrow(/https/)
    expect(parseReleaseArgs(["--out", "x", "--release", "--upload"])).toMatchObject({ upload: true, release: true, allowDirty: false, bucket: "mehen-releases", baseUrl: "https://mehen.dev/dl" })
  })

  test("the version is apps/cli/package.json's", async () => {
    const pkg = JSON.parse(await readFile(join(import.meta.dir, "..", "..", "apps", "cli", "package.json"), "utf8")) as { version: string }
    expect(await cliVersion()).toBe(pkg.version)
  })
})

test("repeatable targets filter assembly and partial uploads need explicit consent", async () => {
  const { releaseBinaries } = await import("./release.ts")
  const args = parseReleaseArgs(["--out", out, "--target", "darwin-arm64", "--target", "darwin-arm64"])
  expect(args.targets).toEqual(["darwin-arm64"])
  const manifest = await assembleRelease({ ...input(), binaries: releaseBinaries(args.targets) })
  expect(manifest.files.map(f => f.name)).toEqual(["mehen-darwin-arm64", "mehen-se"])
  for (const flag of ["--upload", "--upload-script"]) {
    const flags = flag === "--upload" ? [flag] : [flag, join(root, "upload.sh")]
    expect(() => parseReleaseArgs(["--out", out, "--release", "--target", "linux-x64", ...flags])).toThrow("--partial")
    expect(parseReleaseArgs(["--out", out, "--release", "--target", "linux-x64", ...flags, "--partial"]).partial).toBe(true)
  }
  expect(() => parseReleaseArgs(["--out", out, "--target", "windows-x64"])).toThrow("--target must be")
  expect(() => parseReleaseArgs(["--out"])).toThrow("needs a value")
})

// A built darwin-arm64 binary as far as release.ts can tell: a script that
// answers `version --json` like the real one and extracts dist/mehen-se on
// `version --extract-helper`, beside an executable dist/mehen-se. codesign
// cannot verify a script, so the inspector stands in for it and records
// every check.
async function fakeDarwinBuild(commit: string, build: "release" | "dev"): Promise<void> {
  const { chmod } = await import("node:fs/promises")
  const info = JSON.stringify({ version: await cliVersion(), commit, build, helper: "embedded" })
  await writeFile(join(dist, "mehen-se"), "#!/bin/sh\n[ \"$1\" = available ]\n")
  await chmod(join(dist, "mehen-se"), 0o755)
  await writeFile(join(dist, "mehen-darwin-arm64"), `#!/bin/sh\nif [ "$2" = --extract-helper ]; then mkdir -p "$3" && cp '${join(dist, "mehen-se")}' "$3/mehen-se" && printf '%s\\n' "$3/mehen-se"; else printf '%s\\n' '${info}'; fi\n`)
  await chmod(join(dist, "mehen-darwin-arm64"), 0o755)
}
function codesignStub(calls: string[][], verdict: (cmd: string[]) => number = () => 0) {
  return async (cmd: string[]) => {
    calls.push(cmd)
    if (cmd[0] === "codesign") return { code: verdict(cmd), stdout: "", stderr: verdict(cmd) === 0 ? "" : "code object is not signed at all" }
    const { inspectCommand } = await import("./release.ts")
    return inspectCommand(cmd)
  }
}

// main refuses to run anywhere but macOS, where mehen-se builds.
test.skipIf(process.platform !== "darwin")("main isolates noisy child stdout from both forms of upload script", async () => {
  const { main, spawnChecked } = await import("./release.ts")
  const { spyOn } = await import("bun:test")
  const { chmod } = await import("node:fs/promises")
  const { createReleaseKey } = await import("./keys.ts")
  const { helperSigner } = await import("./sign.ts")
  await mkdir(join(root, "se"))
  const helper = join(root, "se", "mehen-se")
  await writeFile(helper, FAKE_SE)
  await chmod(helper, 0o755)
  const keyDir = join(root, "mehen-release")
  const key = await createReleaseKey({ id: "rk-test-noisy", presence: "none", dir: keyDir, helper })
  const stdout: string[] = [], stderr: string[] = []
  const outSpy = spyOn(process.stdout, "write").mockImplementation(chunk => { stdout.push(String(chunk)); return true })
  const errSpy = spyOn(process.stderr, "write").mockImplementation(chunk => { stderr.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString()); return true })
  try {
    await main(["--out", out, "--target", "darwin-arm64", "--partial", "--release", "--upload", "--upload-script", join(root, "upload.sh")], async cmd => {
      expect(cmd.slice(-2)).toEqual(["--target", "darwin-arm64"])
      await spawnChecked(["sh", "-c", "printf 'noisy build (not shell)\\n'"])
      await fakeDarwinBuild(cmd[cmd.indexOf("--commit") + 1]!, "release")
    }, dist, { inspect: codesignStub([]), trusted: [key], keyDir, signer: (signing) => helperSigner(helper, signing), treeClean: () => true })
    const script = await readFile(join(root, "upload.sh"), "utf8")
    expect(stdout.join("")).toBe(script)
    expect(script.startsWith("set -eu\n# PARTIAL release: latest.json will list only darwin-arm64.")).toBe(true)
    expect(script).toContain("\n# Upload v")
    expect(script).not.toContain("noisy build")
    expect(stderr.join("")).toContain("noisy build")
    expect(Bun.spawnSync(["sh", "-n", join(root, "upload.sh")]).exitCode).toBe(0)
  } finally { outSpy.mockRestore(); errSpy.mockRestore() }
})

// Signing. Every key here is a test key made by a fake mehen-se (a Bun
// script holding a WebCrypto key in its "blob"); nothing touches a Secure
// Enclave or ~/.config/mehen-release.
const FAKE_SE = `#!${process.execPath}
const [command, ...rest] = process.argv.slice(2)
const flag = (name) => { const i = rest.indexOf(name); return i === -1 ? null : rest[i + 1] }
const { appendFileSync } = await import("node:fs")
appendFileSync(import.meta.dir + "/calls.log", JSON.stringify([command, ...rest]) + "\\n")
if (command === "available") process.exit(0)
if (command === "create") {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey)
  await Bun.write(flag("--out"), JSON.stringify({ jwk, presence: rest.includes("--user-presence") }))
  console.log(JSON.stringify({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }))
  process.exit(0)
}
if (command === "sign") {
  const blob = JSON.parse(await Bun.file(flag("--key")).text())
  if (blob.presence && rest.includes("--no-interaction")) { console.error("mehen-se: signing failed: user presence required"); process.exit(1) }
  const key = await crypto.subtle.importKey("jwk", blob.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
  const data = new Uint8Array(await Bun.stdin.arrayBuffer())
  console.log(Buffer.from(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data)).toString("base64url"))
  process.exit(0)
}
process.exit(2)
`

describe("release keys and signing", () => {
  let helper: string
  let keyDir: string
  const calls = async () => (await readFile(join(root, "se", "calls.log"), "utf8")).trim().split("\n").map((line) => JSON.parse(line) as string[])

  beforeEach(async () => {
    const { chmod } = await import("node:fs/promises")
    await mkdir(join(root, "se"))
    helper = join(root, "se", "mehen-se")
    await writeFile(helper, FAKE_SE)
    await chmod(helper, 0o755)
    keyDir = join(root, "mehen-release")
  })

  test("keys.ts writes the sidecar with presence in a 0700 directory and prints the ReleaseKey", async () => {
    const { stat } = await import("node:fs/promises")
    const { createReleaseKey } = await import("./keys.ts")
    const { isReleaseKey } = await import("../../packages/protocol/src/release-manifest.ts")
    const open = await createReleaseKey({ id: "rk-test-open", presence: "none", dir: keyDir, helper, now: new Date("2026-10-28T12:00:00.000Z") })
    const touch = await createReleaseKey({ id: "rk-test-touch", presence: "required", dir: keyDir, helper })
    expect(isReleaseKey(open)).toBe(true)
    expect(open).toMatchObject({ id: "rk-test-open", alg: "ES256", presence: "none", created: "2026-10-28T12:00:00.000Z" })
    expect(touch.presence).toBe("required")
    expect(JSON.parse(await readFile(join(keyDir, "rk-test-open.json"), "utf8"))).toEqual(open)
    expect(JSON.parse(await readFile(join(keyDir, "rk-test-touch.json"), "utf8"))).toEqual(touch)
    expect((await stat(keyDir)).mode & 0o777).toBe(0o700)
    for (const name of ["rk-test-open.json", "rk-test-open.se", "rk-test-touch.json", "rk-test-touch.se"]) expect((await stat(join(keyDir, name))).mode & 0o777).toBe(0o600)
    expect(await calls()).toEqual([["create", "--out", join(keyDir, "rk-test-open.se")], ["create", "--out", join(keyDir, "rk-test-touch.se"), "--user-presence"]])
  })

  test("keys.ts never replaces a key and refuses a bad id or a linked directory", async () => {
    const { symlink } = await import("node:fs/promises")
    const { ReleaseKeyError, createReleaseKey, parseKeysArgs } = await import("./keys.ts")
    await createReleaseKey({ id: "rk-test-once", presence: "none", dir: keyDir, helper })
    const before = await readFile(join(keyDir, "rk-test-once.json"), "utf8")
    await expect(createReleaseKey({ id: "rk-test-once", presence: "required", dir: keyDir, helper })).rejects.toThrow(/already exists.*never replaced/)
    expect(await readFile(join(keyDir, "rk-test-once.json"), "utf8")).toBe(before)
    for (const id of ["../rk", "RK-UPPER", "", "rk test"]) await expect(createReleaseKey({ id, presence: "none", dir: keyDir, helper })).rejects.toThrow(ReleaseKeyError)
    await symlink(keyDir, join(root, "linked"))
    await expect(createReleaseKey({ id: "rk-test-link", presence: "none", dir: join(root, "linked"), helper })).rejects.toThrow("not a link")
    expect(parseKeysArgs(["create", "--id", "rk-release-2026"])).toEqual({ command: "create", id: "rk-release-2026", presence: "none" })
    expect(parseKeysArgs(["create", "--id", "rk-release-2026", "--user-presence"]).presence).toBe("required")
    for (const argv of [[], ["delete"], ["create"], ["create", "--id"], ["create", "--id", "x", "--force"]]) expect(() => parseKeysArgs(argv)).toThrow(ReleaseKeyError)
  })

  test("signing refuses a sidecar that disagrees with RELEASE_KEYS, about presence above all", async () => {
    const { createReleaseKey, readSigningKey } = await import("./keys.ts")
    const { SigningError, trustedEntry } = await import("./sign.ts")
    const key = await createReleaseKey({ id: "rk-test-agree", presence: "none", dir: keyDir, helper })
    const signing = await readSigningKey(keyDir, "rk-test-agree")
    expect(signing).toEqual({ key, blob: join(keyDir, "rk-test-agree.se") })
    expect(trustedEntry(signing.key, [key])).toEqual(key)
    expect(() => trustedEntry(signing.key, [])).toThrow("not in RELEASE_KEYS")
    expect(() => trustedEntry(signing.key, [{ ...key, presence: "required" }])).toThrow("says presence none but RELEASE_KEYS says required")
    expect(() => trustedEntry({ ...signing.key, presence: "required" }, [key])).toThrow("says presence required but RELEASE_KEYS says none")
    expect(() => trustedEntry(signing.key, [{ ...key, jwk: { ...key.jwk, x: key.jwk.y } }])).toThrow("different public key")
    expect(() => trustedEntry(signing.key, [{ ...key, created: "2027-01-01T00:00:00.000Z" }])).toThrow(SigningError)
  })

  test("readSigningKey refuses key files others can read and sidecars that are not the key's", async () => {
    const { chmod } = await import("node:fs/promises")
    const { createReleaseKey, readSigningKey } = await import("./keys.ts")
    await createReleaseKey({ id: "rk-test-files", presence: "none", dir: keyDir, helper })
    await chmod(join(keyDir, "rk-test-files.se"), 0o644)
    await expect(readSigningKey(keyDir, "rk-test-files")).rejects.toThrow("readable by other users")
    await chmod(join(keyDir, "rk-test-files.se"), 0o600)
    await writeFile(join(keyDir, "rk-test-files.json"), JSON.stringify({ id: "rk-test-other" }), { mode: 0o600 })
    await expect(readSigningKey(keyDir, "rk-test-files")).rejects.toThrow("is not the ReleaseKey sidecar")
    await expect(readSigningKey(keyDir, "rk-test-missing")).rejects.toThrow("No key sidecar")
    await chmod(keyDir, 0o755)
    await expect(readSigningKey(keyDir, "rk-test-files")).rejects.toThrow("0700 directory")
  })

  test("a manifest signed through mehen-se verifies against the trusted set; presence decides interaction", async () => {
    const { createReleaseKey, readSigningKey } = await import("./keys.ts")
    const { helperSigner, signManifest } = await import("./sign.ts")
    const { verifyManifestSignatures } = await import("../../packages/protocol/src/release-manifest.ts")
    const open = await createReleaseKey({ id: "rk-test-open", presence: "none", dir: keyDir, helper })
    const touch = await createReleaseKey({ id: "rk-test-touch", presence: "required", dir: keyDir, helper })
    const unsigned = await assembleRelease(input())
    for (const key of [open, touch]) {
      const signed = await signManifest(unsigned, key, helperSigner(helper, await readSigningKey(keyDir, key.id)), [open, touch])
      expect(await verifyManifestSignatures(JSON.parse(JSON.stringify(signed)), [open, touch])).toMatchObject({ ok: true, keyId: key.id })
      expect(await verifyManifestSignatures(signed, [key.id === open.id ? touch : open])).toEqual({ ok: false, reason: "unknown_key" })
    }
    const signs = (await calls()).filter((call) => call[0] === "sign")
    expect(signs).toEqual([["sign", "--key", join(keyDir, "rk-test-open.se"), "--no-interaction"], ["sign", "--key", join(keyDir, "rk-test-touch.se")]])
    // A sidecar that claims no presence for a blob that needs it fails fast, never waits.
    const lying = { ...touch, presence: "none" as const }
    await expect(signManifest(unsigned, lying, helperSigner(helper, { key: lying, blob: join(keyDir, "rk-test-touch.se") }), [lying])).rejects.toThrow("user presence required")
  })

  test("a signature that does not verify against the trusted set writes nothing", async () => {
    const { createReleaseKey, readSigningKey } = await import("./keys.ts")
    const { helperSigner, signManifest } = await import("./sign.ts")
    const real = await createReleaseKey({ id: "rk-test-real", presence: "none", dir: keyDir, helper })
    const impostor = await createReleaseKey({ id: "rk-test-impostor", presence: "none", dir: keyDir, helper })
    // The compiled entry names rk-test-real's id with the impostor's public key.
    const trusted = [{ ...real, jwk: impostor.jwk }]
    const signer = helperSigner(helper, await readSigningKey(keyDir, "rk-test-real"))
    await expect(assembleRelease({ ...input(), sign: (m) => signManifest(m, { ...real, jwk: impostor.jwk }, signer, trusted) })).rejects.toThrow("does not verify against RELEASE_KEYS (bad_signature)")
    expect(await readdir(out)).not.toContain("v0.2.0")
    expect(await readdir(out)).not.toContain("latest.json")
  })

  test("assembleRelease writes the signed manifest, and latest.json is its byte copy", async () => {
    const { createReleaseKey, readSigningKey } = await import("./keys.ts")
    const { helperSigner, signManifest } = await import("./sign.ts")
    const { verifyManifestSignatures } = await import("../../packages/protocol/src/release-manifest.ts")
    const key = await createReleaseKey({ id: "rk-test-release", presence: "none", dir: keyDir, helper })
    const signer = helperSigner(helper, await readSigningKey(keyDir, key.id))
    const manifest = await assembleRelease({ ...input(), sign: (m) => signManifest(m, key, signer, [key]) })
    expect(manifest.signatures).toHaveLength(1)
    const written = await readFile(join(out, "v0.2.0", "manifest.json"), "utf8")
    expect(await readFile(join(out, "latest.json"), "utf8")).toBe(written)
    expect(await verifyManifestSignatures(JSON.parse(written), [key])).toMatchObject({ ok: true, keyId: "rk-test-release" })
    expect(await verifyManifestSignatures(JSON.parse(await readFile(join(out, "latest.json"), "utf8")), [key])).toMatchObject({ ok: true })
  })

  test("--unsigned is only for a trial build; the signing key is resolved before anything is built", async () => {
    const { createReleaseKey } = await import("./keys.ts")
    const { releaseSigningKey } = await import("./release.ts")
    expect(() => parseReleaseArgs(["--out", out, "--unsigned"])).toThrow("needs --allow-dirty or --partial")
    expect(() => parseReleaseArgs(["--out", out, "--unsigned", "--upload"])).toThrow("need --release")
    expect(parseReleaseArgs(["--out", out, "--unsigned", "--allow-dirty"]).unsigned).toBe(true)
    expect(parseReleaseArgs(["--out", out, "--target", "linux-x64", "--unsigned", "--partial"]).unsigned).toBe(true)
    expect(() => parseReleaseArgs(["--out", out, "--unsigned", "--allow-dirty", "--key", "rk-x"])).toThrow("contradict")
    const args = parseReleaseArgs(["--out", out])
    expect(args).toMatchObject({ key: null, unsigned: false })
    await expect(releaseSigningKey(args, [], keyDir)).rejects.toThrow("RELEASE_KEYS in packages/protocol/src/release-keys.ts is empty")
    const one = await createReleaseKey({ id: "rk-test-one", presence: "none", dir: keyDir, helper })
    const two = await createReleaseKey({ id: "rk-test-two", presence: "required", dir: keyDir, helper })
    expect((await releaseSigningKey(args, [one], keyDir)).key).toEqual(one)
    await expect(releaseSigningKey(args, [one, two], keyDir)).rejects.toThrow("name the signing key with --key")
    expect((await releaseSigningKey(parseReleaseArgs(["--out", out, "--key", "rk-test-two"]), [one, two], keyDir)).key).toEqual(two)
    await expect(releaseSigningKey(args, [{ ...one, presence: "required" }], keyDir)).rejects.toThrow("says presence none but RELEASE_KEYS says required")
  })

  test.skipIf(process.platform !== "darwin")("main refuses to sign with an empty compiled set before building anything", async () => {
    const { main } = await import("./release.ts")
    let built = false
    await expect(main(["--out", out, "--target", "darwin-arm64", "--partial", "--allow-dirty"], async () => { built = true }, dist, { trusted: [] })).rejects.toThrow("RELEASE_KEYS in packages/protocol/src/release-keys.ts is empty")
    expect(built).toBe(false)
  })

  test.skipIf(process.platform !== "darwin")("main signs the release with the named key and writes a manifest the trusted set verifies", async () => {
    const { spyOn } = await import("bun:test")
    const { main } = await import("./release.ts")
    const { createReleaseKey } = await import("./keys.ts")
    const { helperSigner } = await import("./sign.ts")
    const { verifyManifestSignatures } = await import("../../packages/protocol/src/release-manifest.ts")
    const key = await createReleaseKey({ id: "rk-test-main", presence: "none", dir: keyDir, helper })
    const errSpy = spyOn(process.stderr, "write").mockImplementation(() => true)
    try {
      await main(["--out", out, "--target", "darwin-arm64", "--partial", "--allow-dirty"], async (cmd) => {
        expect(cmd).not.toContain("--release")
        await fakeDarwinBuild(cmd[cmd.indexOf("--commit") + 1]!, "dev")
      }, dist, { trusted: [key], keyDir, signer: (signing) => helperSigner(helper, signing), inspect: codesignStub([]) })
    } finally { errSpy.mockRestore() }
    const version = await cliVersion()
    const written = JSON.parse(await readFile(join(out, `v${version}`, "manifest.json"), "utf8")) as unknown
    expect(await verifyManifestSignatures(written, [key])).toMatchObject({ ok: true, keyId: "rk-test-main" })
    expect(await readFile(join(out, "latest.json"), "utf8")).toBe(await readFile(join(out, `v${version}`, "manifest.json"), "utf8"))
  })
})

// The release-time key commit (handover to R0): every compiled key must
// agree with its sidecar on the release Mac. Skipped while RELEASE_KEYS is
// empty, so it reads nothing until the key commit lands.
test.skipIf(RELEASE_KEYS.length === 0)("every compiled release key agrees with its sidecar on this machine", async () => {
  const { stat } = await import("node:fs/promises")
  const { readSigningKey, releaseKeyDir } = await import("./keys.ts")
  const { trustedEntry } = await import("./sign.ts")
  const dir = releaseKeyDir(process.env)
  for (const key of RELEASE_KEYS) {
    if (!(await stat(join(dir, `${key.id}.json`)).then(() => true, () => false))) continue
    expect(trustedEntry((await readSigningKey(dir, key.id)).key, RELEASE_KEYS)).toEqual(key)
  }
})

describe("--release", () => {
  test("is always signed and needs a clean tree", () => {
    expect(parseReleaseArgs(["--out", out, "--release"])).toMatchObject({ release: true, unsigned: false, allowDirty: false })
    expect(() => parseReleaseArgs(["--out", out, "--release", "--unsigned", "--partial"])).toThrow("--release is always signed")
    expect(() => parseReleaseArgs(["--out", out, "--release", "--allow-dirty"])).toThrow("--release needs a clean tree")
  })

  test.skipIf(process.platform !== "darwin")("refuses to build while the compiled set is empty", async () => {
    const { main } = await import("./release.ts")
    let built = false
    await expect(main(["--out", out, "--release"], async () => { built = true }, dist, { treeClean: () => true, trusted: [] })).rejects.toThrow("RELEASE_KEYS in packages/protocol/src/release-keys.ts is empty")
    expect(built).toBe(false)
    expect(await readdir(out).catch(() => [])).toEqual([])
  })
})

describe("the built-binary checks", () => {
  test("checkHostBinary needs exactly { version, commit, build, helper } as built", async () => {
    const { checkHostBinary, hostTarget } = await import("./release.ts")
    const expected = { version: "0.3.0", commit: "a53a3de", build: "release" as const, helper: "embedded" as const }
    const answer = (stdout: string) => async (cmd: string[]) => { expect(cmd).toEqual([join(dist, `mehen-${hostTarget()}`), "version", "--json"]); return { code: 0, stdout, stderr: "" } }
    await checkHostBinary(expected, dist, answer(JSON.stringify(expected)))
    await checkHostBinary(expected, dist, answer(JSON.stringify({ helper: "embedded", build: "release", commit: "a53a3de", version: "0.3.0" })))
    for (const printed of [{ ...expected, build: "dev" }, { ...expected, build: null }, { ...expected, helper: "none" }, { version: "0.3.0", commit: "a53a3de" }, { ...expected, extra: 1 }]) {
      await expect(checkHostBinary(expected, dist, answer(JSON.stringify(printed)))).rejects.toThrow("version --json printed")
    }
    await expect(checkHostBinary(expected, dist, answer("not json"))).rejects.toThrow("version --json printed not json")
    // Matching JSON is not enough: the command must also succeed.
    const failing = async () => ({ code: 17, stdout: JSON.stringify(expected), stderr: "failed\nmore" })
    await expect(checkHostBinary(expected, dist, failing)).rejects.toThrow("version --json exited 17: failed")
  })

  test("every darwin binary must pass codesign --verify", async () => {
    const { checkDarwinBinaries } = await import("./release.ts")
    const calls: string[][] = []
    await expect(checkDarwinBinaries(dist, ["darwin-x64", "linux-x64"], codesignStub(calls, () => 1))).rejects.toThrow(`codesign --verify refused ${join(dist, "mehen-darwin-x64")}`)
    calls.length = 0
    await checkDarwinBinaries(dist, ["linux-x64", "linux-arm64"], codesignStub(calls, () => 1))
    expect(calls).toEqual([])
  })

  test.skipIf(process.platform !== "darwin" || process.arch !== "arm64")("the host's darwin binary must extract a signed helper that runs and is dist/mehen-se", async () => {
    const { checkDarwinBinaries } = await import("./release.ts")
    await fakeDarwinBuild("a53a3de", "release")
    const calls: string[][] = []
    await checkDarwinBinaries(dist, ["darwin-arm64", "darwin-x64"], codesignStub(calls))
    const extracted = calls.find((c) => c[1] === "version")!
    expect(extracted.slice(0, 3)).toEqual([join(dist, "mehen-darwin-arm64"), "version", "--extract-helper"])
    const helperPath = join(extracted[3]!, "mehen-se")
    expect(calls.map((c) => c[0] === "codesign" ? `codesign ${c.at(-1)}` : c.slice(1).join(" "))).toEqual([
      `codesign ${join(dist, "mehen-darwin-arm64")}`,
      `codesign ${join(dist, "mehen-darwin-x64")}`,
      `version --extract-helper ${extracted[3]}`,
      `codesign ${helperPath}`,
      "available",
    ])
    // The extracted helper fails codesign, does not run, or is not the shipped helper: refused.
    await expect(checkDarwinBinaries(dist, ["darwin-arm64"], codesignStub([], (cmd) => cmd.at(-1)!.endsWith("/mehen-se") ? 1 : 0))).rejects.toThrow("fails codesign --verify")
    const { chmod } = await import("node:fs/promises")
    await writeFile(join(dist, "mehen-se"), "#!/bin/sh\nexit 1\n")
    await chmod(join(dist, "mehen-se"), 0o755)
    await expect(checkDarwinBinaries(dist, ["darwin-arm64"], codesignStub([]))).rejects.toThrow("does not run on this Mac")
    // A binary whose embedded helper is not the helper the release ships.
    await writeFile(join(dist, "mehen-darwin-arm64"), `#!/bin/sh\nmkdir -p "$3" && printf '#!/bin/sh\\nexit 0\\n' > "$3/mehen-se" && chmod 755 "$3/mehen-se" && printf '%s\\n' "$3/mehen-se"\n`)
    await expect(checkDarwinBinaries(dist, ["darwin-arm64"], codesignStub([]))).rejects.toThrow("is not dist/mehen-se")
    await writeFile(join(dist, "mehen-darwin-arm64"), "#!/bin/sh\necho 'no embedded helper' >&2\nexit 2\n")
    await expect(checkDarwinBinaries(dist, ["darwin-arm64"], codesignStub([]))).rejects.toThrow("did not extract its helper: no embedded helper")
  })

  test.skipIf(process.platform !== "darwin" || process.arch !== "arm64")("main --release passes --release to the build, expects build release and signs", async () => {
    const { spyOn } = await import("bun:test")
    const { main } = await import("./release.ts")
    const { createReleaseKey } = await import("./keys.ts")
    const { helperSigner } = await import("./sign.ts")
    const { verifyManifestSignatures } = await import("../../packages/protocol/src/release-manifest.ts")
    await mkdir(join(root, "se"), { recursive: true })
    const { chmod } = await import("node:fs/promises")
    const helper = join(root, "se", "mehen-se")
    await writeFile(helper, FAKE_SE)
    await chmod(helper, 0o755)
    const keyDir = join(root, "mehen-release")
    const key = await createReleaseKey({ id: "rk-test-release-build", presence: "none", dir: keyDir, helper })
    const calls: string[][] = []
    let buildCmd: string[] = []
    const errSpy = spyOn(process.stderr, "write").mockImplementation(() => true)
    // --release needs a clean tree; this checkout may have uncommitted work, so the test stands in for that check.
    try {
      await main(["--out", out, "--target", "darwin-arm64", "--release", "--partial"], async (cmd) => {
        buildCmd = cmd
        await fakeDarwinBuild(cmd[cmd.indexOf("--commit") + 1]!, "release")
      }, dist, { trusted: [key], keyDir, signer: (signing) => helperSigner(helper, signing), inspect: codesignStub(calls), treeClean: () => true })
    } finally { errSpy.mockRestore() }
    expect(buildCmd).toContain("--release")
    expect(calls.some((c) => c[1] === "version" && c[2] === "--json")).toBe(true)
    const written = JSON.parse(await readFile(join(out, `v${await cliVersion()}`, "manifest.json"), "utf8")) as unknown
    expect(await verifyManifestSignatures(written, [key])).toMatchObject({ ok: true, keyId: "rk-test-release-build" })
  })
})

describe("public upload scripts need --release", () => {
  const forms = (): string[][] => [["--upload"], ["--upload-script", join(root, "upload.sh")], ["--upload", "--upload-script", join(root, "upload.sh")]]

  test("every upload form without --release is refused: signed dev, signed trial, unsigned trial, partial", () => {
    const builds: string[][] = [
      [],
      ["--key", "rk-test"],
      ["--allow-dirty"],
      ["--allow-dirty", "--unsigned"],
      ["--target", "darwin-arm64", "--partial"],
      ["--target", "darwin-arm64", "--partial", "--unsigned"],
      ["--target", "darwin-arm64", "--partial", "--allow-dirty", "--unsigned"],
    ]
    for (const form of forms()) {
      for (const build of builds) expect(() => parseReleaseArgs(["--out", out, ...build, ...form])).toThrow("--upload and --upload-script write commands that publish to the release bucket, so they need --release")
    }
  })

  test("with --release every upload form is accepted, and the trial escapes stay refused by --release itself", () => {
    for (const form of forms()) {
      expect(parseReleaseArgs(["--out", out, "--release", ...form])).toMatchObject({ release: true, unsigned: false })
      expect(parseReleaseArgs(["--out", out, "--release", "--target", "darwin-arm64", "--partial", ...form])).toMatchObject({ release: true, partial: true })
      expect(() => parseReleaseArgs(["--out", out, "--release", "--allow-dirty", ...form])).toThrow("--release needs a clean tree")
      expect(() => parseReleaseArgs(["--out", out, "--release", "--target", "darwin-arm64", "--partial", "--unsigned", ...form])).toThrow("--release is always signed")
    }
  })

  test("a trial without upload flags still assembles locally", () => {
    expect(parseReleaseArgs(["--out", out, "--allow-dirty", "--unsigned"])).toMatchObject({ release: false, upload: false, uploadScript: undefined })
    expect(parseReleaseArgs(["--out", out, "--target", "darwin-arm64", "--partial", "--unsigned"])).toMatchObject({ release: false, partial: true })
  })

  test.skipIf(process.platform !== "darwin")("a refused upload starts no build and writes nothing", async () => {
    const { main } = await import("./release.ts")
    for (const form of forms()) {
      let built = false
      await expect(main(["--out", out, "--allow-dirty", "--unsigned", ...form], async () => { built = true }, dist, { treeClean: () => true })).rejects.toThrow("need --release")
      expect(built).toBe(false)
    }
    expect(await readdir(out).catch(() => [])).toEqual([])
    expect(await readdir(root)).not.toContain("upload.sh")
  })
})
