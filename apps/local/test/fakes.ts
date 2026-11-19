// Stand-ins for the custody tools, so the Secure Enclave and keyring paths
// run on any machine. Tests only.
//
// fakeEnclaveHelper: mehen-se's available, wrap and unwrap, with an AES-GCM
// key in the blob file instead of an enclave key. FAKE_ENCLAVE=off makes
// `available` fail, as on a Mac without one; FAKE_ENCLAVE_LOG names a file
// each command is appended to.
//
// fakeSecretTool: secret-tool's store, lookup and clear as libsecret matches
// them: store replaces the item with exactly its attributes, lookup and clear
// take every item holding the attributes given. Items are files in the store
// folder; every argument list is logged so a test can show the secret never
// reached a command line. FAKE_SECRET_TOOL_STORE=fail
// refuses a store; FAKE_SECRET_TOOL_LOOKUP=fail makes lookup fail as a
// broken session bus does, with a message.

import { chmod } from "node:fs/promises"
import { appendFileSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { join } from "node:path"

function wrapper(path: string, role: string): Promise<void> {
  return Bun.write(path, `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(import.meta.path)} ${role} "$@"\n`).then(() => chmod(path, 0o755))
}

export async function fakeEnclaveHelper(dir: string): Promise<string> {
  const path = join(dir, "mehen-se")
  await wrapper(path, "enclave")
  return path
}

export async function fakeSecretTool(dir: string): Promise<string> {
  const path = join(dir, "secret-tool")
  await wrapper(path, "secret-tool")
  return path
}

type Item = { attributes: Record<string, string>; secret: string }

function pairs(list: string[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (let i = 0; i + 1 < list.length; i += 2) out[list[i] as string] = list[i + 1] as string
  return out
}

function items(store: string): { path: string; item: Item }[] {
  return readdirSync(store)
    .filter((name) => name.startsWith("item-"))
    .map((name) => ({ path: join(store, name), item: JSON.parse(readFileSync(join(store, name), "utf8")) as Item }))
}

function matching(store: string, wanted: Record<string, string>): { path: string; item: Item }[] {
  return items(store).filter(({ item }) => Object.entries(wanted).every(([key, value]) => item.attributes[key] === value))
}

// What the fake keyring holds, for a test to inspect: every item, or the
// secrets of those holding the attributes given.
export function keyringItems(store: string): Item[] {
  return items(store).map(({ item }) => item)
}

export function keyringSecrets(store: string, attributes: Record<string, string>): string[] {
  return matching(store, attributes).map(({ item }) => item.secret)
}

async function stdin(): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await new Response(Bun.stdin.stream()).arrayBuffer())
}

function fail(message: string, code = 1): never {
  if (message) process.stderr.write(`${message}\n`)
  process.exit(code)
}

async function keyFrom(path: string, create: boolean): Promise<CryptoKey> {
  const file = Bun.file(path)
  if (!(await file.exists())) {
    if (!create) fail(`mehen-se: cannot read key blob ${path}`)
    await Bun.write(path, crypto.getRandomValues(new Uint8Array(32)))
    await chmod(path, 0o600)
  }
  return crypto.subtle.importKey("raw", await Bun.file(path).bytes(), "AES-GCM", false, ["encrypt", "decrypt"])
}

async function enclave(args: string[]): Promise<void> {
  const [command, flag, key, create] = args
  if (process.env.FAKE_ENCLAVE_LOG) appendFileSync(process.env.FAKE_ENCLAVE_LOG, `${command}\n`)
  if (command === "available") process.exit(process.env.FAKE_ENCLAVE === "off" ? 1 : 0)
  if (flag !== "--key" || !key) fail("mehen-se: usage", 2)
  if (command === "wrap") {
    const aes = await keyFrom(key, create === "--create-if-missing")
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, await stdin()))
    const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url")
    process.stdout.write(`${JSON.stringify({ ct: b64(sealed.subarray(0, -16)), epk: "fake", nonce: b64(nonce), tag: b64(sealed.subarray(-16)), v: 1 })}\n`)
    return
  }
  if (command === "unwrap") {
    const aes = await keyFrom(key, false)
    const envelope = JSON.parse(new TextDecoder().decode(await stdin())) as { ct: string; nonce: string; tag: string }
    const bytes = Buffer.concat([Buffer.from(envelope.ct, "base64url"), Buffer.from(envelope.tag, "base64url")])
    try {
      process.stdout.write(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(envelope.nonce, "base64url") }, aes, bytes)))
    } catch {
      fail("mehen-se: the envelope does not open with this key: it was changed, or sealed to another key")
    }
    return
  }
  fail(`mehen-se: unknown command: ${command}`, 2)
}

async function secretTool(args: string[]): Promise<void> {
  const store = process.env.FAKE_SECRET_TOOL_DIR
  if (!store) fail("secret-tool: FAKE_SECRET_TOOL_DIR is not set", 2)
  appendFileSync(join(store, "args.log"), `${args.join(" ")}\n`)
  const [command, ...rest] = args
  const attributes = pairs(rest.filter((arg) => !arg.startsWith("--label=")))
  if (command === "store") {
    if (process.env.FAKE_SECRET_TOOL_STORE === "fail") fail("secret-tool: cannot create an item in a locked collection")
    const same = items(store).find(({ item }) => JSON.stringify(Object.entries(item.attributes).sort()) === JSON.stringify(Object.entries(attributes).sort()))
    const secret = new TextDecoder().decode(await stdin())
    writeFileSync(same?.path ?? join(store, `item-${crypto.randomUUID()}`), JSON.stringify({ attributes, secret } satisfies Item))
    return
  }
  if (command === "lookup") {
    if (process.env.FAKE_SECRET_TOOL_LOOKUP === "fail") fail("secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY")
    const [first] = matching(store, attributes)
    if (!first) fail("")
    process.stdout.write(first.item.secret)
    return
  }
  if (command === "clear") {
    for (const { path } of matching(store, attributes)) rmSync(path, { force: true })
    return
  }
  fail(`secret-tool: unknown command ${command}`, 2)
}

if (import.meta.main) {
  const [role, ...args] = process.argv.slice(2)
  await (role === "enclave" ? enclave(args) : secretTool(args))
}
