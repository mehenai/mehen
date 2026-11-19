// A stand-in for native/mehen-se with the same command line (available, create
// --out, sign --key --no-interaction), so the enclave code paths run on any
// machine. The "enclave" is a P-256 private JWK in the blob file; the real
// helper's blob is opaque to everything but the Secure Enclave. Tests only.
//
// `fakeHelper(dir)` writes an executable wrapper that runs this file with
// the test's own bun, and returns its path for MEHEN_SE_PATH. With
// `{ unreachable: true }` it answers as the real helper does inside a
// sandbox that blocks the enclave: `available` exits 1, and create and
// sign print "mehen-se: Secure Enclave is not available".

import { chmod } from "node:fs/promises"
import { join } from "node:path"

export async function fakeHelper(dir: string, options: { unreachable?: boolean } = {}): Promise<string> {
  const path = join(dir, "mehen-se")
  await Bun.write(path, `#!/bin/sh\n${options.unreachable ? "FAKE_MEHEN_SE_UNREACHABLE=1 " : ""}exec ${JSON.stringify(process.execPath)} ${JSON.stringify(import.meta.path)} "$@"\n`)
  await chmod(path, 0o755)
  return path
}

type PrivateJwk = { kty: "EC"; crv: "P-256"; x: string; y: string; d: string }

function base64Url(bytes: ArrayBuffer): string {
  return Buffer.from(bytes).toString("base64url")
}

async function create(out: string): Promise<number> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  const exported = await crypto.subtle.exportKey("jwk", pair.privateKey)
  const file: PrivateJwk = { kty: "EC", crv: "P-256", x: exported.x as string, y: exported.y as string, d: exported.d as string }
  await Bun.write(out, `${JSON.stringify(file)}\n`)
  await chmod(out, 0o600)
  process.stdout.write(`${JSON.stringify({ kty: "EC", crv: "P-256", x: file.x, y: file.y })}\n`)
  return 0
}

async function sign(keyPath: string): Promise<number> {
  const file = JSON.parse(await Bun.file(keyPath).text()) as PrivateJwk
  const key = await crypto.subtle.importKey("jwk", { ...file, ext: false }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"])
  const data = new Uint8Array(await new Response(Bun.stdin.stream()).arrayBuffer())
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data)
  process.stdout.write(`${base64Url(signature)}\n`)
  return 0
}

if (import.meta.main) {
  const [command, ...rest] = process.argv.slice(2)
  const option = (name: string): string | undefined => {
    const at = rest.indexOf(name)
    return at === -1 ? undefined : rest[at + 1]
  }
  let code = 2
  if (process.env.FAKE_MEHEN_SE_UNREACHABLE === "1") {
    if (command !== "available") process.stderr.write("mehen-se: Secure Enclave is not available\n")
    code = 1
  } else if (command === "available") code = 0
  else if (command === "create" && option("--out")) code = await create(option("--out") as string)
  else if (command === "sign" && option("--key")) code = await sign(option("--key") as string)
  else process.stderr.write("fake mehen-se: usage: available | create --out <path> | sign --key <path> --no-interaction\n")
  process.exit(code)
}
