import { describe, expect, test } from "bun:test"
import "./reflect-shim.ts"
import { writeFileSync } from "node:fs"
import { join } from "node:path"
import tls from "node:tls"
import type * as X509 from "@peculiar/x509"
import { removeDir, tempDir, withTimeout } from "../run/fake-vault-api.ts"
import { NAME_CONSTRAINTS_OID, createRunCa, nameConstraintsDer } from "./ca.ts"

const x509: typeof X509 = await import("@peculiar/x509")

function hex(bytes: ArrayBuffer | Uint8Array): string {
  return Buffer.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)).toString("hex")
}

async function handshake(leaf: { certPem: string; keyPem: string }, servername: string, caPem: string): Promise<string> {
  const server = tls.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (socket) => socket.end())
  try {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
    const address = server.address()
    if (address === null || typeof address === "string") throw new Error("no port")
    return await withTimeout(
      new Promise<string>((resolve) => {
        const socket = tls.connect({ host: "127.0.0.1", port: address.port, servername, ca: [caPem] }, () => {
          resolve(socket.authorized ? "trusted" : "untrusted")
          socket.destroy()
        })
        socket.on("error", (error) => resolve(`refused: ${error.message}`))
      }),
      5000,
      "TLS handshake",
    )
  } finally {
    server.close()
  }
}

type Tlv = { tag: number; raw: Uint8Array; content: Uint8Array }

function readTlvs(bytes: Uint8Array): Tlv[] {
  const out: Tlv[] = []
  for (let at = 0; at < bytes.length; ) {
    const tag = bytes[at] ?? 0
    let length = bytes[at + 1] ?? 0
    let header = 2
    if (length & 0x80) {
      const count = length & 0x7f
      length = 0
      for (let i = 0; i < count; i++) length = length * 256 + (bytes[at + 2 + i] ?? 0)
      header += count
    }
    out.push({ tag, raw: bytes.subarray(at, at + header + length), content: bytes.subarray(at + header, at + header + length) })
    at += header + length
  }
  return out
}

// The CA's NameConstraints, read back from the certificate: each subtree's
// base as @peculiar/x509 renders it ("dns" ".example.com", "ip" "0.0.0.0/0").
function constraintsOf(caPem: string): { permitted: X509.JsonGeneralName[]; excluded: X509.JsonGeneralName[] } {
  const extension = new x509.X509Certificate(caPem).getExtension(NAME_CONSTRAINTS_OID)
  if (extension === null) throw new Error("no name constraints")
  expect(extension.critical).toBe(true)
  const [sequence] = readTlvs(new Uint8Array(extension.value))
  const parts = readTlvs(sequence?.content ?? new Uint8Array())
  const subtrees = (tag: number) =>
    readTlvs(parts.find((part) => part.tag === tag)?.content ?? new Uint8Array()).map((subtree) => {
      const [base, ...rest] = readTlvs(subtree.content)
      expect(rest).toEqual([])
      return new x509.GeneralName(new Uint8Array(base?.raw ?? [])).toJSON()
    })
  expect(parts.every((part) => part.tag === 0xa0 || part.tag === 0xa1)).toBe(true)
  return { permitted: subtrees(0xa0), excluded: subtrees(0xa1) }
}

const OPENSSL = Bun.which("openssl")

// openssl verify of a leaf against the run CA alone: "OK" or its error line.
async function opensslVerify(ca: Awaited<ReturnType<typeof createRunCa>>, host: string): Promise<string> {
  const dir = tempDir("mehen-ca-test-")
  try {
    writeFileSync(join(dir, "ca.pem"), ca.certPem)
    writeFileSync(join(dir, "leaf.pem"), (await ca.issueLeaf(host)).certPem)
    const result = Bun.spawnSync([OPENSSL as string, "verify", "-CAfile", join(dir, "ca.pem"), join(dir, "leaf.pem")], { stdout: "pipe", stderr: "pipe" })
    const text = `${result.stdout.toString()}${result.stderr.toString()}`
    return result.exitCode === 0 && text.includes(": OK") ? "OK" : text
  } finally {
    removeDir(dir)
  }
}

describe("run CA name constraints close every other name type", () => {
  test("with DNS hosts only, every IPv4 and IPv6 address is excluded", async () => {
    const ca = await createRunCa(["api.openai.com", "*.example.com"])
    expect(constraintsOf(ca.certPem)).toEqual({
      permitted: [
        { type: "dns", value: "api.openai.com" },
        { type: "dns", value: ".example.com" },
      ],
      excluded: [
        { type: "ip", value: "0.0.0.0/0" },
        { type: "ip", value: "::/0" },
      ],
    })
  })

  test("with IP hosts only, the only DNS name permitted is .invalid, and the missing address family is excluded", async () => {
    const ca = await createRunCa(["10.1.2.3"])
    expect(constraintsOf(ca.certPem)).toEqual({
      permitted: [
        { type: "ip", value: "10.1.2.3/32" },
        { type: "dns", value: ".invalid" },
      ],
      excluded: [{ type: "ip", value: "::/0" }],
    })
  })

  test("with DNS, IPv4 and IPv6 hosts, each type is permitted exactly and nothing more is needed", async () => {
    const ca = await createRunCa(["api.mehen.test", "10.1.2.3", "[2001:db8::1]"])
    const { permitted, excluded } = constraintsOf(ca.certPem)
    expect(permitted.map((name) => name.type)).toEqual(["dns", "ip", "ip"])
    expect(permitted[0]?.value).toBe("api.mehen.test")
    expect(permitted[1]?.value).toBe("10.1.2.3/32")
    expect(excluded).toEqual([])
  })

  test.skipIf(OPENSSL === null)("openssl refuses a leaf for an IP address from a DNS-only run CA, and for a host name from an IP-only one", async () => {
    const dnsCa = await createRunCa(["good.mehen.test"])
    expect(await opensslVerify(dnsCa, "good.mehen.test")).toBe("OK")
    for (const address of ["10.9.9.9", "127.0.0.1", "2001:db8::9"]) expect(await opensslVerify(dnsCa, address)).toContain("excluded subtree violation")

    const ipCa = await createRunCa(["10.1.2.3"])
    expect(await opensslVerify(ipCa, "10.1.2.3")).toBe("OK")
    expect(await opensslVerify(ipCa, "10.1.2.4")).toContain("permitted subtree violation")
    expect(await opensslVerify(ipCa, "bank.example")).toContain("permitted subtree violation")
    // OpenSSL reports the permitted check first; ::/0 is excluded as well.
    expect(await opensslVerify(ipCa, "2001:db8::9")).toContain("subtree violation")
  })
})

describe("run CA", () => {
  test("carries critical name constraints for exactly the intercept hosts", async () => {
    const hosts = ["api.openai.com", "*.example.com", "10.1.2.3"]
    const ca = await createRunCa(hosts)
    const cert = new x509.X509Certificate(ca.certPem)
    const extension = cert.getExtension(NAME_CONSTRAINTS_OID)
    expect(extension).not.toBeNull()
    expect(extension?.critical).toBe(true)
    expect(hex(extension?.value ?? new Uint8Array())).toBe(hex(nameConstraintsDer(hosts)))
    const der = Buffer.from(nameConstraintsDer(hosts))
    expect(der.includes(Buffer.from("api.openai.com"))).toBe(true)
    // "*.example.com" is constrained as ".example.com": names below it, not the apex.
    expect(der.includes(Buffer.from([0x82, 12, ...Buffer.from(".example.com")]))).toBe(true)
    expect(der.includes(Buffer.from([0x87, 8, 10, 1, 2, 3, 255, 255, 255, 255]))).toBe(true)
    expect(await cert.isSelfSigned()).toBe(true)
    const algorithm = cert.publicKey.algorithm as EcKeyAlgorithm
    expect(algorithm.namedCurve).toBe("P-256")
  })

  test("a leaf for an intercept host is trusted", async () => {
    const ca = await createRunCa(["good.mehen.test"])
    expect(await handshake(await ca.issueLeaf("good.mehen.test"), "good.mehen.test", ca.certPem)).toBe("trusted")
  })

  test("a leaf the CA signs for any other host is refused by the client", async () => {
    const ca = await createRunCa(["good.mehen.test"])
    const verdict = await handshake(await ca.issueLeaf("bank.example"), "bank.example", ca.certPem)
    expect(verdict).toStartWith("refused")
    expect(verdict).toContain("subtree")
  })

  test("needs at least one host", async () => {
    await expect(createRunCa([])).rejects.toThrow(/at least one/)
  })
})
