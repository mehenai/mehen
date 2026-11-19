// The per-run certificate authority for the local relay. ECDSA P-256 through
// WebCrypto, so no openssl binary is needed. The CA key is generated
// non-extractable and lives only in this process. The CA carries a critical
// X.509 name constraints extension that permits exactly the run's intercept
// hosts, so even a stolen run CA cannot impersonate any other site. A
// constraint of one name type leaves the others open (RFC 5280 4.2.1.10),
// so with no DNS hosts only ".invalid" is permitted, and an address family
// with no intercept host is excluded whole.

import "./reflect-shim.ts"
import type * as X509 from "@peculiar/x509"
import { isIP } from "node:net"

// Loaded after the shim: Bun evaluates a statically imported CommonJS module
// before the modules imported ahead of it.
const x509: typeof X509 = await import("@peculiar/x509")

x509.cryptoProvider.set(crypto)

const EC_KEY: EcKeyGenParams = { name: "ECDSA", namedCurve: "P-256" }
const EC_SIGNING: EcdsaParams = { name: "ECDSA", hash: "SHA-256" }
const VALIDITY_MS = 30 * 24 * 60 * 60 * 1000
const BACKDATE_MS = 60 * 60 * 1000

export const NAME_CONSTRAINTS_OID = "2.5.29.30"

export type LeafCertificate = { certPem: string; keyPem: string }

export type RunCa = {
  certPem: string
  permittedHosts: readonly string[]
  // Cached per host for the life of the run.
  issueLeaf(host: string): Promise<LeafCertificate>
}

function derLength(length: number): number[] {
  if (length < 0x80) return [length]
  const bytes: number[] = []
  for (let n = length; n > 0; n = Math.floor(n / 256)) bytes.unshift(n % 256)
  return [0x80 | bytes.length, ...bytes]
}

function tlv(tag: number, content: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array([tag, ...derLength(content.length), ...content])
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0))
  let at = 0
  for (const part of parts) {
    out.set(part, at)
    at += part.length
  }
  return out
}

function ipv6Bytes(address: string): number[] {
  const [head = "", tail] = address.split("::")
  const groups = (part: string) => (part === "" ? [] : part.split(":"))
  const left = groups(head)
  const right = tail === undefined ? [] : groups(tail)
  const fill = tail === undefined ? [] : Array<string>(8 - left.length - right.length).fill("0")
  return [...left, ...fill, ...right].flatMap((group) => {
    const value = Number.parseInt(group, 16)
    return [value >> 8, value & 0xff]
  })
}

// GeneralName for a permitted subtree: dNSName [2] or iPAddress [7] (an
// address followed by its mask). "*.example.com" becomes ".example.com",
// which permits names below example.com and not the apex.
function generalName(pattern: string): Uint8Array {
  const host = pattern.toLowerCase().replace(/^\[|\]$/g, "")
  const family = isIP(host)
  if (family === 4) {
    const address = host.split(".").map(Number)
    return tlv(0x87, new Uint8Array([...address, 255, 255, 255, 255]))
  }
  if (family === 6) return tlv(0x87, new Uint8Array([...ipv6Bytes(host), ...Array<number>(16).fill(255)]))
  const name = host.startsWith("*.") ? host.slice(1) : host
  return tlv(0x82, new TextEncoder().encode(name))
}

const NO_DNS_NAME = ".invalid"
const ALL_IPV4 = tlv(0x87, new Uint8Array(8))
const ALL_IPV6 = tlv(0x87, new Uint8Array(32))

// NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees,
//   excludedSubtrees [1] GeneralSubtrees }
export function nameConstraintsDer(hosts: readonly string[]): Uint8Array<ArrayBuffer> {
  const family = (host: string) => isIP(host.toLowerCase().replace(/^\[|\]$/g, ""))
  const permitted = hosts.map(generalName)
  if (!hosts.some((host) => family(host) === 0)) permitted.push(generalName(NO_DNS_NAME))
  const excluded: Uint8Array[] = []
  if (!hosts.some((host) => family(host) === 4)) excluded.push(ALL_IPV4)
  if (!hosts.some((host) => family(host) === 6)) excluded.push(ALL_IPV6)
  const subtrees = (names: Uint8Array[]) => concat(names.map((name) => tlv(0x30, name)))
  return tlv(0x30, concat([tlv(0xa0, subtrees(permitted)), ...(excluded.length > 0 ? [tlv(0xa1, subtrees(excluded))] : [])]))
}

function randomSerial(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  bytes[0] = (bytes[0] ?? 0) & 0x7f
  return Buffer.from(bytes).toString("hex")
}

function leafName(host: string): X509.JsonGeneralName {
  return isIP(host) ? { type: "ip", value: host } : { type: "dns", value: host }
}

export async function createRunCa(permittedHosts: readonly string[]): Promise<RunCa> {
  if (permittedHosts.length === 0) throw new Error("a run CA needs at least one intercept host")
  const now = Date.now()
  const caKeys = await crypto.subtle.generateKey(EC_KEY, false, ["sign", "verify"])
  const caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomSerial(),
    name: `CN=mehen run CA ${new Date(now).toISOString()}, O=Mehen local relay`,
    notBefore: new Date(now - BACKDATE_MS),
    notAfter: new Date(now + VALIDITY_MS),
    keys: caKeys,
    signingAlgorithm: EC_SIGNING,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
      new x509.Extension(NAME_CONSTRAINTS_OID, true, nameConstraintsDer(permittedHosts)),
    ],
  })

  // One leaf key pair for every leaf of this run saves a key generation per host.
  const leafKeys = await crypto.subtle.generateKey(EC_KEY, true, ["sign", "verify"])
  const leafKeyPem = x509.PemConverter.encode(await crypto.subtle.exportKey("pkcs8", leafKeys.privateKey), "PRIVATE KEY")
  const authorityKeyId = await x509.AuthorityKeyIdentifierExtension.create(caCert, false)
  const leaves = new Map<string, Promise<LeafCertificate>>()

  async function mintLeaf(host: string): Promise<LeafCertificate> {
    const name = leafName(host)
    const leaf = await x509.X509CertificateGenerator.create({
      serialNumber: randomSerial(),
      // OpenSSL checks a hostname-like CN against DNS constraints, so IP leaves carry no CN.
      subject: name.type === "dns" ? `CN=${host}` : "O=mehen relay leaf",
      issuer: caCert.subject,
      notBefore: new Date(now - BACKDATE_MS),
      notAfter: new Date(now + VALIDITY_MS),
      publicKey: leafKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: EC_SIGNING,
      extensions: [
        new x509.BasicConstraintsExtension(false, undefined, true),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth], false),
        new x509.SubjectAlternativeNameExtension([name], false),
        await x509.SubjectKeyIdentifierExtension.create(leafKeys.publicKey),
        authorityKeyId,
      ],
    })
    return { certPem: leaf.toString("pem"), keyPem: leafKeyPem }
  }

  return {
    certPem: caCert.toString("pem"),
    permittedHosts,
    issueLeaf(host) {
      const key = host.toLowerCase()
      let pending = leaves.get(key)
      if (pending === undefined) {
        pending = mintLeaf(key)
        leaves.set(key, pending)
      }
      return pending
    },
  }
}
