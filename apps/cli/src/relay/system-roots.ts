// The system trust roots, for the bundle handed to clients through
// SSL_CERT_FILE and friends: those variables replace a client's roots rather
// than extend them, so the bundle must hold the system roots plus the run CA.
// Read only: nothing here touches a keychain or trust store.

import { existsSync, readFileSync } from "node:fs"
import tls from "node:tls"

// Well-known OpenSSL-format bundles, first match wins.
const BUNDLE_FILES = [
  "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Arch, Alpine
  "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Fedora, RHEL
  "/etc/pki/tls/certs/ca-bundle.crt", // older RHEL
  "/etc/ssl/ca-bundle.pem", // openSUSE
  "/etc/ssl/cert.pem", // macOS, BSDs
]

const PEM_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g

// The caller's own SSL_CERT_FILE when set (an existing corporate bundle is
// respected), else the distro or macOS bundle, then the OS trust store as
// Node sees it (admin-installed enterprise roots), with the bundled Mozilla
// roots as the last resort.
export function loadSystemRoots(parentEnv: Record<string, string | undefined>): string[] {
  const seen = new Set<string>()
  const pems: string[] = []
  const add = (candidates: readonly string[]) => {
    for (const pem of candidates) {
      const key = pem.replace(/\s/g, "")
      if (seen.has(key)) continue
      seen.add(key)
      pems.push(pem)
    }
  }
  const inherited = parentEnv.SSL_CERT_FILE
  const file = inherited !== undefined && inherited !== "" && existsSync(inherited) ? inherited : BUNDLE_FILES.find((path) => existsSync(path))
  if (file !== undefined) add(readFileSync(file, "utf8").match(PEM_BLOCK) ?? [])
  try {
    add(tls.getCACertificates("system"))
  } catch {
    // Not every runtime exposes the system store; the file bundle stands alone then.
  }
  if (pems.length === 0) add(tls.rootCertificates)
  return pems
}
