// Starts the local relay for one run and works out what the child needs to
// use it: the proxy variables, the CA files and the base URLs.

import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { VaultApi } from "../vault-api.ts"
import { createRunCa } from "./ca.ts"
import { type BaseUrlRoute, startLocalRelay } from "./relay.ts"
import { loadSystemRoots } from "./system-roots.ts"

export type RunRelayOptions = {
  api: VaultApi
  run: string
  env: string
  interceptHosts: readonly string[]
  fencedHosts: readonly string[]
  baseUrls: readonly BaseUrlRoute[]
  // True when the run has placeholders: the child is then pointed at the proxy.
  proxy: boolean
  parentEnv: Record<string, string | undefined>
}

export type RunRelay = {
  port: number
  // Variables to add to the child's environment.
  env: Record<string, string>
  // The local base URL that replaces each base-url item's upstream.
  baseUrls: Map<string, string>
  close(): Promise<void>
}

export async function startRunRelay(options: RunRelayOptions): Promise<RunRelay> {
  const ca = options.proxy && options.interceptHosts.length > 0 ? await createRunCa(options.interceptHosts) : null
  const relay = await startLocalRelay({
    api: options.api,
    run: options.run,
    env: options.env,
    interceptHosts: options.interceptHosts,
    fencedHosts: options.fencedHosts,
    baseUrls: options.baseUrls,
    ca,
  })
  let dir: string | null = null
  const close = async () => {
    await relay.close()
    if (dir !== null) rmSync(dir, { recursive: true, force: true })
  }
  try {
    const env: Record<string, string> = {}
    if (options.proxy) {
      Object.assign(env, {
        HTTPS_PROXY: relay.proxyUrl,
        HTTP_PROXY: relay.proxyUrl,
        https_proxy: relay.proxyUrl,
        http_proxy: relay.proxyUrl,
        NO_PROXY: "",
        no_proxy: "",
        // Node ignores the proxy variables without this, and would send the placeholder straight upstream.
        NODE_USE_ENV_PROXY: "1",
      })
    }
    if (ca !== null) {
      // mkdtemp makes the directory 0700; the files are 0600 and removed on exit.
      dir = mkdtempSync(join(tmpdir(), "mehen-run-"))
      const caFile = join(dir, "mehen-run-ca.pem")
      const bundleFile = join(dir, "mehen-run-ca-bundle.pem")
      writeFileSync(caFile, ca.certPem, { mode: 0o600 })
      writeFileSync(bundleFile, `${[...loadSystemRoots(options.parentEnv), ca.certPem].join("\n")}\n`, { mode: 0o600 })
      Object.assign(env, {
        NODE_EXTRA_CA_CERTS: caFile,
        SSL_CERT_FILE: bundleFile,
        REQUESTS_CA_BUNDLE: bundleFile,
        CURL_CA_BUNDLE: bundleFile,
        GIT_SSL_CAINFO: bundleFile,
      })
    }
    const baseUrls = new Map(options.baseUrls.map((route) => [route.item, relay.baseUrl(route.item)]))
    return { port: relay.port, env, baseUrls, close }
  } catch (error) {
    await close()
    throw error
  }
}
