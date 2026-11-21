// Starts the local relay for one run and works out what the child needs to
// use it: the proxy variables, the CA files and the base URLs.

import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { VaultApi } from "../vault-api.ts"
import { createRunCa } from "./ca.ts"
import { type BaseUrlRoute, type ItemRoute, type RelaySeen, startLocalRelay } from "./relay.ts"
import { loadSystemRoots } from "./system-roots.ts"

export type RunRelayOptions = {
  api: VaultApi
  // Null for an ad hoc run (mehen run --item with no project).
  run: string | null
  env: string
  interceptHosts: readonly string[]
  fencedHosts: readonly string[]
  baseUrls: readonly BaseUrlRoute[]
  // Ad hoc items, each relayed as vault_fetch relays it.
  itemRoutes?: readonly ItemRoute[]
  // True when the run has placeholders or ad hoc items: the child is then pointed at the proxy.
  proxy: boolean
  parentEnv: Record<string, string | undefined>
  // mehen run --stream-writes: pass every write's answer on as it comes.
  streamWrites?: boolean
}

export type RunRelay = {
  port: number
  // Variables to add to the child's environment.
  env: Record<string, string>
  // The local base URL that replaces each base-url item's upstream.
  baseUrls: Map<string, string>
  // What reached the relay so far: mehen run warns when a run with
  // placeholders ends with no connection to any intercept host.
  seen(): RelaySeen
  close(): Promise<void>
}

export async function startRunRelay(options: RunRelayOptions): Promise<RunRelay> {
  const itemRoutes = options.itemRoutes ?? []
  // The CA permits only the hosts the vault returned: the run's own and each ad hoc item's.
  const caHosts = options.proxy ? [...new Set([...options.interceptHosts, ...itemRoutes.flatMap((route) => route.hosts)])] : []
  const ca = caHosts.length > 0 ? await createRunCa(caHosts) : null
  const relay = await startLocalRelay({
    api: options.api,
    run: options.run,
    env: options.env,
    interceptHosts: options.interceptHosts,
    fencedHosts: options.fencedHosts,
    baseUrls: options.baseUrls,
    ca,
    ...(itemRoutes.length > 0 ? { itemRoutes } : {}),
    ...(options.streamWrites ? { streamWrites: true } : {}),
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
        // The AWS CLI and SDKs and Deno each read only their own variable.
        AWS_CA_BUNDLE: bundleFile,
        DENO_CERT: bundleFile,
      })
    }
    const baseUrls = new Map(options.baseUrls.map((route) => [route.item, relay.baseUrl(route.item)]))
    return { port: relay.port, env, baseUrls, seen: () => relay.seen(), close }
  } catch (error) {
    await close()
    throw error
  }
}
