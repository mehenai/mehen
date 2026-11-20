// Invariants of the self-hosting Dockerfile and compose.yaml: unprivileged
// runtime, 0700 data folder, Host-matched healthcheck, loopback host binding
// and required https origin.

import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dir, "..")

describe("Docker self-hosting files", () => {
  test("Dockerfile builds linux targets, runs as non-root with 0700 /data/vault and checks /healthz with the origin Host", () => {
    const text = readFileSync(join(ROOT, "Dockerfile"), "utf8")
    expect(text).toContain("FROM oven/bun:1.4.2-debian AS builder")
    expect(text).toContain("FROM debian:bookworm-slim AS runtime")
    expect(text).toContain("ca-certificates")
    expect(text).toContain("install -d -m 0700 -o mehen -g mehen /data /data/vault")
    expect(text).toContain("USER mehen")
    expect(text).toContain("MEHEN_SERVE_DATA=/data/vault")
    expect(text).toContain('ENTRYPOINT ["/usr/local/bin/mehen"]')
    expect(text).toContain('CMD ["serve"]')
    expect(text).toContain("HEALTHCHECK")
    expect(text).toContain("Host:")
    expect(text).toContain("/healthz")
  })

  test("compose.yaml requires MEHEN_SERVE_ORIGIN, hardens the vault container and offers an optional Caddy TLS profile", () => {
    const text = readFileSync(join(ROOT, "compose.yaml"), "utf8")
    expect(text).toContain("MEHEN_SERVE_ORIGIN: ${MEHEN_SERVE_ORIGIN:?")
    expect(text).toContain('"127.0.0.1:7787:7787"')
    expect(text).toContain("read_only: true")
    expect(text).toContain("no-new-privileges:true")
    expect(text).toContain("cap_drop:")
    expect(text).toContain("- ALL")
    expect(text).toContain("caddy:")
    expect(text).toContain("- caddy")
    expect(text).toContain("condition: service_healthy")
  })
})
