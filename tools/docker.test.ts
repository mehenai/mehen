// Invariants of the self-hosting Dockerfile, compose.yaml and the workflow
// that publishes the image: unprivileged runtime, 0700 data folder,
// Host-matched healthcheck, loopback host binding, required https origin, and
// a publish that never runs for a pull request and pins what it runs.

import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dir, "..")

describe("Docker self-hosting files", () => {
  test("Dockerfile builds linux targets, runs as non-root with 0700 /data/vault and checks /healthz with the origin Host", () => {
    const text = readFileSync(join(ROOT, "Dockerfile"), "utf8")
    expect(text).toContain("FROM --platform=$BUILDPLATFORM oven/bun:1.4.2-debian AS builder")
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
    expect(text).toContain("image: ghcr.io/mehenai/mehen:latest\n    build:\n      context: .\n      dockerfile: Dockerfile\n")
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

  test("the image workflow publishes on releases and tags only, with job-scoped write permissions and pinned actions", () => {
    const text = readFileSync(join(ROOT, ".github", "workflows", "image.yml"), "utf8")
    expect(text).not.toContain("pull_request")
    expect(text).toContain("on:\n  release:\n    types: [published]\n  push:\n    tags: [\"v*\"]\n  workflow_dispatch:\n")
    expect(text).toContain("permissions:\n  contents: read\n")
    expect(text).toContain("    permissions:\n      contents: read\n      packages: write\n      id-token: write\n      attestations: write\n")
    expect(text).toContain("platforms: linux/amd64,linux/arm64")
    expect(text).toContain("provenance: mode=max")
    expect(text).toContain("sbom: true")
    expect(text).toContain("persist-credentials: false")
    for (const label of ["source", "licenses", "version", "revision"]) expect(text).toContain(`org.opencontainers.image.${label}=`)
    const uses = [...text.matchAll(/uses: (\S+)(.*)/g)]
    expect(uses.length).toBeGreaterThan(1)
    for (const [, action, rest] of uses) {
      if (action!.startsWith("actions/checkout@")) continue
      expect(action).toMatch(/@[0-9a-f]{40}$/)
      expect(rest).toMatch(/^ # v\d+\.\d+\.\d+$/)
    }
  })
})
