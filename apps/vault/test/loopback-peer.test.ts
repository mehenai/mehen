// Whether a request came from this machine: only a local vault's own peer
// address, which apps/local writes into cf-connecting-ip, is loopback.
import { describe, expect, it } from "vitest"
import { loopbackPeer } from "../src/directory/session.ts"

const from = (ip: string | null) => new Request("https://vault.test/", ip === null ? {} : { headers: { "cf-connecting-ip": ip } })

describe("loopbackPeer", () => {
  it("is true for this machine's addresses only", () => {
    for (const ip of ["127.0.0.1", "127.8.0.1", "::1", "::ffff:127.0.0.1"]) expect(loopbackPeer(from(ip)), ip).toBe(true)
    for (const ip of [null, "", "local", "10.0.0.1", "192.168.1.2", "2001:db8::1", "::ffff:10.0.0.1", "127.0.0.1, 10.0.0.1", "1127.0.0.1"]) expect(loopbackPeer(from(ip)), String(ip)).toBe(false)
  })
})
