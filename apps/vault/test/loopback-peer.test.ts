// Whether a request came from this machine: only a local vault's own peer
// address, which apps/local writes into cf-connecting-ip, is loopback.
import { describe, expect, it } from "vitest"
import { loopbackPeer, onThisMachine } from "../src/directory/session.ts"

const from = (ip: string | null) => new Request("https://vault.test/", ip === null ? {} : { headers: { "cf-connecting-ip": ip } })

describe("loopbackPeer", () => {
  it("is true for this machine's addresses only", () => {
    for (const ip of ["127.0.0.1", "127.8.0.1", "::1", "::ffff:127.0.0.1"]) expect(loopbackPeer(from(ip)), ip).toBe(true)
    for (const ip of [null, "", "local", "10.0.0.1", "192.168.1.2", "2001:db8::1", "::ffff:10.0.0.1", "127.0.0.1, 10.0.0.1", "1127.0.0.1"]) expect(loopbackPeer(from(ip)), String(ip)).toBe(false)
  })

  it("is this machine only when the vault itself answers on a loopback origin, not merely when a proxy in front of it is the peer", () => {
    for (const origin of ["http://localhost:7787", "http://127.0.0.1:7787", "http://[::1]:7787"]) expect(onThisMachine(from("127.0.0.1"), origin), origin).toBe(true)
    for (const origin of ["https://mehen.example.ts.net", "https://vault.example.com", "https://localhost:7787", "http://vault.lan:7787"]) expect(onThisMachine(from("127.0.0.1"), origin), origin).toBe(false)
    expect(onThisMachine(from("10.0.0.5"), "http://localhost:7787")).toBe(false)
    expect(onThisMachine(from("127.0.0.1"), "not a url")).toBe(false)
  })
})
