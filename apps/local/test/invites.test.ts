// Inviting on a local vault, over real HTTP. It has no Google sign-in and no
// email sending, so it cannot verify an email address: an invitation bound
// to one is refused, with why, and the People page offers a guest by link.
// A second person signs up through that link with a passkey, joins and is
// confirmed by the owner.

import { afterAll, beforeAll, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import type { InviteTerms } from "@mehen/protocol"
import { BOOTSTRAP_FILE, startLocalVault, type LocalVault } from "../src/host.ts"
import { Person } from "./person.ts"

const base = process.env.TMPDIR && process.env.TMPDIR !== "/tmp" ? tmpdir() : join(homedir(), ".cache")
const root = mkdtempSync(join(base, "mehen-local-invites-"))
const dataDir = join(root, "data")
const DAY = 86_400_000
let vault: LocalVault

beforeAll(async () => {
  vault = await startLocalVault({ dataDir, port: 0, hostname: "127.0.0.1", origin: null })
})

afterAll(async () => {
  await vault.stop()
  rmSync(root, { recursive: true, force: true })
})

test("invites by link only, and a second person joins through it and is confirmed", async () => {
  const owner = new Person(vault.origin)
  await owner.signUp((await Bun.file(join(dataDir, BOOTSTRAP_FILE)).text()).trim(), "Owner")
  await owner.createWorkspace("local", "Local")
  const project = await owner.createProject("local", "site")
  const expiresAt = new Date(Date.now() + DAY).toISOString()

  const bound: InviteTerms = { role: "member", email: "colleague@example.test", teams: [], shares: [], expiresAt, onJoin: "confirm" }
  await expect(owner.invite("local", bound)).rejects.toThrow(/400 .*This vault cannot verify an email address.*Invite by link instead/)

  const people = await owner.page("/w/local/people")
  expect(people).toContain('data-region="invite-link-only"')
  expect(people).not.toContain('data-input="invite-email"')
  expect(await owner.page("/w/local/")).toContain("Invite someone by link; you confirm them once they have joined.")

  const link = await owner.invite("local", { role: "guest", email: null, teams: [], shares: [{ project: project.id, level: "edit", protected: false, expiresAt: null }], expiresAt, onJoin: "confirm" })
  expect(link.url).toBe(`${vault.origin}/signup#${link.code}`)
  expect(await new Person(vault.origin).call("/api/auth/invite/peek", { code: link.code })).toMatchObject({ role: "guest", bound: false, emailCode: "off" })

  const guest = new Person(vault.origin)
  await guest.signUp(link.code, "Guest")
  const joined = await guest.join(link.code)
  expect(joined.member).toMatch(/^mem_/)
  expect(joined.state).toBe("pending_confirmation")
  expect(await owner.page("/w/local/people")).toContain(`data-action="member-confirm" data-member="${joined.member}"`)

  expect(await owner.confirm("local", joined.member)).toMatchObject({ member: joined.member, name: "Guest", role: "guest", status: "active" })
  const session = await guest.call<{ memberships: { member: string; status: string }[] }>("/api/account")
  expect(session.memberships.find((m) => m.member === joined.member)?.status).toBe("active")
}, 60_000)
