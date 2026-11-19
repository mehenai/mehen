// A passkey that syncs through a password manager as a way back in
// (directory/account-recovery-setup.ts), through the real Worker and the
// real @simplewebauthn/server ceremonies, with software passkeys that report
// their backup flags.
import { describe, expect, it } from "vitest"
import { AccountSessionSchema, type InviteTerms } from "@mehen/protocol"
import { currentAccountSession } from "../../src/directory/account-session.ts"
import { issueAccountRecoveryCodes } from "../../src/directory/workspace-recovery.ts"
import { ORIGIN } from "../helpers.ts"
import { body, workJourney, type Person } from "./workspace-journey.ts"
import { assertion, registration, softwarePasskey, type PasskeyBackup } from "./passkeys.ts"

async function syncedJourney() {
  const f = await workJourney()
  // An open guest invitation, and a new account made from it as /signup does.
  const signupFromInvite = async (name: string, backup: PasskeyBackup) => {
    const terms: InviteTerms = { role: "guest", email: null, teams: [], shares: [{ project: f.project.id, level: "edit", protected: false, expiresAt: null }], expiresAt: new Date(Date.now() + 86400000).toISOString() }
    const { code } = await f.invite(f.alex, f.work, terms)
    const passkey = await softwarePasskey()
    const { options } = await body<{ options: { challenge: string } }>(await f.request("/api/auth/signup/options", undefined, { invite: code, name }))
    const response = await f.request("/api/auth/signup/verify", undefined, { invite: code, name, response: await registration(passkey, options.challenge, true, backup) })
    const cookie = response.headers.get("set-cookie")?.split(";")[0] ?? ""
    const created = await body<{ account: string; onboarding: string; recoveryReady: boolean }>(response)
    const person: Person = { account: created.account, cookie, passkey, counter: 0, codes: [] }
    return { person, code, created }
  }
  const recoveryReady = async (person: Person) => !AccountSessionSchema.parse(await body(await f.request("/api/account", person))).recoverySetupRequired
  // What /signup's server render hands its client after a reload.
  const signupBoot = async (person: Person) => {
    const page = await (await f.request("/signup", person, undefined, { accept: "text/html" })).text()
    const raw = /data-boot="([^"]*)"/.exec(page)?.[1] ?? ""
    return JSON.parse(raw.replaceAll("&quot;", '"').replaceAll("&amp;", "&")) as Record<string, unknown>
  }
  const setupKind = async (person: Person) => (await f.db.prepare("SELECT recovery_setup_kind FROM accounts WHERE id=?").bind(person.account).first<{ recovery_setup_kind: string | null }>())?.recovery_setup_kind ?? null
  // A sign-in, and an account step-up, whose assertion reports `backup`.
  const signinReporting = async (person: Person, backup: PasskeyBackup) => {
    const started = await body<{ flow: string; options: { challenge: string } }>(await f.request("/api/auth/signin/options", undefined, {}))
    const response = await f.request("/api/auth/signin/verify", undefined, { flow: started.flow, response: await assertion(person.passkey, started.options.challenge, ++person.counter, true, backup) })
    expect(await body(response.clone())).toEqual({ account: person.account })
    return { ...person, cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "" }
  }
  const stepUpReporting = async (person: Person, backup: PasskeyBackup) => {
    const action = { type: "recovery.generate" } as const
    const { nonce, options } = await body<{ nonce: string; options: { challenge: string } }>(await f.request("/api/account/stepup/start", person, { action }))
    return f.request("/api/account/recovery/generate", person, { stepUp: { nonce, assertion: await assertion(person.passkey, options.challenge, ++person.counter, true, backup) } })
  }
  return { ...f, signupFromInvite, recoveryReady, signupBoot, setupKind, signinReporting, stepUpReporting }
}

describe("a synced passkey counts as a way back in", () => {
  it("one synced passkey makes the account recovery-ready, so it joins with no codes", async () => {
    const f = await syncedJourney()
    const { person, code } = await f.signupFromInvite("Sam", "synced")
    expect(await f.db.prepare("SELECT backed_up FROM passkeys WHERE account=?").bind(person.account).first()).toEqual({ backed_up: 1 })
    expect(await f.recoveryReady(person)).toBe(true)
    expect(await f.setupKind(person)).toBe("passkey")
    expect(await body(await f.request("/api/account/invites/join", person, { code }))).toMatchObject({ state: "pending_confirmation" })
  })

  it("one passkey on this device only, and no codes, is not ready, so joining is refused", async () => {
    const f = await syncedJourney()
    for (const backup of ["device", "eligible"] as const) {
      const { person, code } = await f.signupFromInvite(`Dee ${backup}`, backup)
      expect(await f.recoveryReady(person)).toBe(false)
      expect(await f.setupKind(person)).toBeNull()
      expect((await f.request("/api/account/invites/join", person, { code })).status).toBe(403)
    }
  })
})

describe("/signup skips the recovery step when the new passkey is already a way back in", () => {
  it("the signup reply and the reloaded page say ready for a synced passkey, and not for one on this device only", async () => {
    const f = await syncedJourney()
    const synced = await f.signupFromInvite("Sam", "synced")
    expect(synced.created).toMatchObject({ onboarding: "join", recoveryReady: true })
    expect(await f.signupBoot(synced.person)).toEqual({ page: "workspace-signup", signedIn: true, recoveryReady: true })
    const device = await f.signupFromInvite("Dee", "device")
    expect(device.created).toMatchObject({ onboarding: "join", recoveryReady: false })
    expect(await f.signupBoot(device.person)).toEqual({ page: "workspace-signup", signedIn: true, recoveryReady: false })
  })
})

describe("the backed-up flag follows what the authenticator says at each use", () => {
  it("a sign-in whose passkey no longer reports backed up turns readiness off, without ending the session that was open", async () => {
    const f = await syncedJourney()
    const { person } = await f.signupFromInvite("Sam", "synced")
    expect(await f.recoveryReady(person)).toBe(true)
    const later = await f.signinReporting(person, "eligible")
    expect(await f.db.prepare("SELECT backed_up FROM passkeys WHERE account=?").bind(person.account).first()).toEqual({ backed_up: 0 })
    expect(await f.recoveryReady(later)).toBe(false)
    expect(await f.setupKind(person)).toBeNull()
    // Both sessions still work; only the next readiness check differs.
    expect(await f.recoveryReady(person)).toBe(false)
    const again = await f.signinReporting(person, "synced")
    expect(await f.recoveryReady(again)).toBe(true)
    expect(await f.setupKind(person)).toBe("passkey")
  })

  it("a step-up whose passkey no longer reports backed up turns readiness off too", async () => {
    const f = await syncedJourney()
    const { person, code } = await f.signupFromInvite("Sam", "synced")
    expect((await f.stepUpReporting(person, "eligible")).status).toBe(200)
    expect(await f.db.prepare("SELECT backed_up FROM passkeys WHERE account=?").bind(person.account).first()).toEqual({ backed_up: 0 })
    expect(await f.recoveryReady(person)).toBe(false)
    expect((await f.request("/api/account/invites/join", person, { code })).status).toBe(403)
  })
})

describe("an account's first recovery codes, straight after sign-up, need no step-up", () => {
  const STEP_UP_REFUSAL = { error: "forbidden", message: "This needs a passkey confirmation. Confirm with your passkey on the vault page and try again." }

  it("the first set within 15 minutes, from the sign-up session, needs no step-up; a second set does", async () => {
    const f = await syncedJourney()
    const { person } = await f.signupFromInvite("Dee", "device")
    const first = await body<{ batch: string; codes: string[]; confirmPosition: number }>(await f.request("/api/account/recovery/generate", person, {}))
    expect(await body(await f.request("/api/account/recovery/confirm", person, { batch: first.batch, code: first.codes[first.confirmPosition - 1] }))).toEqual({})
    expect(await f.recoveryReady(person)).toBe(true)
    const again = await f.request("/api/account/recovery/generate", person, {})
    expect(again.status).toBe(403)
    expect(await again.json()).toMatchObject(STEP_UP_REFUSAL)
    expect((await f.stepUpReporting(person, "device")).status).toBe(200)
  })

  it("the account's generate event records whether a step-up was used", async () => {
    const f = await syncedJourney()
    const { person } = await f.signupFromInvite("Dee", "device")
    expect((await f.request("/api/account/recovery/generate", person, {})).status).toBe(200)
    expect((await f.stepUpReporting(person, "device")).status).toBe(200)
    const events = await f.db.prepare("SELECT detail FROM account_events WHERE account=? AND action='account.recovery_generate' ORDER BY at,rowid").bind(person.account).all<{ detail: string }>()
    expect(events.results.map(event => JSON.parse(event.detail))).toEqual([{ count: 10, stepUp: false }, { count: 10, stepUp: true }])
  })

  it("an unconfirmed first set still counts: the next one needs a step-up", async () => {
    const f = await syncedJourney()
    const { person } = await f.signupFromInvite("Dee", "device")
    expect((await f.request("/api/account/recovery/generate", person, {})).status).toBe(200)
    expect((await f.request("/api/account/recovery/generate", person, {})).status).toBe(403)
  })

  it("an account whose passkey syncs needs a step-up even for its first set in the sign-up window", async () => {
    const f = await syncedJourney()
    const { person } = await f.signupFromInvite("Sam", "synced")
    const refused = await f.request("/api/account/recovery/generate", person, {})
    expect(refused.status).toBe(403)
    expect(await refused.json()).toMatchObject(STEP_UP_REFUSAL)
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM recovery_codes WHERE account=?").bind(person.account).first()).toEqual({ n: 0 })
    const account = await currentAccountSession(new Request(ORIGIN, { headers: { cookie: person.cookie } }), f.env)
    if (!account) throw new Error("Missing sign-up session")
    await expect(issueAccountRecoveryCodes(f.env, account, Date.now(), true)).rejects.toMatchObject({ code: "conflict" })
    expect((await f.stepUpReporting(person, "synced")).status).toBe(200)
  })

  it("the issuing batch refuses a second set made without a step-up, as a parallel first request would be", async () => {
    const f = await syncedJourney()
    const { person } = await f.signupFromInvite("Dee", "device")
    expect((await f.request("/api/account/recovery/generate", person, {})).status).toBe(200)
    const account = await currentAccountSession(new Request(ORIGIN, { headers: { cookie: person.cookie } }), f.env)
    if (!account) throw new Error("Missing sign-up session")
    await expect(issueAccountRecoveryCodes(f.env, account, Date.now(), true)).rejects.toMatchObject({ code: "conflict" })
    expect(await f.db.prepare("SELECT COUNT(*) AS codes, COUNT(DISTINCT batch) AS batches FROM recovery_codes WHERE account=?").bind(person.account).first()).toEqual({ codes: 10, batches: 1 })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM recovery_batches WHERE account=?").bind(person.account).first()).toEqual({ n: 1 })
  })

  it("past 15 minutes, or from a session that is not the sign-up's, the first set needs a step-up", async () => {
    const f = await syncedJourney()
    const late = await f.signupFromInvite("Lee", "device")
    await f.db.prepare("UPDATE web_sessions SET created_at=created_at-? WHERE account=?").bind(15 * 60_000 + 1, late.person.account).run()
    const refused = await f.request("/api/account/recovery/generate", late.person, {})
    expect(refused.status).toBe(403)
    expect(await refused.json()).toMatchObject(STEP_UP_REFUSAL)
    expect((await f.stepUpReporting(late.person, "device")).status).toBe(200)

    const signedIn = await f.signinReporting((await f.signupFromInvite("Kim", "device")).person, "device")
    expect((await f.request("/api/account/recovery/generate", signedIn, {})).status).toBe(403)
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM recovery_codes WHERE account=?").bind(signedIn.account).first()).toEqual({ n: 0 })
  })
})
