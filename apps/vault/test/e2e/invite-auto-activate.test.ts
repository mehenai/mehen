// Joining through an email-bound invitation signed with onJoin "activate",
// end to end: the Google proof, the passkey, recovery, then the join, which
// answers active, mirrors the membership and installs the proof as the
// session's identity check, so the person goes straight to Connect an agent.
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import type { InviteTerms } from "@mehen/protocol"
import { setOidcFetchForTest } from "../../src/directory/oidc.ts"
import { fakeGoogle } from "../oidc-google.ts"
import { body, workJourney, type Person } from "./workspace-journey.ts"
import { registration, softwarePasskey } from "./passkeys.ts"
import { linkGoogle, oidcResultOf, setGoogleRule, webGate } from "./oidc-journey.ts"
let google: Awaited<ReturnType<typeof fakeGoogle>>
beforeEach(async () => { google = await fakeGoogle(); setOidcFetchForTest(google.fetcher) })
afterEach(() => setOidcFetchForTest(null))

async function invitedPerson(onJoin: InviteTerms["onJoin"], identityRule = false) {
  const f = await workJourney()
  if (identityRule) { await linkGoogle(f, google); await setGoogleRule(f, google); await webGate(f, google) }
  const invite = await f.invite(f.alex, f.work, { role: "member", email: "new@northwind.example", teams: [], shares: [], expiresAt: new Date(Date.now() + 86400000).toISOString(), onJoin })
  f.env.GOOGLE_SIGNIN_CLIENT_ID = "test-google-client"; f.env.GOOGLE_SIGNIN_CLIENT_SECRET = "test-only-google-secret"
  const started = await f.request("/api/auth/oidc/google/start", undefined, { purpose: "invite", invite: invite.code }), flowCookie = started.headers.get("set-cookie")!.split(";")[0]!, { url } = await body<{ url: string }>(started)
  const callback = await f.request(`/auth/oidc/google/callback?${new URLSearchParams(google.authorise(url, { sub: "new-subject", email: "new@northwind.example" }))}`, undefined, undefined, { cookie: flowCookie })
  const result = oidcResultOf(callback, f.env.VAULT_ORIGIN), passkey = await softwarePasskey(), name = "New person"
  const options = await body<{ options: { challenge: string } }>(await f.request("/api/auth/signup/options", undefined, { invite: invite.code, name, oidcResult: result }, { cookie: flowCookie }))
  const registered = await f.request("/api/auth/signup/verify", undefined, { invite: invite.code, name, oidcResult: result, response: await registration(passkey, options.options.challenge) }, { cookie: flowCookie })
  const cookie = registered.headers.get("set-cookie")!.split(";")[0]!, created = await body<{ account: string }>(registered)
  const person: Person = { account: created.account, cookie: `${cookie}; ${flowCookie}`, passkey, counter: 0, codes: [] }
  await f.recoverySetup(person)
  return { ...f, invite, result, person }
}

describe("joining straight away through the directory", () => {
  it("answers active, mirrors the membership, installs the proof as a session check and onboards to Connect an agent", async () => {
    const f = await invitedPerson("activate")
    const joined = await body<{ member: string; state: string }>(await f.request("/api/account/invites/join", f.person, { code: f.invite.code, oidcResult: f.result }))
    expect(joined).toEqual({ member: expect.stringMatching(/^mem_/), state: "active" })
    expect(await f.db.prepare("SELECT state FROM memberships WHERE id=?").bind(joined.member).first()).toEqual({ state: "member" })
    expect(await f.db.prepare("SELECT state FROM oidc_results WHERE id=?").bind(f.result).first()).toEqual({ state: "consumed" })
    expect(await f.db.prepare("SELECT COUNT(*) AS n FROM session_identity_checks WHERE member=?").bind(joined.member).first()).toEqual({ n: 1 })
    expect(await f.sql(f.work, "SELECT status FROM members WHERE id=?", joined.member)).toEqual([{ status: "active" }])
    expect(await f.sql(f.work, "SELECT purpose FROM workspace_identity_checks WHERE member=?", joined.member)).toEqual([{ purpose: "session" }])
    expect(await body(await f.request(`/api/account/onboarding/${f.work.id}`, f.person))).toEqual({ next: `${f.env.VAULT_ORIGIN}/w/${f.work.slug}/connect-agent` })
  })

  it("under a workspace identity rule covering members, installs the proof as the session check that admits the new member", async () => {
    const f = await invitedPerson("activate", true)
    const joined = await body<{ member: string; state: string }>(await f.request("/api/account/invites/join", f.person, { code: f.invite.code, oidcResult: f.result }))
    expect(joined).toEqual({ member: expect.stringMatching(/^mem_/), state: "active" })
    expect(await f.sql(f.work, "SELECT purpose FROM workspace_identity_checks WHERE member=?", joined.member)).toEqual([{ purpose: "session" }])
    expect((await f.request(`/api/w/${f.work.slug}`, f.person)).status).toBe(200)
  })

  it("waits for confirmation as before when the inviter chose to confirm", async () => {
    const f = await invitedPerson("confirm")
    const joined = await body<{ member: string; state: string }>(await f.request("/api/account/invites/join", f.person, { code: f.invite.code, oidcResult: f.result }))
    expect(joined).toEqual({ member: expect.stringMatching(/^mem_/), state: "pending_confirmation" })
    expect(await f.sql(f.work, "SELECT status FROM members WHERE id=?", joined.member)).toEqual([{ status: "unconfirmed" }])
    expect(await f.sql(f.work, "SELECT purpose FROM workspace_identity_checks WHERE member=?", joined.member)).toEqual([{ purpose: "invite" }])
  })
})
