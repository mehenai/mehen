import { expect,it } from "vitest"
import { AccountSessionSchema } from "@mehen/protocol"
import { breakGlassStatement } from "../../scripts/break-glass.ts"
import { sha256Text } from "../../src/directory/session.ts"
import { registration,softwarePasskey } from "./passkeys.ts"
import { body,refusal,workJourney } from "./workspace-journey.ts"

it("break-glass: offline account intent, both real DO barriers, real replacement passkey, cooling-off, notices and replay refusal",async () => {
  const f = await workJourney(),code = "offline-cutover-recovery-link",now = Date.now()
  const old = (await f.db.prepare("SELECT handle FROM passkeys WHERE account=?").bind(f.alex.account).all<{ handle: string }>()).results
  await f.db.prepare(breakGlassStatement(f.alex.account,"operator:verified",await sha256Text(code),now,`bgi_${"a".repeat(32)}`,`ntc_${"b".repeat(32)}`)).run()
  f.faults.blockWorkspace = f.personal.id
  await f.cron()
  await refusal(await f.request("/api/auth/signup/options",undefined,{ invite: code,name: "Ignored label" }),404,{ error: "not_found",message: "No such recovery link." })
  expect(await f.db.prepare("SELECT state FROM account_break_glass_intents").first()).toEqual({ state: "pending" })
  expect(await f.db.prepare("SELECT handle FROM passkeys WHERE account=?").bind(f.alex.account).first()).toEqual(old[0])
  f.faults.blockWorkspace = ""
  await f.cron()
  expect(await f.db.prepare("SELECT state FROM account_break_glass_intents").first()).toEqual({ state: "ready" })
  await refusal(await f.request("/api/account",f.alex),401,{ error: "unauthenticated",message: "Sign in with your passkey to continue." })
  const passkey = await softwarePasskey(),{ options } = await body<{ options: { challenge: string } }>(await f.request("/api/auth/signup/options",undefined,{ invite: code,name: "Ignored label" }))
  const recovered = await f.request("/api/auth/signup/verify",undefined,{ invite: code,name: "Ignored label",response: await registration(passkey,options.challenge) })
  expect(await body(recovered)).toEqual({ account: f.alex.account,onboarding: "break-glass",recoveryReady: false })
  f.alex.cookie = recovered.headers.get("set-cookie")!.split(";")[0]!
  f.alex.passkey = passkey
  f.alex.counter = 0
  const account = AccountSessionSchema.parse(await body(await f.request("/api/account",f.alex)))
  expect(account.name).toBe("Alex")
  expect(account.restricted?.reason).toBe("break-glass")
  expect(Date.parse(account.restricted!.until!)).toBeGreaterThanOrEqual(now+86400000)
  expect(account.recoverySetupRequired).toBe(true)
  expect(account.memberships.map(m => m.workspace.id).sort()).toEqual([f.personal.id,f.work.id].sort())
  await refusal(await f.request("/api/auth/signup/options",undefined,{ invite: code,name: "Replay" }),404,{ error: "not_found",message: "No such recovery link." })
  await f.cron()
  for (const workspace of [f.personal,f.work]) {
    expect((await f.sql(workspace,"SELECT action FROM audit WHERE action='account.break_glass'")).length).toBeGreaterThanOrEqual(1)
    expect(await f.sql(workspace,"SELECT role,status FROM members WHERE account=?",f.alex.account)).toEqual([{ role: "owner",status: "active" }])
  }
  const notices = await body<{ kind: string; restrictedUntil: string | null }[]>(await f.request("/api/account/notices",f.alex))
  expect(notices.some(n => n.kind === "break-glass" && n.restrictedUntil !== null)).toBe(true)
  expect(JSON.stringify(notices)).not.toContain(code)
})
