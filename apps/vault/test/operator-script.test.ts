import { beforeEach, describe, expect, it } from "vitest"
import { operatorStatements, operatorUpdate, parseOperatorArgs, parseOperatorSettingArgs, runOperator, runOperatorSetting, settingCeilingFromConfig, type OperatorAccountRow, type OperatorIo } from "../scripts/operator.ts"
import { createWorkspaceFixture, type WorkspaceTestFixture } from "./workspace-fixtures.ts"
let f: WorkspaceTestFixture
beforeEach(async () => { f = await createWorkspaceFixture() })
const args = () => parseOperatorArgs(["--local","allow-workspaces",f.account,"--actor","operator:test"])
function io(typed: string | null = f.account): OperatorIo & { output: string[] } {
  const output: string[] = []
  return { output,async query(_target,sql) { return (await f.env.DB.prepare(sql).all<OperatorAccountRow>()).results },async update(_target,statements) { return (await f.env.DB.batch<{ id: string }>(statements.map(sql => f.env.DB.prepare(sql))))[0]?.results ?? [] },async bookmark() { output.push("bookmark"); return "fixture-bookmark" },async ask() { return typed },print(line) { output.push(line) } }
}
describe("operator allow-list",() => {
  it("requires explicit database, account and actor, rejects SQL-shaped values",() => {
    for (const argv of [[],["--remote","--local"],["--local","allow-workspaces","acc_x'","--actor","operator:test"],["--local","allow-workspaces","acc_x","--actor","test"],["--local","allow-workspaces","acc_x","--actor","operator:a';"]]) expect(() => parseOperatorArgs(argv)).toThrow("Usage:")
  })
  it("updates a default-denied account with same-statement event and notice; no-op adds neither",async () => {
    expect(await f.env.DB.prepare("SELECT can_create_workspaces FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ can_create_workspaces: 0 })
    const transport = io()
    expect(await runOperator(args(),transport)).toBe(0)
    expect(transport.output[0]).toBe("bookmark")
    expect(await f.env.DB.prepare("SELECT action,detail FROM account_events WHERE account=?").bind(f.account).first()).toEqual({ action: "operator.allow_workspaces",detail: JSON.stringify({ by: "operator:test",allowed: 1 }) })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_notices WHERE account=?").bind(f.account).first()).toEqual({ n: 1 })
    expect(await runOperator(args(),io())).toBe(0)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events WHERE account=?").bind(f.account).first()).toEqual({ n: 1 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_notices WHERE account=?").bind(f.account).first()).toEqual({ n: 1 })
  })
  it("denies creation and records explicit actor",async () => {
    await f.env.DB.prepare(operatorUpdate(args())).run()
    expect(await runOperator({ ...args(),command: "deny-workspaces" },io())).toBe(0)
    expect(await f.env.DB.prepare("SELECT can_create_workspaces FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ can_create_workspaces: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events WHERE action='operator.deny_workspaces'").first()).toEqual({ n: 1 })
  })
  it("spells an account name's control characters in the plan, so no ESC or BEL from it reaches the terminal",async () => {
    await f.env.DB.prepare("UPDATE accounts SET name=? WHERE id=?").bind("Mallory\u001b[31m red\u001b[0m\u0007\u009b2J",f.account).run()
    const transport = io(null)
    expect(await runOperator(args(),transport)).toBe(1)
    expect(transport.output.filter(line => /[\u0000-\u001f\u007f-\u009f]/.test(line))).toEqual([])
    expect(transport.output).toContain(`allow-workspaces for Mallory\\u001B[31m red\\u001B[0m\\u0007\\u009B2J (${f.account}) on local database mehen-local, actor operator:test.`)
  })
  it("says where the account's workspace creation comes from before asking",async () => {
    const transport = io()
    expect(await runOperator({ ...args(),command: "deny-workspaces" },transport)).toBe(0)
    expect(transport.output).toContain("Workspace creation for this account now: no operator decision, so the deployment default (WORKSPACE_CREATION) decides.")
    const again = io()
    expect(await runOperator(args(),again)).toBe(0)
    expect(again.output).toContain("Workspace creation for this account now: denied by operator:test.")
  })
  it("denies a never-flagged account with the same event and notice the trigger writes for a deny",async () => {
    const rows = async (account: string) => ({
      events: (await f.env.DB.prepare("SELECT account,action,detail,mirrored_to,targets,attempts,next_retry_at FROM account_events WHERE account=? ORDER BY at,rowid").bind(account).all()).results,
      notices: (await f.env.DB.prepare("SELECT account,kind,payload,resolved_at FROM account_notices WHERE account=? ORDER BY at,rowid").bind(account).all()).results,
    })
    expect(await f.env.DB.prepare("SELECT can_create_workspaces,can_create_workspaces_by FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ can_create_workspaces: 0,can_create_workspaces_by: null })
    expect(await runOperator({ ...args(),command: "deny-workspaces" },io())).toBe(0)
    expect(await f.env.DB.prepare("SELECT can_create_workspaces,can_create_workspaces_by FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ can_create_workspaces: 0,can_create_workspaces_by: "operator:test" })
    const scripted = await rows(f.account)
    // The trigger's own deny, on another account: allowed first, then denied.
    const other = "acc_admin",otherArgs = { ...args(),account: other }
    await f.env.DB.prepare(operatorUpdate(otherArgs)).run()
    await f.env.DB.prepare(operatorUpdate({ ...otherArgs,command: "deny-workspaces" })).run()
    const triggered = await rows(other)
    expect(scripted.events).toHaveLength(1)
    expect(scripted.notices).toHaveLength(1)
    expect(scripted.events[0]).toEqual({ ...triggered.events[1],account: f.account })
    expect(scripted.notices[0]).toEqual({ ...triggered.notices[1],account: f.account })
    expect(scripted.events[0]).toMatchObject({ action: "operator.deny_workspaces",detail: JSON.stringify({ by: "operator:test",allowed: 0 }) })
  })
  it("a deny from the default that finds the account already decided writes nothing",async () => {
    const stale: OperatorAccountRow = { id: f.account,name: "owner",can_create_workspaces: 0,can_create_workspaces_by: null }
    const statements = operatorStatements({ ...args(),command: "deny-workspaces" },stale)
    expect(statements).toHaveLength(3)
    await f.env.DB.prepare(operatorUpdate(args())).run()
    const before = { events: (await f.env.DB.prepare("SELECT * FROM account_events").all()).results,notices: (await f.env.DB.prepare("SELECT * FROM account_notices").all()).results }
    const results = await f.env.DB.batch(statements.map(sql => f.env.DB.prepare(sql)))
    expect(results[0]?.results).toEqual([])
    expect(await f.env.DB.prepare("SELECT can_create_workspaces FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ can_create_workspaces: 1 })
    expect({ events: (await f.env.DB.prepare("SELECT * FROM account_events").all()).results,notices: (await f.env.DB.prepare("SELECT * FROM account_notices").all()).results }).toEqual(before)
  })
  it("refuses missing account, non-terminal or wrong confirmation without writing anything",async () => {
    for (const typed of [null,"acc_wrong"]) expect(await runOperator(args(),io(typed))).toBe(1)
    expect(await runOperator({ ...args(),account: "acc_missing" },io())).toBe(1)
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_events").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_notices").first()).toEqual({ n: 0 })
    expect(await f.env.DB.prepare("SELECT can_create_workspaces FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ can_create_workspaces: 0 })
  })
  it("rolls back flag and notice if the operator event cannot commit",async () => {
    await f.env.DB.prepare("CREATE TRIGGER reject_event BEFORE INSERT ON account_events BEGIN SELECT RAISE(ABORT,'audit failure'); END").run()
    await expect(f.env.DB.prepare(operatorUpdate(args())).run()).rejects.toThrow("audit failure")
    expect(await f.env.DB.prepare("SELECT can_create_workspaces FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ can_create_workspaces: 0 })
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM account_notices").first()).toEqual({ n: 0 })
    await f.env.DB.prepare("DROP TRIGGER reject_event").run()
  })
})

it("a stale operator actor without a fresh operation id cannot change the flag",async () => {
  await f.env.DB.prepare(operatorUpdate(args())).run()
  const before = (await f.env.DB.prepare("SELECT * FROM account_events").all()).results,notices = (await f.env.DB.prepare("SELECT * FROM account_notices").all()).results
  await expect(f.env.DB.prepare("UPDATE accounts SET can_create_workspaces=0 WHERE id=?").bind(f.account).run()).rejects.toThrow("fresh operator operation required")
  expect(await f.env.DB.prepare("SELECT can_create_workspaces FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ can_create_workspaces: 1 })
  expect((await f.env.DB.prepare("SELECT * FROM account_events").all()).results).toEqual(before)
  expect((await f.env.DB.prepare("SELECT * FROM account_notices").all()).results).toEqual(notices)
})


it("remote operator scripts explicitly select the top-level Worker environment",async () => {
  const { parseArgs } = await import("../scripts/break-glass.ts")
  expect(parseOperatorArgs(["--remote","allow-workspaces",f.account,"--actor","operator:test"]).target.flags).toEqual(["--remote","--env",""])
  expect(parseArgs(["--remote","--list"]).target.flags).toEqual(["--remote","--env",""])
})

describe("operator role",() => {
  const role = (command: "grant-operator" | "revoke-operator") => parseOperatorArgs(["--local",command,f.account,"--actor","operator:test"])
  it("grant-operator and revoke-operator set the flag with the account id typed back, each with one event and one notice",async () => {
    expect(await runOperator(role("grant-operator"),io("acc_wrong"))).toBe(1)
    expect(await f.env.DB.prepare("SELECT is_operator FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ is_operator: 0 })
    expect(await runOperator(role("grant-operator"),io())).toBe(0)
    expect(await f.env.DB.prepare("SELECT is_operator,is_operator_by,can_create_workspaces FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ is_operator: 1,is_operator_by: "operator:test",can_create_workspaces: 0 })
    expect(await runOperator(role("revoke-operator"),io())).toBe(0)
    expect((await f.env.DB.prepare("SELECT action FROM account_events WHERE account=? ORDER BY at,rowid").bind(f.account).all()).results).toEqual([{ action: "operator.grant_operator" },{ action: "operator.revoke_operator" }])
    expect((await f.env.DB.prepare("SELECT payload FROM account_notices WHERE account=? ORDER BY at,rowid").bind(f.account).all<{ payload: string }>()).results.map(r => JSON.parse(r.payload))).toEqual([{ change: "operator_role",operator: 1,by: "operator:test" },{ change: "operator_role",operator: 0,by: "operator:test" }])
    expect((await f.env.DB.prepare("SELECT kind,actor,approver,target,details FROM deployment_events ORDER BY at,rowid").all()).results).toEqual([
      { kind: "operator.grant",actor: "operator:test",approver: null,target: f.account,details: JSON.stringify({ via: "scripts/operator.ts" }) },
      { kind: "operator.revoke",actor: "operator:test",approver: null,target: f.account,details: JSON.stringify({ via: "scripts/operator.ts" }) },
    ])
  })
  it("granting an operator or revoking a non-operator changes nothing and records no deployment event, as the 0012 trigger records no operator event",async () => {
    const revoke = io()
    expect(await runOperator(role("revoke-operator"),revoke)).toBe(1)
    expect(revoke.output.at(-1)).toBe("Nothing changed: the account already has that role, or no longer matched.")
    expect(await runOperator(role("grant-operator"),io())).toBe(0)
    await f.env.DB.prepare("UPDATE accounts SET is_operator_by='operator:first' WHERE id=?").bind(f.account).run()
    expect(await runOperator(parseOperatorArgs(["--local","grant-operator",f.account,"--actor","operator:again"]),io())).toBe(1)
    expect(await f.env.DB.prepare("SELECT is_operator,is_operator_by FROM accounts WHERE id=?").bind(f.account).first()).toEqual({ is_operator: 1,is_operator_by: "operator:first" })
    expect((await f.env.DB.prepare("SELECT action FROM account_events WHERE account=?").bind(f.account).all()).results).toEqual([{ action: "operator.grant_operator" }])
    expect((await f.env.DB.prepare("SELECT kind FROM deployment_events").all()).results).toEqual([{ kind: "operator.grant" }])
  })
  it("a role change that does not land records no deployment event",async () => {
    const [account] = (await f.env.DB.prepare("SELECT id,name,can_create_workspaces,can_create_workspaces_by FROM accounts WHERE id=?").bind(f.account).all<OperatorAccountRow>()).results
    const statements = operatorStatements({ ...role("grant-operator"),account: "acc_nobody" },account!)
    expect((await f.env.DB.batch(statements.map(sql => f.env.DB.prepare(sql))))[0]?.results).toEqual([])
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM deployment_events").first()).toEqual({ n: 0 })
  })
})

// The deploy's wrangler.jsonc, as far as the setting command reads it.
const CONFIG = `{
  // the production deploy
  "vars": { "WORKSPACE_CREATION": "accounts", "SIGNUP_MODE_MAX": "invite" },
  "env": { "local": { "vars": { "WORKSPACE_CREATION": "accounts", "SIGNUP_MODE_MAX": "open" } } }
}`
const settingArgs = (key: string,value: string) => parseOperatorSettingArgs(["--local","setting",key,value,"--actor","operator:test"])
const stored = async () => (await f.env.DB.prepare("SELECT key,value,updated_by FROM deployment_settings ORDER BY key").all()).results
const settingEvents = async () => (await f.env.DB.prepare("SELECT kind,actor,target,details FROM deployment_events WHERE kind='settings.set' ORDER BY at,rowid").all()).results
describe("operator setting",() => {
  it("requires a database, a known setting, one of its values or --default, and an operator actor",() => {
    for (const argv of [["--local","setting","workspace_creation","accounts"],["--local","setting","colour","red","--actor","operator:test"],["--local","setting","signup_mode","everyone","--actor","operator:test"],["--local","setting","signup_mode","open","--actor","test"],["setting","signup_mode","open","--actor","operator:test"]]) expect(() => parseOperatorSettingArgs(argv)).toThrow("Usage:")
    expect(settingArgs("signup_mode","--default")).toMatchObject({ key: "signup_mode",value: null,target: { kind: "local",database: "mehen-local" } })
  })
  it("reads the ceiling from the named environment's vars, and nothing it cannot read",() => {
    const remote = parseOperatorSettingArgs(["--remote","setting","signup_mode","open","--actor","operator:test"]).target
    expect(settingCeilingFromConfig(CONFIG,remote,"signup_mode")).toBe("invite")
    expect(settingCeilingFromConfig(CONFIG,settingArgs("signup_mode","open").target,"signup_mode")).toBe("open")
    expect(settingCeilingFromConfig("{ not json",remote,"signup_mode")).toBeNull()
    const deployed = Object.values(import.meta.glob<string>("../wrangler.jsonc",{ query: "?raw",import: "default",eager: true }))[0] ?? ""
    expect([settingCeilingFromConfig(deployed,remote,"workspace_creation"),settingCeilingFromConfig(deployed,remote,"signup_mode"),settingCeilingFromConfig(deployed,settingArgs("signup_mode","open").target,"signup_mode")]).toEqual(["accounts","invite","invite"])
    expect(settingCeilingFromConfig("{}",remote,"signup_mode")).toBeNull()
  })
  it("sets a setting up to the ceiling with its deployment event in the same batch, after a typed confirmation",async () => {
    const transport = io("workspace_creation")
    expect(await runOperatorSetting(settingArgs("workspace_creation","operator"),transport,CONFIG)).toBe(0)
    expect(transport.output[0]).toBe("bookmark")
    expect(await stored()).toEqual([{ key: "workspace_creation",value: "operator",updated_by: "operator:test" }])
    expect(await settingEvents()).toEqual([{ kind: "settings.set",actor: "operator:test",target: "workspace_creation",details: JSON.stringify({ via: "scripts/operator.ts",params: { value: "operator" } }) }])
    expect(await runOperatorSetting(settingArgs("workspace_creation","--default"),io("workspace_creation"),CONFIG)).toBe(0)
    expect(await stored()).toEqual([])
    expect(await settingEvents()).toHaveLength(2)
  })
  it("refuses a value past the ceiling, an unreadable ceiling and a wrong confirmation, changing nothing",async () => {
    const remote = { ...parseOperatorSettingArgs(["--remote","setting","signup_mode","open","--actor","operator:test"]),target: settingArgs("signup_mode","open").target }
    const past = io("signup_mode")
    expect(await runOperatorSetting(remote,past,CONFIG.replace('"SIGNUP_MODE_MAX": "open"','"SIGNUP_MODE_MAX": "request"'))).toBe(1)
    expect(past.output).toEqual(["Nothing changed: this deploy allows at most request (SIGNUP_MODE_MAX); change wrangler.jsonc and deploy first."])
    const unreadable = io("signup_mode")
    expect(await runOperatorSetting(settingArgs("signup_mode","open"),unreadable,"{")).toBe(1)
    expect(unreadable.output).toEqual(["Nothing changed: the deploy's ceiling cannot be read from wrangler.jsonc."])
    expect(await runOperatorSetting(settingArgs("signup_mode","open"),io("nope"),CONFIG)).toBe(1)
    expect(await runOperatorSetting(settingArgs("signup_mode","--default"),io("signup_mode"),CONFIG)).toBe(1)
    expect(await stored()).toEqual([])
    expect(await settingEvents()).toEqual([])
  })
})
