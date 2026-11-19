// Offline operator only. In the app, the operator role changes only by two
// operators (a proposal one makes and another approves, routes/
// console-operators.ts); this script is the break-glass for when the app is
// down or every operator is locked out, and adds the first extra operators.
// Whoever can write D1 or deploy the Worker still bypasses all of it
// (docs/OPERATIONS.md, Operators). One account's workspace creation is also
// set in the app, on its page in the Accounts view, which writes the same
// columns, event and notice (directory/operator-account-kinds.ts). Creating
// workspaces is the
// deployment's WORKSPACE_CREATION for an account the operator has not decided
// on (src/directory/workspace-creation.ts): under "accounts" every account may,
// deny-workspaces stops one and allow-workspaces undoes a deny; under
// "operator" an account needs allow-workspaces first. The operator role
// opens the web console's operator pages (routes/console.ts), and every
// write there still needs that account's passkey; this script and
// scripts/platform.ts stay the break-glass beside it.
// `setting` is the break-glass for the deployment settings the Settings
// view changes (src/directory/deployment-settings.ts): it sets one, never
// past the ceiling the deploy's wrangler.jsonc sets for that database, or
// clears it back to the deploy's default, recording settings.set in
// deployment_events in the same batch.
import { DEPLOYMENT_SETTINGS,type DeploymentSettingKey,deploymentSettingCeiling,deploymentSettingRank,isDeploymentSettingValue } from "@mehen/protocol/deployment-settings"
import { spelledPrint } from "./terminal.ts"
export type OperatorTarget = { kind: "remote" | "local"; database: string; flags: string[] }
const COMMANDS = ["allow-workspaces","deny-workspaces","grant-operator","revoke-operator"] as const
export type OperatorCommand = (typeof COMMANDS)[number]
export type OperatorArgs = { target: OperatorTarget; command: OperatorCommand; account: string; actor: string }
const ACCOUNT = /^acc_[A-Za-z0-9_-]{1,64}$/
const ACTOR = /^operator:[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/
export function parseOperatorArgs(argv: string[]): OperatorArgs {
  if (argv.length !== 5 || !["--remote","--local"].includes(argv[0] ?? "") || !(COMMANDS as readonly string[]).includes(argv[1] ?? "") || !ACCOUNT.test(argv[2] ?? "") || argv[3] !== "--actor" || !ACTOR.test(argv[4] ?? "")) throw new Error("Usage: bun scripts/operator.ts (--remote | --local) (allow-workspaces | deny-workspaces | grant-operator | revoke-operator) acc_id --actor operator:label")
  return { target: operatorTarget(argv[0] === "--remote"),command: argv[1] as OperatorArgs["command"],account: argv[2] as string,actor: argv[4] as string }
}
function operatorTarget(remote: boolean): OperatorTarget {
  return { kind: remote ? "remote" : "local",database: remote ? "mehen" : "mehen-local",flags: remote ? ["--remote","--env",""] : ["--local","--env","local"] }
}
// The flag each command sets, and to what.
const FLAGS: Record<OperatorCommand,{ column: "can_create_workspaces" | "is_operator"; value: 0 | 1 }> = {
  "allow-workspaces": { column: "can_create_workspaces",value: 1 },"deny-workspaces": { column: "can_create_workspaces",value: 0 },
  "grant-operator": { column: "is_operator",value: 1 },"revoke-operator": { column: "is_operator",value: 0 },
}
// The operator role changes only from the other value, so granting an
// operator or revoking a non-operator lands nothing and records nothing,
// as the 0012 trigger records nothing when the flag stays the same.
export function operatorUpdate(args: OperatorArgs,op: string = crypto.randomUUID()): string {
  if (!ACCOUNT.test(args.account) || !ACTOR.test(args.actor)) throw new Error("Invalid operator target or actor")
  const { column,value } = FLAGS[args.command]
  const changes = column === "is_operator" ? ` AND is_operator=${1 - value}` : ""
  return `UPDATE accounts SET ${column}=${value},${column}_by='${args.actor}',${column}_op='${op}' WHERE id='${args.account}' AND status='active'${changes} RETURNING id,${column}`
}
export type OperatorAccountRow = { id: string; name: string; can_create_workspaces: number; can_create_workspaces_by: string | null }
// Whether this command is deny-workspaces of an account the operator never
// decided on. Its flag is already 0, so the 0005 trigger, which fires only
// when the flag changes, writes no event and no notice.
export function deniesFromDefault(args: OperatorArgs,account: OperatorAccountRow): boolean {
  return args.command === "deny-workspaces" && account.can_create_workspaces_by === null
}
// The deployment_events row a change of the operator role writes, only if
// the UPDATE with this operation id landed.
function roleEvent(args: OperatorArgs,op: string): string {
  return `INSERT INTO deployment_events(id,at,kind,actor,approver,target,details) SELECT 'dpe_' || lower(hex(randomblob(16))),CAST(unixepoch('subsec')*1000 AS INTEGER),'${args.command === "grant-operator" ? "operator.grant" : "operator.revoke"}','${args.actor}',NULL,'${args.account}',json_object('via','scripts/operator.ts') WHERE EXISTS (SELECT 1 FROM accounts WHERE id='${args.account}' AND is_operator_op='${op}')`
}
// The statements one run sends, in one batch; the first is the UPDATE. A
// change of the operator role also records its deployment event. A deny
// from the default records the decision only while the account is still
// undecided, and writes the event and notice the trigger would, each only if
// that UPDATE landed (its fresh operation id).
export function operatorStatements(args: OperatorArgs,account: OperatorAccountRow): string[] {
  const op = crypto.randomUUID()
  if (FLAGS[args.command].column === "is_operator") return [operatorUpdate(args,op),roleEvent(args,op)]
  if (!deniesFromDefault(args,account)) return [operatorUpdate(args,op)]
  const landed = `EXISTS (SELECT 1 FROM accounts WHERE id='${args.account}' AND can_create_workspaces_op='${op}' AND can_create_workspaces_by='${args.actor}')`
  return [
    `UPDATE accounts SET can_create_workspaces=0,can_create_workspaces_by='${args.actor}',can_create_workspaces_op='${op}' WHERE id='${args.account}' AND status='active' AND can_create_workspaces=0 AND can_create_workspaces_by IS NULL RETURNING id,can_create_workspaces`,
    `INSERT INTO account_events(id,account,at,action,detail) SELECT 'evt_' || lower(hex(randomblob(16))),'${args.account}',CAST(unixepoch('subsec')*1000 AS INTEGER),'operator.deny_workspaces',json_object('by','${args.actor}','allowed',0) WHERE ${landed}`,
    `INSERT INTO account_notices(id,account,kind,payload,at) SELECT 'ntc_' || lower(hex(randomblob(16))),'${args.account}','workspace',json_object('change','workspace_creation','allowed',0,'by','${args.actor}'),CAST(unixepoch('subsec')*1000 AS INTEGER) WHERE ${landed}`,
  ]
}
function workspaceCreationWords(account: OperatorAccountRow): string {
  if (account.can_create_workspaces_by === null) return "no operator decision, so the deployment default (WORKSPACE_CREATION) decides"
  return `${account.can_create_workspaces === 1 ? "allowed" : "denied"} by ${account.can_create_workspaces_by}`
}
export type OperatorIo = {
  query(target: OperatorTarget,sql: string): Promise<OperatorAccountRow[]>
  // Runs the statements as one batch and answers the first one's rows.
  update(target: OperatorTarget,statements: string[]): Promise<{ id: string }[]>
  bookmark(target: OperatorTarget): Promise<string>
  ask(prompt: string): Promise<string | null>
  print(line: string): void
}
export async function runOperator(args: OperatorArgs,terminal: OperatorIo): Promise<number> {
  const io = spelledPrint(terminal)
  if (!ACCOUNT.test(args.account) || !ACTOR.test(args.actor)) throw new Error("Invalid operator target or actor")
  const [account] = await io.query(args.target,`SELECT id,name,can_create_workspaces,can_create_workspaces_by FROM accounts WHERE id='${args.account}' AND status='active'`)
  if (!account) { io.print("Nothing changed: no active account with that id."); return 1 }
  const statements = operatorStatements(args,account)
  const bookmark = await io.bookmark(args.target)
  if (!bookmark) throw new Error("No D1 bookmark; nothing changed.")
  io.print(`D1 bookmark before change: ${bookmark}`)
  io.print(`${args.command} for ${account.name} (${account.id}) on ${args.target.kind} database ${args.target.database}, actor ${args.actor}.`)
  if (FLAGS[args.command].column === "can_create_workspaces") io.print(`Workspace creation for this account now: ${workspaceCreationWords(account)}.`)
  if (deniesFromDefault(args,account)) io.print("The flag is already off, so its trigger writes nothing: this batch records the deny, then writes the operator event and the account notice the trigger would, only if the deny was recorded.")
  else io.print(`One UPDATE changes the flag. Its trigger atomically writes the operator event and the account notice, only if the flag changes${FLAGS[args.command].column === "is_operator" ? "; the next statement records the deployment event, only if it did" : ""}.`)
  for (const statement of statements) io.print(statement)
  if ((await io.ask(`Type account id ${account.id}: `))?.trim() !== account.id) { io.print("Nothing changed: account id confirmation did not match."); return 1 }
  const rows = await io.update(args.target,statements)
  if (rows.length !== 1 || rows[0]?.id !== account.id) { io.print(FLAGS[args.command].column === "is_operator" ? "Nothing changed: the account already has that role, or no longer matched." : "Nothing changed: the account no longer matched."); return 1 }
  io.print(`Recorded ${args.command} for ${account.id}.`)
  return 0
}
export type OperatorSettingArgs = { target: OperatorTarget; key: DeploymentSettingKey; value: string | null; actor: string }
const SETTING_USAGE = "Usage: bun scripts/operator.ts (--remote | --local) setting (workspace_creation | signup_mode) (value | --default) --actor operator:label"
export function parseOperatorSettingArgs(argv: string[]): OperatorSettingArgs {
  const [database,command,key,value,actorFlag,actor] = argv
  if (argv.length !== 6 || !["--remote","--local"].includes(database ?? "") || command !== "setting" || !Object.hasOwn(DEPLOYMENT_SETTINGS,key ?? "") || actorFlag !== "--actor" || !ACTOR.test(actor ?? "")) throw new Error(SETTING_USAGE)
  const settingKey = key as DeploymentSettingKey
  if (value !== "--default" && !isDeploymentSettingValue(settingKey,value ?? "")) throw new Error(`${SETTING_USAGE}\n${settingKey} is one of ${DEPLOYMENT_SETTINGS[settingKey].values.join(", ")}.`)
  return { target: operatorTarget(database === "--remote"),key: settingKey,value: value === "--default" ? null : value as string,actor: actor as string }
}
// The deploy's ceiling for this database: the variable in wrangler.jsonc's
// vars for its environment (the top level for --remote, env.local for
// --local), or null when the file cannot be read that way. Its comments are
// whole lines.
export function settingCeilingFromConfig(config: string,target: OperatorTarget,key: DeploymentSettingKey): string | null {
  let parsed: unknown
  try { parsed = JSON.parse(config.split("\n").filter(line => !line.trim().startsWith("//")).join("\n")) } catch { return null }
  const root = parsed as { vars?: Record<string,unknown>; env?: Record<string,{ vars?: Record<string,unknown> }> }
  const vars = target.kind === "remote" ? root.vars : root.env?.local?.vars
  if (typeof vars !== "object" || vars === null) return null
  const raw = vars[DEPLOYMENT_SETTINGS[key].ceilingVar]
  return deploymentSettingCeiling(key,typeof raw === "string" ? raw : undefined)
}
// The statements one run sends, in one batch: the setting written (or
// cleared), then its deployment event, only if it was.
export function operatorSettingStatements(args: OperatorSettingArgs): string[] {
  if (!ACTOR.test(args.actor) || !Object.hasOwn(DEPLOYMENT_SETTINGS,args.key) || (args.value !== null && !isDeploymentSettingValue(args.key,args.value))) throw new Error("Invalid setting or actor")
  const now = "CAST(unixepoch('subsec')*1000 AS INTEGER)"
  const details = args.value === null ? "json_object('via','scripts/operator.ts','default',json('true'))" : `json_object('via','scripts/operator.ts','params',json_object('value','${args.value}'))`
  return [
    args.value === null
      ? `DELETE FROM deployment_settings WHERE key='${args.key}' RETURNING key AS id`
      : `INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('${args.key}','${args.value}',${now},'${args.actor}') ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by RETURNING key AS id`,
    `INSERT INTO deployment_events(id,at,kind,actor,approver,target,details) SELECT 'dpe_' || lower(hex(randomblob(16))),${now},'settings.set','${args.actor}',NULL,'${args.key}',${details} WHERE changes()>0`,
  ]
}
export async function runOperatorSetting(args: OperatorSettingArgs,terminal: OperatorIo,config: string): Promise<number> {
  const io = spelledPrint(terminal)
  const ceiling = settingCeilingFromConfig(config,args.target,args.key)
  if (ceiling === null) { io.print("Nothing changed: the deploy's ceiling cannot be read from wrangler.jsonc."); return 1 }
  const ceilingVar = DEPLOYMENT_SETTINGS[args.key].ceilingVar
  if (args.value !== null && isDeploymentSettingValue(args.key,args.value) && isDeploymentSettingValue(args.key,ceiling) && deploymentSettingRank(args.key,args.value) > deploymentSettingRank(args.key,ceiling)) { io.print(`Nothing changed: this deploy allows at most ${ceiling} (${ceilingVar}); change wrangler.jsonc and deploy first.`); return 1 }
  const statements = operatorSettingStatements(args)
  const bookmark = await io.bookmark(args.target)
  if (!bookmark) throw new Error("No D1 bookmark; nothing changed.")
  io.print(`D1 bookmark before change: ${bookmark}`)
  io.print(`setting ${args.key} ${args.value ?? "back to the deploy's default"} on ${args.target.kind} database ${args.target.database}, actor ${args.actor}; the deploy's ceiling is ${ceiling} (${ceilingVar}).`)
  io.print("The first statement writes the setting; the next records the deployment event, only if it did.")
  for (const statement of statements) io.print(statement)
  if ((await io.ask(`Type setting ${args.key}: `))?.trim() !== args.key) { io.print("Nothing changed: setting confirmation did not match."); return 1 }
  const rows = await io.update(args.target,statements)
  if (rows.length !== 1 || rows[0]?.id !== args.key) { io.print(`Nothing changed: ${args.key} was not set, so the deploy's default already holds.`); return 1 }
  io.print(`Recorded setting ${args.key} ${args.value ?? "--default"}.`)
  return 0
}
async function operatorIo(): Promise<OperatorIo> {
  const { spawnSync } = await import("node:child_process")
  const { createInterface } = await import("node:readline/promises")
  const run = (args: string[]) => {
    const result = spawnSync("bunx",["wrangler",...args],{ cwd: import.meta.dirname + "/..",encoding: "utf8",stdio: ["ignore","pipe","inherit"] })
    if (result.status !== 0) throw new Error("Operator command failed; inspect the database before retrying.")
    return JSON.parse(result.stdout) as unknown
  }
  async function query<T>(target: OperatorTarget,statements: string[]): Promise<T[]> {
    const result = run(["d1","execute",target.database,...target.flags,"--json","--command",statements.join(";\n")]) as { success?: boolean; results?: T[] }[]
    if (result.length !== statements.length || result.some(r => r.success !== true)) throw new Error("D1 did not confirm the operator statements.")
    return result[0]?.results ?? []
  }
  return {
    query: (target,sql) => query(target,[sql]),update: (target,statements) => query(target,statements),
    async bookmark(target) {
      if (target.kind === "local") return "local database, no time travel"
      const result = run(["d1","time-travel","info",target.database,"--json"]) as { bookmark?: unknown }
      if (typeof result.bookmark !== "string") throw new Error("D1 gave no bookmark.")
      return result.bookmark
    },
    print: line => console.log(line),async ask(prompt) { if (!process.stdin.isTTY) return null; const rl = createInterface({ input: process.stdin,output: process.stdout }); try { return await rl.question(prompt) } finally { rl.close() } },
  }
}
if ((import.meta as { main?: boolean }).main) {
  const argv = process.argv.slice(2)
  try {
    if (argv[1] === "setting") {
      const { readFile } = await import("node:fs/promises")
      process.exitCode = await runOperatorSetting(parseOperatorSettingArgs(argv),await operatorIo(),await readFile(`${import.meta.dirname}/../wrangler.jsonc`,"utf8"))
    } else process.exitCode = await runOperator(parseOperatorArgs(argv),await operatorIo())
  }
  catch (error) { console.error(error instanceof Error ? error.message : "Operator command failed."); process.exitCode = 1 }
}
