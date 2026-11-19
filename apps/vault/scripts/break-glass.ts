// Offline operator only, after out-of-band identity verification. In the
// app, recovering access to an account needs two operators (the Accounts
// view, directory/operator-account-kinds.ts), as changes to the operator
// role do; this script and
// scripts/operator.ts are the break-glass for when the app is down or every
// operator is locked out. Whoever can write D1 or deploy the Worker still
// bypasses all of it (docs/OPERATIONS.md, Operators).
// D1 stores a hash, never the link. Cron installs every workspace's security
// barrier before the script may print the one-hour, single-use link.
import { randomToken, sha256Text } from "../src/directory/session.ts"
import { spelledPrint } from "./terminal.ts"

export type Target = { kind: "remote" | "local"; database: string; origin: string; flags: string[] }
const targets: Record<Target["kind"],Target> = {
  remote: { kind: "remote",database: "mehen",origin: "https://app.mehen.dev",flags: ["--remote","--env",""] },
  local: { kind: "local",database: "mehen-local",origin: "http://localhost:8787",flags: ["--local","--env","local"] },
}
const accountId = /^acc_[A-Za-z0-9_-]{1,64}$/
const actorId = /^operator:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
export const USAGE = "Usage: bun scripts/break-glass.ts (--remote | --local) (--list | --account acc_id --actor operator:label)"
export type BreakGlassArgs = { target: Target; command: { kind: "list" } | { kind: "account"; account: string; actor: string } }
export function parseArgs(argv: string[]): BreakGlassArgs {
  if (!["--remote","--local"].includes(argv[0] ?? "")) throw new Error(USAGE)
  const target = targets[argv[0] === "--remote" ? "remote" : "local"]
  if (argv.length === 2 && argv[1] === "--list") return { target,command: { kind: "list" } }
  if (argv.length !== 5 || argv[1] !== "--account" || !accountId.test(argv[2] ?? "") || argv[3] !== "--actor" || !actorId.test(argv[4] ?? "")) throw new Error(USAGE)
  return { target,command: { kind: "account",account: argv[2]!,actor: argv[4]! } }
}
export function breakGlassStatement(account: string,actor: string,hash: string,now: number,id: string,notice: string): string {
  if (!accountId.test(account) || !actorId.test(actor) || !/^[A-Za-z0-9_-]{43}$/.test(hash) || !/^bgi_[a-f0-9]{32}$/.test(id) || !/^ntc_[a-f0-9]{32}$/.test(notice) || !Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(now+3600000)) throw new Error("Invalid break-glass intent")
  return `INSERT INTO account_break_glass_intents(id,account,actor,code_hash,notice,created_at,expires_at) VALUES ('${id}','${account}','${actor}','${hash}','${notice}',${now},${now+3600000})`
}
export type BreakGlassIo = {
  query<T>(target: Target,sql: string): Promise<T[]>
  execute(target: Target,sql: string): Promise<void>
  bookmark(target: Target): Promise<string>
  print(line: string): void
  ask(prompt: string): Promise<string | null>
  now(): number
  wait(): Promise<void>
}
export async function runBreakGlass(args: BreakGlassArgs,terminal: BreakGlassIo): Promise<number> {
  const io = spelledPrint(terminal)
  const { target,command } = args
  if (command.kind === "list") {
    const rows = await io.query<{ id: string; name: string; status: string }>(target,"SELECT id,name,status FROM accounts ORDER BY created_at,id")
    for (const row of rows) io.print(`${row.id}  ${row.name}  ${row.status}`)
    return 0
  }
  if (!accountId.test(command.account) || !actorId.test(command.actor)) throw new Error("Invalid operator target")
  const [account] = await io.query<{ id: string; name: string; status: string }>(target,`SELECT id,name,status FROM accounts WHERE id='${command.account}'`)
  if (!account || account.status !== "active" || account.id !== command.account) { io.print("Nothing changed: no active account with that id."); return 1 }
  const bookmark = await io.bookmark(target)
  if (!bookmark) throw new Error("No D1 bookmark; nothing changed.")
  io.print(`D1 bookmark before change: ${bookmark}`)
  io.print(`Break glass for ${account.name} (${account.id}) on ${target.kind} database ${target.database}, actor ${command.actor}.`)
  io.print("This ends every account passkey, session, recovery code and open operator link through the workspace security barrier. It never restores membership or bypasses Google.")
  io.print("An unavailable workspace keeps the change pending. The account is restricted until redemption, then for at least 24 hours. A D1 bookmark alone cannot undo a committed barrier.")
  if ((await io.ask(`After independently verifying this person's identity, type account id ${account.id}: `))?.trim() !== account.id) { io.print("Nothing changed: account confirmation did not match."); return 1 }
  const now = io.now(),code = randomToken(24),id = `bgi_${crypto.randomUUID().replaceAll("-","")}`,notice = `ntc_${crypto.randomUUID().replaceAll("-","")}`
  await io.execute(target,breakGlassStatement(account.id,command.actor,await sha256Text(code),now,id,notice))
  io.print(`Recorded operator intent ${id}. Waiting for cron and every workspace acknowledgement; no link is usable yet.`)
  while (io.now() < now+3600000) {
    const [row] = await io.query<{ state: string; ready: number }>(target,`SELECT i.state,EXISTS (SELECT 1 FROM account_security_transitions t JOIN accounts a ON a.id=t.account JOIN invite_codes c ON c.code_hash=i.code_hash WHERE t.id=i.transition_id AND t.state='committed' AND a.security_transition IS NULL AND a.security_epoch=t.reserved_epoch AND c.state='active' AND c.used_at IS NULL AND c.expires_at>${io.now()}) AS ready FROM account_break_glass_intents i WHERE i.id='${id}'`)
    if (row?.state === "ready" && row.ready === 1) {
      io.print("Give this link privately to the verified person. It works once, until one hour after issue, and is not shown again:")
      io.print(`${target.origin}/signup#${code}`)
      return 0
    }
    if (!row || row.state !== "pending") break
    await io.wait()
  }
  io.print("No link published. Inspect the recorded intent and pending transition; never force-clear it. An interrupted script cannot recover its code.")
  return 1
}
async function wranglerIo(): Promise<BreakGlassIo> {
  const { spawnSync } = await import("node:child_process")
  const { createInterface } = await import("node:readline/promises")
  const run = (args: string[]): unknown => {
    const result = spawnSync("bunx",["wrangler",...args],{ cwd: `${import.meta.dirname}/..`,encoding: "utf8",stdio: ["ignore","pipe","inherit"] })
    if (result.status !== 0) throw new Error("Operator command failed; inspect the intent before retrying.")
    return JSON.parse(result.stdout) as unknown
  }
  async function query<T>(target: Target,sql: string): Promise<T[]> {
    const result = run(["d1","execute",target.database,...target.flags,"--json","--command",sql]) as { success?: boolean; results?: T[] }[]
    if (result.length !== 1 || result[0]?.success !== true) throw new Error("D1 did not confirm the statement.")
    return result[0].results ?? []
  }
  return {
    query,async execute(target,sql) { await query(target,sql) },
    async bookmark(target) {
      if (target.kind === "local") return "local database, no time travel"
      const result = run(["d1","time-travel","info",target.database,"--json"]) as { bookmark?: unknown }
      if (typeof result.bookmark !== "string") throw new Error("D1 gave no bookmark.")
      return result.bookmark
    },
    print: line => console.log(line),
    async ask(prompt) { if (!process.stdin.isTTY) return null; const rl = createInterface({ input: process.stdin,output: process.stdout }); try { return await rl.question(prompt) } finally { rl.close() } },
    now: () => Date.now(),wait: () => new Promise(resolve => setTimeout(resolve,15000)),
  }
}
if ((import.meta as { main?: boolean }).main) {
  try { process.exitCode = await runBreakGlass(parseArgs(process.argv.slice(2)),await wranglerIo()) }
  catch (error) { console.error(error instanceof Error ? error.message : "Break-glass failed."); process.exitCode = 1 }
}
