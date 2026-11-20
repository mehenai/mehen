import { describe, expect, test } from "bun:test"
import { CliError, DEFAULT_NEXT } from "../errors.ts"
import { pinMismatch } from "./binding.ts"
import { TOOL_SCHEMA_NEXT, toolCall, toolFlags, toolNext, toolSay } from "./tool-next.ts"

describe("toolCall", () => {
  test("names the tool and carries the one value over where the tool takes it", () => {
    expect(toolCall("mehen ls", false)).toBe("vault_list")
    expect(toolCall("mehen status --json", false)).toBe("vault_status")
    expect(toolCall("mehen doctor --json", false)).toBe("vault_doctor")
    expect(toolCall("mehen pending", false)).toBe("vault_pending")
    expect(toolCall("mehen wait apr_1", false)).toBe('vault_wait { "id": "apr_1" }')
    expect(toolCall("mehen wait int_7 --timeout 60 --json", false)).toBe('vault_wait { "id": "int_7" }')
    expect(toolCall("mehen show openai-personal", false)).toBe('vault_show { "item": "openai-personal" }')
    expect(toolCall("mehen show <item>", false)).toBe('vault_show { "item": "<item>" }')
    expect(toolCall("mehen templates google-gmail --json", false)).toBe('vault_templates { "id": "google-gmail" }')
    expect(toolCall("mehen mandate ls", false)).toBe('vault_mandate { "action": "list" }')
    expect(toolCall("mehen mandate show mdt_1", false)).toBe('vault_mandate { "action": "show", "id": "mdt_1" }')
    expect(toolCall("mehen mandate pause mdt_1", false)).toBe('vault_mandate { "action": "pause", "id": "mdt_1" }')
    expect(toolCall("mehen policy show openai-personal", false)).toBe('vault_policy { "action": "show", "item": "openai-personal" }')
    expect(toolCall("mehen adopt status adp_1", false)).toBe('vault_adopt_status { "adoption": "adp_1" }')
    expect(toolCall("mehen adopt scan", false)).toBe("vault_adopt_scan")
    expect(toolCall("mehen workspace list", false)).toBe("vault_status")
  })

  test("keeps a placeholder in the arguments, so the action it goes with is kept", () => {
    expect(toolCall("mehen mandate pause <mdt_id>", false)).toBe('vault_mandate { "action": "pause", "id": "<mdt_id>" }')
    expect(toolCall("mehen policy show <item>", false)).toBe('vault_policy { "action": "show", "item": "<item>" }')
    expect(toolSay("Pause each with `mehen mandate pause <mdt_id>`.")).toBe('Pause each with `vault_mandate { "action": "pause", "id": "<mdt_id>" }`.')
  })

  test("takes a command with flags of its own as the tool by name only when loose", () => {
    expect(toolCall('mehen request api-key --name openai-new --reason "tests"', true)).toBe("vault_request")
    expect(toolCall("mehen policy propose --from <apr_id> --reason <why>", true)).toBe("vault_policy")
    expect(toolCall("mehen request --help", true)).toBe("vault_request")
    expect(toolCall("mehen fetch -o <file>", false)).toBeNull()
  })

  test("is null for what only the command line does", () => {
    for (const command of ["mehen enrol --workspace <slug> --json", "mehen update", "mehen update --json", "mehen run -- npm test", "mehen env set OPENAI_API_KEY", "mehen init", "mehen workspace bind", "mehen workspace forget --slot /x", "mehen adopt plan", "mehen setup --json", "mehen revoke --workspace a", "mehen backup restore", "mehen ls\u001b[2J"]) {
      expect(toolCall(command, true)).toBeNull()
    }
  })
})

describe("toolNext", () => {
  const error = (command: string | undefined, say: string, code: "not_found" | "forbidden" | "usage" | "approval_required" | "cli_outdated" = "not_found") => new CliError(code, "No.", command === undefined ? { say } : { command, say })

  test("a step a tool does is the tool call in next.tool and next.arguments, the command dropped and the say left for the human", () => {
    const listed = toolNext(error("mehen ls", "Check the name with `mehen ls`; ask for a missing credential with `mehen request`."), "vault_mandate")
    expect(listed.next).toEqual({ say: "Check the name with `vault_list`; ask for a missing credential with `vault_request`.", tool: "vault_list" })
    const status = toolNext(error("mehen status", "Tell the human.", "forbidden"), "vault_fetch")
    expect(status.next).toEqual({ say: "Tell the human.", tool: "vault_status" })
    const wait = toolNext(new CliError("approval_required", "Held.", { url: "https://vault.example/a/apr_1", command: "mehen wait apr_1", say: "Relay the link." }), "vault_fetch")
    expect(wait.next).toEqual({ url: "https://vault.example/a/apr_1", say: "Relay the link.", tool: "vault_wait", arguments: { id: "apr_1" } })
  })

  test("a placeholder stays in next.arguments, which are then partial", () => {
    const several = toolNext(new CliError("conflict", "Two live mandates.", { command: "mehen mandate pause <mdt_id>", say: "Pause each one." }), "vault_mandate")
    expect(several.next).toEqual({ say: "Pause each one.", tool: "vault_mandate", arguments: { action: "pause", id: "<mdt_id>" } })
  })

  test("a workspace to name is the same tool's workspace argument", () => {
    const named = toolNext(new CliError("context_ambiguous", "Which one?", { command: "mehen --workspace acme", say: "Name the checkout's workspace." }), "vault_show")
    expect(named.next).toEqual({ say: "Name the checkout's workspace.", tool: "vault_show", arguments: { workspace: "acme" } })
  })

  test("a step only the command line takes keeps its command, names no tool and leaves the say as it was", () => {
    const update = toolNext(error("mehen update", "Update mehen.", "cli_outdated"), "vault_fetch")
    expect(update.next).toEqual({ command: "mehen update", say: "Update mehen." })
    const enrol = toolNext(error("mehen enrol --workspace <slug> --json", "If you cannot run commands, ask the human to run this in a terminal."), "vault_list")
    expect(enrol.next).toEqual({ command: "mehen enrol --workspace <slug> --json", say: "If you cannot run commands, ask the human to run this in a terminal." })
  })

  test("no say gains a tool call or a line about the command line", () => {
    for (const [code, next] of Object.entries(DEFAULT_NEXT)) {
      const mapped = toolNext(new CliError(code as "not_found", "No.", next), "vault_fetch").next
      expect(mapped?.say).not.toContain("Call `")
      expect(mapped?.say).not.toContain("Only the mehen command line")
    }
  })

  test("a usage error's --help is the tool's input schema", () => {
    expect(toolNext(error("mehen ls --help", "Check the usage with `mehen ls --help`.", "usage"), "vault_list").next).toEqual({ say: "Fix the arguments to match the tool's input schema." })
  })

  test("no default next step keeps a command a tool does, or names one in its say", () => {
    for (const [code, next] of Object.entries(DEFAULT_NEXT)) {
      const mapped = toolNext(new CliError(code as "not_found", "No.", next), "vault_fetch").next
      if (mapped?.command !== undefined) expect(toolCall(mapped.command, true)).toBeNull()
      for (const [, command] of (mapped?.say ?? "").matchAll(/`(mehen [^`]+)`/g)) expect(toolCall(command ?? "", false)).toBeNull()
    }
  })

  test("a flag a say names is the argument of the tool the error came through, and one the tool lacks stays", () => {
    const several = new CliError("usage", "Several clients.", { command: "mehen connect google-gmail --client gmail-a ...", say: "Pick one of gmail-a, gmail-b with --client." })
    expect(toolNext(several, "vault_connect").next?.say).toStartWith("Pick one of gmail-a, gmail-b with `client`.")
    expect(toolFlags("or repeat it with --request-client to ask for both at once.", "vault_connect")).toBe("or repeat it with `requestClient` to ask for both at once.")
    expect(toolFlags("Check whether it took effect, or give --max-time more time.", "vault_fetch")).toBe("Check whether it took effect, or give `timeoutSeconds` more time.")
    expect(toolFlags("Name one with --workspace <slug>; `mehen workspace list --json` shows them.", "vault_show")).toBe("Name one with `workspace` <slug>; `mehen workspace list --json` shows them.")
    expect(toolFlags("Use an unprotected one, or run with a literal --env <name>.", "vault_fetch")).toBe("Use an unprotected one, or run with a literal --env <name>.")
  })

  test("a flag of a mehen or mcp command written in the same clause stays the command's flag", () => {
    expect(toolFlags("without MEHEN_WORKSPACE (or mcp --workspace) to use several workspaces.", "vault_fetch")).toBe("without MEHEN_WORKSPACE (or mcp --workspace) to use several workspaces.")
    expect(toolFlags("set requestClient: true (mehen connect --request-client) to ask a human for one.", "vault_connect")).toBe("set requestClient: true (mehen connect --request-client) to ask a human for one.")
    const pinned = pinMismatch({ text: "acme", vault: "https://vault.example", tenant: "ten_1" }, "other")
    expect(toolNext(pinned, "vault_fetch").next?.say).toBe("Leave workspace out of the call, or have the harness start the server without MEHEN_WORKSPACE (or `mehen mcp --workspace`) to use several workspaces.")
    const clientMissing = "Ask a human for the Gmail OAuth client first, or repeat the connect with requestClient: true to ask for both at once."
    const missing = new CliError("bad_request", "No client.", { command: "mehen request oauth-client --name gmail-client --provider google-oauth-client --reason mail", say: clientMissing })
    expect(toolNext(missing, "vault_connect").next).toEqual({ say: clientMissing, tool: "vault_request" })
  })

  test("the vault's bad_request without its own step is the tool's input schema", () => {
    expect(toolNext(new CliError("bad_request", "Bad.", DEFAULT_NEXT.bad_request), "vault_fetch").next).toEqual(TOOL_SCHEMA_NEXT)
    const own = { say: "Send the body as JSON." }
    expect(toolNext(new CliError("bad_request", "Bad.", own), "vault_fetch").next).toEqual(own)
  })

  // A tool outside the server's toolsets is no step an agent can take there:
  // its command stays, as a step only the command line takes.
  test("a step whose tool this server does not serve keeps its command and names no tool", () => {
    const core = (name: string) => ["vault_status", "vault_list", "vault_request", "vault_fetch", "vault_env", "vault_wait"].includes(name)
    const doctor = toolNext(error("mehen doctor --json", "Run `mehen doctor` to find out why; then `mehen ls`."), "vault_fetch", core)
    expect(doctor.next).toEqual({ command: "mehen doctor --json", say: "Run `mehen doctor` to find out why; then `vault_list`." })
    const templates = toolNext(error("mehen templates", "List them."), "vault_request", core)
    expect(templates.next).toEqual({ command: "mehen templates", say: "List them." })
    const wait = toolNext(error("mehen wait apr_1", "Wait."), "vault_fetch", core)
    expect(wait.next).toEqual({ say: "Wait.", tool: "vault_wait", arguments: { id: "apr_1" } })
    expect(toolSay("Use `mehen show <item>` or `mehen ls`.", core)).toBe("Use `mehen show <item>` or `vault_list`.")
  })

  test("toolSay leaves a command with flags no tool takes", () => {
    expect(toolSay("Use `mehen fetch -o <file>` or `mehen run`.")).toBe("Use `mehen fetch -o <file>` or `mehen run`.")
    expect(toolSay("Use `mehen fetch` or `mehen run`.")).toBe("Use `vault_fetch` or `mehen run`.")
  })
})
