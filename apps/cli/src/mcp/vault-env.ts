import { isAbsolute } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import { z } from "zod"
import { CliError, usageError } from "../errors.ts"
import { boundCheckoutRefusal } from "../run/bound-project.ts"
import { manifestWorkspace } from "../run/manifest.ts"
import { READS, WORKSPACE_ARG, outputSchema, plain, tool } from "./shared.ts"

// Collects what a src/run command writes, for a tool result.
class TextCapture {
  private readonly decoder = new TextDecoder()
  private buffer = ""

  write(chunk: string | Uint8Array): boolean {
    this.buffer += typeof chunk === "string" ? chunk : this.decoder.decode(chunk, { stream: true })
    return true
  }

  text(): string {
    return this.buffer
  }

  lines(): string[] {
    return this.buffer.split("\n").filter((line) => line.trim())
  }
}

export const vaultEnv = tool({
  name: "vault_env",
  title: "Check project variables",
  description:
    "How each variable a project declares in mehen.toml resolves for an environment (a vault item, a plain value, or unset), as `mehen env ls` prints it. Never returns values. With check, fails when any variable does not resolve.",
  input: z.object({
    env: z.string().optional().describe("environment name; the project's default when absent"),
    cwd: z.string().optional().describe("absolute path inside the project; where mehen mcp runs when absent"),
    check: z.boolean().optional().describe("fail unless every declared variable resolves"),
    workspace: WORKSPACE_ARG,
  }),
  annotations: READS,
  output: outputSchema({ exitCode: "integer", variables: "array", context: "array" }),
  async call(args, deps) {
    if (args.cwd !== undefined && !isAbsolute(args.cwd)) throw usageError("cwd must be an absolute path.")
    // The call's own checkout decides: its manifest resolves
    // inside the ceiling or refuses, an unbound one under several workspaces
    // is workspace_unbound, and a workspace argument or pin must agree with
    // it. All before any signer, network call or session.
    const cwd = args.cwd ?? process.cwd()
    const manifest = manifestWorkspace(cwd)
    const { api, config, vaultUrl } = await deps.session(args.workspace, { manifest, strict: true })
    // A checkout with no mehen.toml whose remote is already a project: the
    // step to bind it, as a next the agent follows. A lookup that fails
    // leaves mehen env's own no mehen.toml refusal standing.
    const unbound = manifest === null ? await boundCheckoutRefusal(api, cwd).catch(() => null) : null
    if (unbound !== null) throw new CliError("command_failed", unbound.message, unbound.next)
    const { envCommand } = await import("../run/index.ts")
    const stdout = new TextCapture()
    const stderr = new TextCapture()
    const argv = [args.check ? "check" : "ls", ...(args.env ? ["--env", args.env] : [])]
    const exitCode = await envCommand(argv, { api, config: { ...config, vault: vaultUrl }, stdout, stderr, env: deps.env, ...(args.cwd ? { cwd: args.cwd } : {}) })
    if (exitCode !== EXIT.ok) {
      throw new CliError("command_failed", stderr.text().trim() || `mehen env ${argv[0]} failed with exit ${exitCode}.`, {
        say: "Read the message: it names the variables or the mehen.toml problem and what to run next.",
      })
    }
    return plain({ exitCode, variables: stdout.lines(), context: stderr.lines() })
  },
})
