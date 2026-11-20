// mehen guide, mehen version, and the help for mehen mcp (whose options are --workspace and --toolsets).

import { mkdir } from "node:fs/promises"
import { join, resolve } from "node:path"
import { EXIT } from "@mehen/protocol/api"
import type { Command } from "../command.ts"
import { embeddedHelperPath } from "../embedded-helper.ts"
import { usageError } from "../errors.ts"
import guide from "../guide.md" with { type: "text" }
import { TOOLSETS_ENV, TOOLSET_NAMES, type Toolset, servedTools } from "../mcp/registry.ts"
import { writeHelperFile } from "../mehen-se.ts"
import { printJson, printLine } from "../output.ts"
import { BUILD_COMMIT, BUILD_KIND, VERSION } from "../version.ts"

export const GUIDE_TEXT: string = guide

// Each section of the guide as a topic `mehen guide <topic>` prints alone,
// by its heading; a test holds the two lists to each other.
export const GUIDE_TOPICS: Readonly<Record<string, string>> = {
  items: "References, not values",
  never: "Never ask for values",
  adopt: "Keys already on this machine",
  ask: "The ask block",
  request: "How to ask a human for a credential",
  approvals: "Approvals",
  "asking-less": "Asking less",
  plan: "Several writes at once",
  mandates: "Mandates",
  next: "What `next` means",
  "exit-codes": "Exit codes",
  workspaces: "Workspaces",
  enrol: "Enrolment",
  projects: "Coding projects",
  sandbox: "Sandboxed shells",
  mcp: "MCP tools and toolsets",
  updating: "Updating",
  commands: "Other commands",
}

// One topic's section: its heading line to the line before the next heading.
export function guideSection(topic: string): string {
  const title = Object.hasOwn(GUIDE_TOPICS, topic) ? GUIDE_TOPICS[topic] : undefined
  if (title === undefined) throw usageError(`mehen guide has no topic ${JSON.stringify(topic)}. The topics are ${Object.keys(GUIDE_TOPICS).join(", ")}.`, "mehen guide")
  const start = GUIDE_TEXT.indexOf(`\n## ${title}\n`) + 1
  const end = GUIDE_TEXT.indexOf("\n## ", start)
  return GUIDE_TEXT.slice(start, end === -1 ? undefined : end).trimEnd()
}

export const guideCommand: Command = {
  summary: "how agents use the vault, whole or one topic: references, intake, next, exit codes",
  spec: { usage: "mehen guide [<topic>]", flags: {}, positionals: { min: 0, max: 1 } },
  examples: [["guide"], ["guide", "exit-codes"]],
  notes: [`Topics: ${Object.keys(GUIDE_TOPICS).join(", ")}.`],
  async run({ args, json }) {
    const topic = args.positionals[0]
    const text = topic === undefined ? GUIDE_TEXT : guideSection(topic)
    if (json) printJson(topic === undefined ? { version: VERSION, guide: text } : { version: VERSION, topic, guide: text })
    else process.stdout.write(text.endsWith("\n") ? text : `${text}\n`)
    return EXIT.ok
  },
}

export const MCP_SUMMARY = "serve the vault tools over MCP on stdio"
export const MCP_USAGE = "mehen mcp [--workspace <slug or id>] [--toolsets <names>]"

const toolNames = (toolset: Toolset) => servedTools([toolset]).map((tool) => tool.name).join(", ")
const toolsetLine = TOOLSET_NAMES.filter((name) => name !== "core").map((name) => `${name} (${toolNames(name)})`)

// What mehen mcp --help prints: the tools an MCP host gets, named from the
// server's own toolsets, and how to wire it.
export const MCP_HELP = [
  `usage: ${MCP_USAGE}`,
  `  ${MCP_SUMMARY}`,
  "",
  "  Speaks MCP over stdin and stdout; a host (Claude Desktop, Cursor, pi) starts it as a command.",
  "  The tools share core operations and enforcement with the mehen commands, and never return a secret value. Their inputs, output shapes, timeouts and body limits differ: vault_fetch, for one, returns at most 256 KiB of body text.",
  `  Core tools, always served: ${toolNames("core")}.`,
  `  --toolsets <names> (or ${TOOLSETS_ENV}) adds toolsets, comma-separated: ${toolsetLine.join("; ")}. --toolsets all serves every tool. The flag decides when both are set. A call to a tool in a toolset the server does not serve is refused tool_not_served, which names the toolset.`,
  "  vault_policy proposes standing rules and task grants, which the person approves with their passkey; vault_mandate proposes a mandate, which the person signs with their passkey, and lists, follows and pauses it.",
  "  One server spans every workspace MEHEN_WORKSPACES allows under the config root (MEHEN_HOME; every one when it is unset), including one enrolled while it runs. Every tool but vault_templates takes an optional workspace (slug or id); with more than one workspace, a call names one unless the checkout's mehen.toml binds it. vault_status lists them.",
  "  --workspace (or MEHEN_WORKSPACE) pins the server to one workspace, and a call naming another is refused. A workspace's enrolment is latched on first use: if it changes on disk while the server runs, that workspace is refused until the agent restarts; the others keep working.",
  "  Enrol this machine first with mehen enrol --workspace <slug>; until it is accepted only vault_status, vault_wait (for the enr_ id mehen enrol started) and, when served, vault_doctor, vault_templates and vault_pending answer.",
].join("\n")

// What `mehen version --json` prints: build is "release" for a --release
// build, "dev" for another build and null from source; helper says whether
// this binary carries the Secure Enclave helper (darwin builds).
export type VersionInfo = { version: string; commit: string | null; build: "release" | "dev" | null; helper: "embedded" | "none" }

// `--extract-helper <dir>` is internal: the release check writes the
// embedded helper into <dir>/mehen-se and verifies it runs and is signed.
async function extractEmbeddedHelper(dir: string, json: boolean): Promise<number> {
  const embedded = await embeddedHelperPath()
  if (!embedded) throw usageError("This mehen carries no embedded Secure Enclave helper (helper: none), so there is nothing to extract.")
  const target = join(resolve(dir), "mehen-se")
  await mkdir(resolve(dir), { recursive: true, mode: 0o700 })
  await writeHelperFile(await Bun.file(embedded).bytes(), target)
  if (json) printJson({ path: target })
  else printLine(target)
  return EXIT.ok
}

export const versionCommand: Command = {
  summary: "print the mehen version and the commit it was built from",
  spec: { usage: "mehen version", flags: { "extract-helper": { type: "string" } }, positionals: { min: 0, max: 0 } },
  examples: [["version", "--json"]],
  notes: ["--json prints { version, commit, build, helper }; commit and build are null when mehen runs from source."],
  async run({ args, json }) {
    const extract = args.string("extract-helper")
    if (extract !== null) {
      if (!extract) throw usageError("--extract-helper needs a directory.")
      return extractEmbeddedHelper(extract, json)
    }
    const info: VersionInfo = { version: VERSION, commit: BUILD_COMMIT, build: BUILD_KIND, helper: (await embeddedHelperPath()) ? "embedded" : "none" }
    if (json) printJson(info)
    else process.stdout.write(`mehen ${VERSION}${BUILD_COMMIT ? ` (${BUILD_COMMIT})` : ""}\n`)
    return EXIT.ok
  },
}
