// mehen fill: one field of a credential typed into one checked field of the
// page the agent's browser shows (browser/fill.ts). The value never reaches
// stdout, stderr or a file; the output says only what was typed where.

import { EXIT } from "@mehen/protocol/api"
import { type CdpSource } from "../browser/cdp.ts"
import { type FillResult, fill } from "../browser/fill.ts"
import type { Command } from "../command.ts"
import { usageError } from "../errors.ts"
import { fetchContext } from "../operations.ts"
import { printJson, printLine } from "../output.ts"
import { openSession } from "../session.ts"

const HELP = "mehen fill --help"

export function fillTarget(text: string, help: string): { item: string; field: string } {
  const hash = text.indexOf("#")
  if (hash <= 0 || hash === text.length - 1 || text.indexOf("#", hash + 1) !== -1) throw usageError(`Name the item and the field as <item>#<field>, for example github-alex#password; got ${JSON.stringify(text)}.`, help)
  return { item: text.slice(0, hash), field: text.slice(hash + 1) }
}

export function cdpSource(cdp: string | null, userDataDir: string | null, help: string): CdpSource {
  if ((cdp === null) === (userDataDir === null)) throw usageError("Give the browser as --cdp <url> or --user-data-dir <dir>, one of them.", help)
  return cdp !== null ? { cdp } : { userDataDir: userDataDir as string }
}

export function fillSummary(result: FillResult): string {
  const typed = `mehen: typed ${result.label} into ${result.origin}${result.page}`
  if (!result.submitted) return typed
  return `${typed} and submitted it${result.navigatedTo ? `; the page went to ${result.navigatedTo}` : ""}`
}

export const fillCommand: Command = {
  summary: "type a password, username, one-time code or API key into one checked field of a web page",
  spec: {
    usage: "mehen fill <item>#<field> (--cdp <url> | --user-data-dir <dir>) [--target <id>] --selector <css> [--submit] [--project <prj_id> --env <name>] [--approval apr_...]",
    flags: {
      cdp: { type: "string" },
      "user-data-dir": { type: "string" },
      target: { type: "string" },
      selector: { type: "string" },
      submit: { type: "boolean" },
      project: { type: "string" },
      env: { type: "string" },
      approval: { type: "string" },
    },
    positionals: { min: 1, max: 1 },
  },
  examples: [
    ["fill", "github-alex#password", "--cdp", "http://127.0.0.1:9222", "--selector", "#password"],
    ["fill", "github-alex#totp", "--user-data-dir", "/tmp/agent-profile", "--selector", "input[autocomplete=one-time-code]", "--submit"],
    ["fill", "github-alex#username", "--cdp", "http://127.0.0.1:9222", "--target", "8F2C51A0D3", "--selector", "login-form >>> #login"],
  ],
  notes: [
    "The browser is the agent's own, reached at its browser-level endpoint: ws://127.0.0.1:<port>/devtools/browser/<id>, http://127.0.0.1:<port>, a wss:// URL, or --user-data-dir (mehen reads DevToolsActivePort there). --target names the page when the browser has more than one.",
    "Before asking the vault, mehen checks in the page that the selector names exactly one field of the right kind, visible and usable, in a frame whose page has its own https origin alone. ' >>> ' steps into an open shadow root.",
    "The value is typed into the field and never printed. --submit presses Enter there and waits up to 10 s for the page to go; if it does not, mehen empties the field and exits with not_submitted.",
    "When a human must approve, mehen exits 3 with a link; after they approve, run mehen wait <id>, then run mehen fill again with --approval <id>.",
  ],
  async run({ args, json, env }) {
    const { item, field } = fillTarget(args.positionals[0] as string, HELP)
    const selector = args.string("selector")
    if (selector === null) throw usageError("Give --selector, the CSS selector of the one field to type into.", HELP)
    const result = await fill(
      {
        item,
        field,
        selector,
        submit: args.bool("submit"),
        source: cdpSource(args.string("cdp"), args.string("user-data-dir"), HELP),
        target: args.string("target"),
        context: fetchContext(args.string("project"), args.string("env"), HELP),
        approval: args.string("approval"),
        help: HELP,
      },
      {
        async vault() {
          const session = await openSession(env)
          return { api: session.api, workspace: session.config.tenant }
        },
      },
    )
    if (json) printJson(result)
    else printLine(fillSummary(result))
    return EXIT.ok
  },
}
