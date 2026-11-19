import { z } from "zod"
import { fill } from "../browser/fill.ts"
import { fetchContext } from "../operations.ts"
import { type ToolOutput, WORKSPACE_ARG, plain, tool } from "./shared.ts"

const HELP = "vault_fill"

export const vaultFill = tool({
  name: "vault_fill",
  title: "Type a credential into a web page",
  description:
    "Type one field of an item into one field of the page your browser shows, after mehen checks in the page that the selector names exactly one visible field of the right kind on an https page of its own origin alone. The vault decides whether this machine may fill that page; mehen never returns the value. " +
    "With submit, mehen presses Enter in the field and waits up to 10 s for the page to go, else empties the field and fails with not_submitted. A refusal is an error with `next`; when a human must approve, it also carries `ask` and a link: hand them over, call vault_wait with the id, then fill again with approval.",
  input: z.object({
    item: z.string().describe("the item to type from"),
    field: z.string().describe("the item's field: username, password or totp for a password-login, code for a totp item, key for an api-key, token for a bearer-token, value for a generic item"),
    cdp: z.string().describe("the browser's own DevTools endpoint: ws://127.0.0.1:<port>/devtools/browser/<id>, http://127.0.0.1:<port>, or a wss:// URL"),
    target: z.string().optional().describe("the target id of the page to fill; needed when the browser has more than one page"),
    selector: z.string().describe("the CSS selector of the one field to type into; ' >>> ' steps into an open shadow root"),
    submit: z.boolean().optional().describe("press Enter in the field after typing and wait for the page to go"),
    context: z.object({ project: z.string().describe("the project id (prj_...)"), environment: z.string().describe("the environment name") }).optional().describe("the project environment the credential is used for; needed for a protected, team or guest credential. Never changes the workspace."),
    approval: z.string().optional().describe("an approved apr_ id, when filling again after an approval"),
    workspace: WORKSPACE_ARG,
  }),
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  async call(args, deps, call): Promise<ToolOutput> {
    const result = await fill(
      {
        item: args.item,
        field: args.field,
        selector: args.selector,
        submit: args.submit ?? false,
        source: { cdp: args.cdp },
        target: args.target ?? null,
        context: args.context ? fetchContext(args.context.project, args.context.environment, HELP) : null,
        approval: args.approval ?? null,
        help: HELP,
      },
      {
        async vault() {
          const session = await deps.session(args.workspace)
          return { api: session.api, workspace: session.config.tenant }
        },
        signal: call.signal,
      },
    )
    return plain(result)
  },
})
