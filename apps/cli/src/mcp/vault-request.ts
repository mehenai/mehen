import { withContext } from "../ask.ts"
import { InjectionSchema, KindSchema } from "@mehen/protocol/api"
import { z } from "zod"
import { checkedLink, intakeNext, nextFor, recordAsk, requestAsk } from "../commands/intake.ts"
import { type IntakeInput, privateHomeUnavailable, requestCommandText, requestIntake, resolveHome, withPrivateHomeExplained } from "../operations.ts"
import { sessionLabel } from "../session.ts"
import { WORKSPACE_ARG, handing, manifestProject, tool } from "./shared.ts"

const requestInput = z.object({
  kind: KindSchema.describe("what sort of credential"),
  name: z.string().describe("slug for the new item, e.g. openai-personal"),
  reason: z.string().describe("why you need it; the human sees this"),
  provider: z.string().optional().describe("provider template id, e.g. openai, anthropic, github-pat"),
  tags: z.array(z.string()).optional(),
  hosts: z.array(z.string()).optional().describe("without a provider: hosts it may go to, e.g. api.example.com"),
  paths: z.array(z.string()).optional().describe("without a provider: path globs, e.g. /v1/**"),
  injection: InjectionSchema.optional().describe('without a provider: how it goes into a request, e.g. { "in": "header", "name": "X-Api-Key", "format": "{key}" }'),
  new: z.boolean().optional().describe("a fresh link, closing your open one for the name; else the same request gets the same link"),
  home: z.enum(["private", "project", "workspace"]).optional().describe("who it belongs to: private (only its owner; the default), project (needs project, or the startup checkout's) or workspace; the human may change it. With vault_status scope.privateCredentials false, pass project or workspace."),
  project: z.string().optional().describe("with home project: the project id (prj_...)"),
  workspace: WORKSPACE_ARG,
})

// injection as one flat object rather than its four shapes, which would be
// a quarter of the default tool list; input still parses the exact shape.
const advertised = requestInput.extend({
  injection: z
    .object({ in: z.enum(["header", "query", "basic", "headers"]), name: z.string().optional(), format: z.string().optional(), field: z.string().optional(), username: z.string().optional(), password: z.string().optional() })
    .optional()
    .describe('without a provider: how it goes in: header (name, format such as "Bearer {key}"), query (name, field), basic (username, password) or headers (field)'),
})

export const vaultRequest = tool({
  name: "vault_request",
  title: "Ask for a credential",
  description:
    "Ask a human to add a credential, or rotate one this machine may reach. Returns `ask`, a checked link where the human types the value into the vault page, never the chat: hand it over, then call vault_wait with the id. " +
    "Without a provider template, propose hosts (and paths) and, if Bearer in Authorization is wrong, injection; the human sees both marked unverified. Never returns the value.",
  input: requestInput,
  advertised,
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  async call(args, deps) {
    const now = new Date()
    const { api, vaultUrl, configDir: dir, ledger: scope, context, config } = await deps.session(args.workspace)
    const home = resolveHome({ home: args.home ?? null, project: args.project ?? null, manifestProject: manifestProject(deps.server, config), help: "vault_request" })
    const input: IntakeInput = {
      kind: args.kind,
      name: args.name,
      home,
      reason: args.reason,
      provider: args.provider ?? null,
      tags: args.tags ?? [],
      hosts: args.hosts ?? [],
      paths: args.paths ?? [],
      injection: args.injection ?? null,
      session: sessionLabel(deps.env),
      ...(args.new ? { fresh: true } : {}),
    }
    const created = await withPrivateHomeExplained(api, home, () => privateHomeUnavailable("mcp", null, args.home === undefined), () => requestIntake(api, input))
    // The link is handed over only through checkedLink, as mehen request does.
    const link = checkedLink(created.url, "intake", created.intake, scope)
    const ask = withContext(requestAsk({ link, input, expiresAt: created.expiresAt, vaultUrl, env: deps.env, machineName: config.name ?? null }), context)
    const next = nextFor(ask, link, intakeNext, now)
    if (ask) await recordAsk(dir, scope, ask, input.name, requestCommandText(input), now)
    return handing(
      { ...created, url: link.url, kind: input.kind, name: input.name, provider: input.provider, ...(ask ? { ask } : {}), next, ...(link.warning ? { warning: link.warning } : {}) },
      ask,
      link.warning,
    )
  },
})
