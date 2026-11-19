import { withContext } from "../ask.ts"
import { InjectionSchema, KindSchema } from "@mehen/protocol/api"
import { z } from "zod"
import { checkedLink, intakeNext, nextFor, recordAsk, requestAsk } from "../commands/intake.ts"
import { type IntakeInput, privateHomeUnavailable, requestCommandText, requestIntake, resolveHome, withPrivateHomeExplained } from "../operations.ts"
import { sessionLabel } from "../session.ts"
import { WORKSPACE_ARG, handing, manifestProject, tool } from "./shared.ts"

export const vaultRequest = tool({
  name: "vault_request",
  title: "Ask for a credential",
  description:
    "Ask a human to add a credential, or to rotate an existing credential this machine may reach (name it; home and provider must match it). Returns `ask`: a checked link the human opens to type the value into the vault page (never into the chat, never to you). Hand the human the link, what it is for and what to check, then call vault_wait with the intake id. " +
    "Without a provider template, propose where it may be sent with hosts (and optionally paths), and how with injection when the kind's usual way (Bearer in Authorization) is wrong; the human sees both marked unverified. Never returns the value.",
  input: z.object({
    kind: KindSchema.describe("what sort of credential"),
    name: z.string().describe("slug for the new item, e.g. openai-personal"),
    reason: z.string().describe("why you need it; the human sees this"),
    provider: z.string().optional().describe("provider template, e.g. openai, anthropic, github-pat (vault_templates lists them)"),
    tags: z.array(z.string()).optional(),
    hosts: z.array(z.string()).optional().describe("without a provider: the hosts it may be sent to, e.g. api.example.com"),
    paths: z.array(z.string()).optional().describe("without a provider: path globs it is limited to, e.g. /v1/**"),
    injection: InjectionSchema.optional().describe('without a provider: how the relay puts it into a request, e.g. { "in": "header", "name": "X-Api-Key", "format": "{key}" }'),
    new: z.boolean().optional().describe("make a fresh link and close this machine's open one for the same name; otherwise the same request returns the same open link"),
    home: z.enum(["private", "project", "workspace"]).optional().describe("who the credential belongs to: private (only its owner; the default), project (needs project, or the project of the checkout this server started in) or workspace; the human may change it. A machine with vault_status scope.privateCredentials false cannot use private: pass project with a project the person can edit, or workspace if they are an owner or admin."),
    project: z.string().optional().describe("with home project: the project id (prj_...)"),
    workspace: WORKSPACE_ARG,
  }),
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
