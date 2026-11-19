import { withContext } from "../ask.ts"
import { z } from "zod"
import { checkedLink, connectAskFor, connectNext, intakeNext, nextFor, recordAsk, requestAsk } from "../commands/intake.ts"
import { type ConnectInput, type IntakeInput, chooseOauthClient, clientRequestReason, connectCommandText, createConnect, knownOauthProvider, missingClientError, privateHomeUnavailable, resolveHome, withPrivateHomeExplained } from "../operations.ts"
import { sessionLabel } from "../session.ts"
import { WORKSPACE_ARG, handing, manifestProject, mcpThen, tool } from "./shared.ts"

export const vaultConnect = tool({
  name: "vault_connect",
  title: "Ask to connect an OAuth account",
  description:
    "Ask a human to connect an OAuth account (for example Gmail). Returns `ask`: a link the human opens to sign in at the provider; the tokens go into the vault, never to you. Hand the link over, then call vault_wait with the connection id. " +
    "Needs an oauth-client item for the provider: name it with `client`, or leave `client` out to use the one that exists. With none, the result is the `client_missing` error whose `request` is exactly the vault_request arguments for the client; " +
    "or set `requestClient` to have the vault ask for the client first: the result is then that intake's `ask` with `step: \"client\"`; vault_wait for it, then call vault_connect again with the same arguments for the connection link.",
  input: z.object({
    provider: z.string().describe("OAuth provider, e.g. google-gmail (vault_templates lists them)"),
    client: z.string().optional().describe("the oauth-client item to use; when absent, the one client made from the provider's client template"),
    name: z.string().describe("slug for the connection item"),
    reason: z.string().describe("why you need it; the human sees this"),
    scopes: z.array(z.string()).optional(),
    expect: z.string().optional().describe("the account the human should sign in as"),
    requestClient: z.boolean().optional().describe("when no client exists, ask the human for one first (an intake chained to this connection)"),
    clientTags: z.array(z.string()).optional().describe("with requestClient: the tags the new client gets, so a tag-scoped machine may use it"),
    new: z.boolean().optional().describe("make a fresh link and close this machine's open one for the same name"),
    home: z.enum(["private", "project", "workspace"]).optional().describe("who the connection belongs to, as vault_request's home; with scope.privateCredentials false, project or workspace"),
    project: z.string().optional().describe("with home project: the project id (prj_...)"),
    workspace: WORKSPACE_ARG,
  }),
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  async call(args, deps) {
    const now = new Date()
    const { api, vaultUrl, configDir: dir, ledger: scope, context, config } = await deps.session(args.workspace)
    const home = resolveHome({ home: args.home ?? null, project: args.project ?? null, manifestProject: manifestProject(deps.server, config), help: "vault_connect" })
    const provider = knownOauthProvider(args.provider)
    const input: ConnectInput & { name: string } = {
      provider: provider.id,
      client: args.client ?? null,
      name: args.name,
      home,
      reason: args.reason,
      scopes: args.scopes ?? [],
      expect: args.expect ?? null,
      session: sessionLabel(deps.env),
      requestClient: args.requestClient ?? false,
      ...(args.clientTags?.length ? { clientTags: args.clientTags } : {}),
      ...(args.new ? { fresh: true } : {}),
    }
    if (!input.client) {
      const choice = await chooseOauthClient(api, provider)
      if (choice) {
        input.client = choice.client
        input.requestClient = false
      } else if (!input.requestClient) {
        throw missingClientError({ provider, name: input.name, expect: input.expect, reason: args.reason, vaultUrl, home })
      }
    }
    const created = await withPrivateHomeExplained(api, home, () => privateHomeUnavailable("mcp", null, args.home === undefined), () => createConnect(api, input))
    const link = checkedLink(created.url, "connect", created.connect, scope)
    const ask = withContext(connectAskFor({ link, input, expiresAt: created.expiresAt, env: deps.env, machineName: config.name ?? null }), context)
    const next = nextFor(ask, link, connectNext, now)
    const command = connectCommandText(input)
    if (ask) await recordAsk(dir, scope, ask, input.name, command, now)
    const client = input.client ?? provider.clientTemplate
    // The chained case (V-4): the vault made a client intake first, and the
    // connection link starts once that intake has saved the client. The
    // agent waits for the intake, then calls vault_connect again.
    if (created.intake) {
      const clientLink = checkedLink(created.intake.url, "intake", created.intake.intake, scope)
      const clientInput: IntakeInput = { kind: "oauth-client", name: client, provider: provider.clientTemplate, reason: clientRequestReason({ provider, expect: input.expect, reason: args.reason }), tags: input.clientTags ?? [], hosts: [], paths: [], injection: null, session: input.session, home }
      const clientAsk = withContext(requestAsk({ link: clientLink, input: clientInput, expiresAt: created.intake.expiresAt, vaultUrl, env: deps.env, machineName: config.name ?? null }), context)
      const clientNext = nextFor(clientAsk, clientLink, intakeNext, now)
      if (clientAsk) await recordAsk(dir, scope, clientAsk, client, command, now)
      const then = clientAsk?.wait ? `${mcpThen(clientAsk)}, then vault_connect again with the same arguments` : null
      return handing(
        {
          step: "client",
          ...created.intake,
          url: clientLink.url,
          connect: created.connect,
          provider: provider.id,
          client,
          name: input.name,
          ...(clientAsk ? { ask: clientAsk } : {}),
          next: clientNext,
          then: "Once vault_wait says the client intake is completed, call vault_connect again with the same arguments: it returns the connection link for the human.",
          ...(clientLink.warning ? { warning: clientLink.warning } : {}),
        },
        clientAsk,
        clientLink.warning,
        then,
      )
    }
    return handing(
      { connect: created.connect, url: link.url, expiresAt: created.expiresAt, provider: provider.id, client, name: input.name, ...(input.expect ? { account: input.expect } : {}), ...(ask ? { ask } : {}), next, ...(link.warning ? { warning: link.warning } : {}) },
      ask,
      link.warning,
    )
  },
})
