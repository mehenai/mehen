// mehen push: ask for one secret field of a credential to be put into a
// provider's secret store. A human approves every push in the vault, which
// sends the value; it never reaches this machine.

import { EXIT } from "@mehen/protocol/api"
import { type PushResult, formatPushDestination, pushDestinationWords } from "@mehen/protocol/push"
import { askForError, refusedLinkWarning } from "../ask.ts"
import type { Command } from "../command.ts"
import { toCliError, usageError } from "../errors.ts"
import { pushDestinationArgument, pushItemArgument, pushRequest, pushWords, requestPush } from "../operations.ts"
import { errorJson, note, printAsk, printJson, printLine } from "../output.ts"
import { openSession } from "../session.ts"
import { THEN_KEEPS_WAITING, runWait, timeoutSeconds } from "./intake.ts"
import { localStamp } from "./items.ts"

const HELP = "mehen push --help"

// The vault answers a result only for the same push done in the last ten
// minutes, so nothing was sent again.
export function pushResultLine(result: PushResult, timeZone?: string): string {
  return `Already put ${result.item} into ${pushWords(result.destination)}: ${result.outcome} at ${localStamp(result.at, timeZone) ?? result.at}.`
}

export const pushCommand: Command = {
  summary: "ask a human to let the vault put a credential into a GitHub, Vercel or Cloudflare secret store (the value never reaches this machine)",
  spec: {
    usage: "mehen push <item>[#<field>] --to <destination> [--with <item>] [--reason <text>] [--wait] [--timeout <duration>]",
    flags: { to: { type: "list" }, with: { type: "string" }, reason: { type: "string" }, wait: { type: "boolean" }, timeout: { type: "string" } },
    positionals: { min: 1, max: 1 },
  },
  examples: [
    ["push", "openai-prod", "--to", "github:acme/app/OPENAI_API_KEY", "--reason", "the evals workflow calls OpenAI"],
    ["push", "openai-prod#key", "--to", "github:acme/app/env/production/OPENAI_API_KEY", "--with", "github-pat-ci", "--wait"],
    ["push", "stripe-prod", "--to", "vercel:shop@acme/production/STRIPE_SECRET_KEY", "--json"],
    ["push", "resend-key", "--to", "cloudflare:0123456789abcdef0123456789abcdef/mailer/RESEND_API_KEY"],
  ],
  notes: [
    "Destinations: github:<owner>/<repo>/<NAME> (an Actions secret), github:<owner>/<repo>/env/<environment>/<NAME>, github:<owner>/<repo>/dependabot/<NAME>, vercel:<project>[@<team>]/<production|preview|development>/<NAME> and cloudflare:<account id>/<script>/<NAME>. mehen prints the destination as the vault will read it before it sends anything. One --to per push.",
    "Every push asks a human to approve it in the vault, which then sends the value itself. Exit 3 while it waits for them (relay the link, then mehen wait <apr_id>), 0 once the provider has it, 5 provider_refused when the provider refused it. --wait waits in the same process, as on mehen request.",
    "A human must first allow the credential to be put into other services' secret stores, on its page. --with names the credential that writes it (a GitHub, Vercel or Cloudflare token); without it, the one this machine may use for that provider.",
  ],
  async run({ args, json, env }) {
    const { item, field } = pushItemArgument(args.positionals[0] as string, HELP)
    const to = args.list("to")
    if (to.length === 0) throw usageError("Say where it goes with --to <destination>.", HELP)
    if (to.length > 1) throw usageError("Give one --to per push; run mehen push again for another destination.", HELP)
    const request = pushRequest({ item, field, to: pushDestinationArgument(to[0] as string, HELP), with: args.string("with"), reason: args.string("reason") }, HELP)
    const wait = args.bool("wait")
    const noQr = args.bool("no-qr")
    const timeout = timeoutSeconds(args.string("timeout"), HELP)
    const destination = formatPushDestination(request.to)
    note(`mehen: pushing ${item}${field === null ? "" : `#${field}`} to ${destination} (${pushDestinationWords(request.to)})`)
    const { api, ledger: scope } = await openSession(env)
    let result: PushResult
    try {
      result = await requestPush(api, request)
    } catch (error) {
      const failure = toCliError(error)
      if (!wait || failure.code !== "approval_required") throw failure
      const { ask, refusedLink } = askForError(failure, env, scope)
      if (!ask?.wait) throw failure
      const warning = refusedLink ? refusedLinkWarning(scope) : null
      if (json) {
        const { next } = errorJson(failure, { env, noQr, vaultUrl: scope })
        printJson({ approval: ask.id, url: ask.url, expiresAt: ask.expiresAt, item, ...(field === null ? {} : { field }), destination, bindingCode: failure.extras.bindingCode ?? null, ask, next, ...(warning ? { warning } : {}) })
      } else {
        if (warning) note(`mehen: warning: ${warning}`)
        printAsk(ask, { env, noQr, then: THEN_KEEPS_WAITING(ask.wait) })
      }
      return runWait(env, ask.id, { json, events: false, noQr, timeoutSeconds: timeout, showAsk: false })
    }
    if (json) printJson(result)
    else printLine(pushResultLine(result))
    return EXIT.ok
  },
}
