---
title: The mehen command line
question: What does each command do, and what are its flags, variables and exit codes?
section: reference
covers: both
order: 10
generate: cli
---

# The mehen command line

`mehen` is the command line on every machine an agent works from, and `mehen mcp` serves the core operations as [MCP tools](mcp.md); their inputs, output shapes, timeouts and body limits differ where those pages say so. No command and no tool returns a secret value, except the real values a human allowed into a `mehen run` child, which go to that child only. The command sections below are generated from the command table `mehen` itself is built from, so they match `mehen <command> --help` for the version in the footer.

## By task

| Task | CLI | MCP tool |
| --- | --- | --- |
| Set up Mehen on this machine, with a local vault | `mehen up` (run it again to resume; `--remove` stops the vault) | |
| Run a vault other machines reach | `mehen serve --origin https://<name>` | |
| Keep agents away from key files | `mehen guard install`; `mehen guard block\|warn\|off` | |
| Which workspaces is this machine in? | `mehen status` | `vault_status` |
| Why is it not working? | `mehen doctor` | `vault_doctor` |
| Enrol it in a workspace | `mehen enrol --workspace <slug>` (prints the ask and exits), then `mehen wait enr_...` | `vault_wait` (to finish) |
| Register Mehen with the agents on this machine | `mehen setup` (`--remove` undoes it) | |
| Revoke this machine in one workspace | `mehen revoke --workspace <slug>` | |
| Which workspace does this checkout use? | `mehen workspace show` | |
| Bind a checkout to its project | `mehen init` | |
| Is `mehen` current? | `mehen update --check --json` (a release build with a trusted key updates itself) | |
| What may I name as a provider? | `mehen templates [<id>]` | `vault_templates` |
| Start a template for a new service (in a checkout of the repository) | `mehen templates new <id> --host <host> --category <category>` | |
| What credentials exist? | `mehen ls` | `vault_list` |
| Is this key set and right? | `mehen show <slug>` | `vault_show` |
| Will this request be allowed? | `mehen check <slug> <METHOD> <url>` | `vault_check` |
| Ask a human for a new credential | `mehen request <kind> --name <slug> --provider <template> --reason <why> [--home private\|project\|workspace]` | `vault_request` |
| Connect an OAuth account | `mehen connect <provider> --name <slug> --reason <why> [--expect <account>] [--request-client]` | `vault_connect` |
| Wait for an intake, connection, approval, enrolment, rule proposal, adoption, bundle or mandate proposal | `mehen wait <id>` (`int_`, `con_`, `apr_`, `enr_`, `pol_`, `adp_`, `bnd_`, `mdp_`) | `vault_wait` |
| Which links are still open? | `mehen pending [<id>]` | `vault_pending` |
| Call an HTTP API | `mehen fetch <slug> <METHOD> <url> [--project <prj_id> --env <name>]` | `vault_fetch` |
| Ask for several writes at once | `mehen plan submit <plan.json>`, then `mehen wait bnd_...`; `mehen check --plan <plan.json>` checks one first | `vault_plan` |
| Stop the same ask coming back | `mehen policy propose --from apr_... --reason <why>` (a standing rule), or with `--item <slug> --area <area>` (a task grant) | `vault_policy` |
| Let a machine carry on without asking | `mehen mandate propose --classes <classes> --items <slugs> --note <why>`; `mehen mandate ls`, `pause` | `vault_mandate` |
| Type a credential into a web page | `mehen fill <slug>#<field> --cdp <url> --selector <css> [--submit]` | `vault_fill` |
| Put a secret into GitHub, Vercel or Cloudflare | `mehen push <slug>[#<field>] --to <destination> [--with <slug>] --reason <why>`, then `mehen wait apr_...` | `vault_push`, then `vault_wait` |
| Bring the keys already on this machine in | `mehen adopt scan`, `plan`, `submit`, then `mehen wait adp_...` and `mehen adopt apply` | `vault_adopt_scan`, `vault_adopt_status` |
| Keep your own encrypted copies | `mehen backup snapshot`, `export`, `status` | |
| Run a project command | `mehen run [--env <name>] -- <cmd>` ([which programs work](../guides/run-compatibility.md)) | |
| Check a project's variables | `mehen env check` | `vault_env` with `check` |
| Which workloads does this machine have, and end one | `mehen workload ls`, `mehen workload revoke <wl_id>` (a harness creates them with `@mehen/client`) | |
| Pull the brake | `mehen freeze` | |
| The short guide | `mehen guide` | |

## Output and `--json`

`--json` works on every command except `mehen run`, `mehen env set` and `mehen mcp`. With it, results go to stdout as one JSON object per line, and errors go to stdout as an error object (see [Errors and exit codes](errors.md)). Without it, results go to stdout and anything meant for a person reading along goes to stderr. Use `--json` whenever a program reads the output; it may also come before the command (`mehen --json status`).

The standard commands accept `--no-qr`, which turns off the terminal QR code for one run; `mehen mcp`, `mehen run`, `mehen env` and `mehen init` do not, so set `MEHEN_QR=0` when a run's approval block must not draw one. `--workspace <slug or id>` is accepted by every command, before or after it, and picks which of this machine's enrolments acts ([Several workspaces on one machine](../guides/several-workspaces.md)). `mehen run --help`, `mehen env --help` and `mehen init --help` print the usage and exit 0.

`--timeout` on `wait`, `request`, `connect` and `enrol --wait` takes `0` (check once), a number of seconds, or `30s`, `10m`, `2h`, up to 24 hours. The default is 10 minutes.

## Environment variables

The variables `mehen` reads:

| Variable | Meaning |
| --- | --- |
| `MEHEN_SESSION` | A label for your session (1 to 120 letters, digits, `.`, `:`, `_` or `-`), shown to the human in the details of intake, connect and approval pages and written to the audit log. Set it; a harness that draws cards from your calls usually sets it for you. It grants nothing. |
| `MEHEN_ENV` | Picks an unprotected environment for `mehen run` and `mehen env` when there is no `--env`. Never a protected one. |
| `MEHEN_VAULT_URL` | The vault to enrol with when it is not `https://app.mehen.dev`. Once a workspace is selected, a value naming another origin is `workspace_mismatch`. |
| `MEHEN_HOME` | Where this machine's Mehen state lives: one directory per workspace under it, with its config, device key, key scope and ledger. Default `~/.config/mehen`. A different `MEHEN_HOME` is a different machine to the vault. Set by the harness or the human; leave it as it is. |
| `MEHEN_WORKSPACES` | Which workspaces this agent may use, comma-separated slugs or `tn_` ids; unset means all. It only narrows: anything outside is `workspace_not_allowed`. Set by the harness; only the human widens it. |
| `MEHEN_WORKSPACE` | The same as `--workspace <slug or id>`: which workspace acts. |
| `MEHEN_MANAGED_CONTEXT` | Set by an agent launcher on a managed host, with the pinned workspace directory; never set it yourself. |
| `MEHEN_NO_AUTO_UPDATE` | `1` switches off the background update, the automatic update when the vault asks for a newer `mehen`, and a running `mehen mcp` switching to a newer one in place. |
| `MEHEN_GUARD` | `block`, `warn` or `off`: what the guard hooks do in this process, over the level `mehen guard` saved. |
| `MEHEN_BROWSER` | The program `mehen up` opens links with, given the link as its only argument; `none` opens nothing and prints the link. |
| `MEHEN_SERVICE` | `launchd`, `systemd` or `process`: how `mehen up` keeps the vault running, instead of the one it picks for this machine. |
| `MEHEN_SERVE_PORT`, `MEHEN_SERVE_DATA` | The port and data folder for `mehen serve` and `mehen up` when `--port` and `--data` are not given. |
| `MEHEN_SERVE_ORIGIN`, `MEHEN_SERVE_HOST` | The `--origin` and `--bind` for `mehen serve` when the flags are not given. `mehen up` ignores both: its vault is on this machine's loopback. |
| `MEHEN_RUN_STREAM_WRITES` | `1` does what `mehen run --stream-writes` does: the local relay passes every write's answer on as it comes instead of reading it in full first. Turn the program's transport retries off for those writes. |
| `MEHEN_QR` | `0` turns the terminal QR code off; `light` or `dark` picks its colours when the terminal does not say. |
| `NO_COLOR`, `FORCE_COLOR`, `TERM` | Colour is used only on a terminal, never with `NO_COLOR` set or `TERM=dumb`; `FORCE_COLOR` forces it on. Colour never carries meaning on its own. |
