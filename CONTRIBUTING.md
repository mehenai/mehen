# Contributing to Mehen

Thank you for helping. Mehen keeps other people's keys, so the bar for a change is that it is easy to review and proves what it claims. This page says how to set up, what to run, and what a reviewer looks for.

## Setting up

You need [Bun](https://bun.sh) 1.4 and git. On macOS, building the Secure Enclave helper also needs the Xcode command line tools.

```sh
git clone https://github.com/mehenai/mehen
cd mehen
bun install --frozen-lockfile
bun run --cwd apps/vault build:ui   # the UI the vault serves
```

Run the CLI from source with `bun apps/cli/src/main.ts <command>`, and a local vault with `bun apps/cli/src/main.ts serve --data ~/.cache/mehen-dev`.

## The layout

| Folder | What it is |
| --- | --- |
| `apps/cli` | The `mehen` binary: the CLI, the MCP server, `serve`, `up`, the guard hooks, the local relay |
| `apps/vault` | The vault engine and the Cloudflare Worker that runs it as Mehen Cloud |
| `apps/local` | The same engine on one machine: SQLite storage and the local stand-ins for Cloudflare's bindings |
| `apps/web` | The site at mehen.dev and the installer |
| `apps/docs` | The docs at docs.mehen.dev, built from `docs/site` |
| `packages/protocol` | What the vault, the CLI and the client share: types, crypto, bindings, policy, provider templates |
| `packages/client` | `@mehen/client`, the SDK for platforms built on Mehen |
| `packages/brand` | Fonts and icons |

Running your own Mehen Cloud deployment (the Workers, secrets, migrations, releases, backups and keys) is in `docs/OPERATIONS.md`.

## Before you open a pull request

Run the checks for what you changed, not the whole suite; CI runs everything on every pull request.

| You changed | Run |
| --- | --- |
| Anything | `bun run typecheck` and `bun run check:dashes` |
| `packages/protocol` | `bun test packages/protocol` |
| `apps/cli` | `bun test apps/cli/src/<the folder or file>` |
| `apps/local` | `bun run --cwd apps/local test` |
| `apps/vault` | `cd apps/vault && bunx vitest run test/<the file>.test.ts` (the whole suite takes a while; run the files that cover your change) |
| `docs/site` or `apps/docs` | `bun run --cwd apps/docs check` |
| `apps/web` | `bun run --cwd apps/web check` |

CI also scans every pull request for secrets with gitleaks. A test that needs a key-shaped value uses an obviously fake one (the tests mark theirs with `SENTINEL`), and a file that must hold one is listed in `.gitleaks.toml` with the reason.

The CLI refuses a home under a folder other users can write, which Linux's `/tmp` is. If tests fail with `key_insecure`, point `TMPDIR` at a private folder: `mkdir -p ~/.cache/tmp && chmod 700 ~/.cache/tmp && export TMPDIR=~/.cache/tmp`.

## How the code is written

- TypeScript in strict mode, no `any`, `type` aliases rather than interfaces, kebab-case file names.
- British English in code, comments, messages and docs ("colour", "behaviour", "organise"). If it is not your English, write it as you would and a reviewer will fix the spelling; it never blocks a pull request.
- No em or en dashes anywhere, in code, docs or strings: use a comma, a full stop or a hyphen. Editors and AI tools put them in by themselves, so run `bun run check:dashes` before you push; CI runs the same check and it does block.
- A comment says why, never what the next line does.
- Every error says what to do next. Errors are `VaultError` in the vault and `CliError` in the CLI, with a `next` the person or agent can act on.
- No new dependency without a reason in the pull request. Mehen compiles everything it uses into one binary, and each package is code that handles keys.

## Changes that touch security

The vault engine, the local host, the relay, the protocol's crypto, bindings and policy, and anything that decides who may do what are owned by the maintainers (see `.github/CODEOWNERS`) and get a security review before they merge. For these:

- Every refusal you add gets a test that proves the refusal, not only the happy path.
- Say in the pull request what an attacker could do before and after the change.
- Never log, return, audit or put in an error message a secret value, a token, a code or a nonce.

If you think you have found a vulnerability, do not open an issue: follow [SECURITY.md](SECURITY.md).

## Adding a service

Templates tell Mehen where a service's key may go and which of its endpoints need a person's approval. The guide is [Add a service](https://docs.mehen.dev/guides/add-a-service), and the rules a reviewer checks are in `docs/INTEGRATING.md`. Start one with `bun apps/cli/src/main.ts templates new <id> --host <host> --category <category>`, which writes the template with the safe defaults, its test and its registration. Then write the rest from the provider's own documentation, link that documentation in the pull request for the host, the header and each write it allows, and keep the binding as narrow as the API allows.

## Commits and pull requests

- One change per pull request, with a title that says what it does.
- The description says why, what changed, what does not, and exactly which checks you ran.
- Keep commits readable; they are squashed on merge.

By contributing you agree that your contribution is licensed under the [Apache License 2.0](LICENSE), the licence of the project.
