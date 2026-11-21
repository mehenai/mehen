---
title: Project variables with mehen run
question: How do I give a coding project its variables without a .env?
section: guides
covers: both
order: 90
---

# Project variables with mehen run

A repo that uses the vault commits a `mehen.toml` at its root, with variable names and no values ([mehen.toml](../reference/mehen-toml.md)). `mehen run` gives a command those variables, as placeholders, plain values or, only where a human allowed it, real values. Never write a secret to disk: no `.env` with values, no config file, no shell history.

## Set one up

```sh
mehen init --env dev --env staging
```

`mehen init` at the repo root creates the project in the vault, bound to the repo's `origin` remote, and writes `mehen.toml` with the project id, workspace and vault. It never overwrites a `mehen.toml` or `mehen.local.toml` that is already there. Working in a shared or open-source repo where you cannot commit `mehen.toml`? Pass `mehen init --local` to write an uncommitted `mehen.local.toml` instead (add `mehen.local.toml` to `.git/info/exclude` or `.gitignore`). Creating a project needs a member's machine (not a guest's or a team's) whose scope covers every project. If this machine is refused (`forbidden`), stop and ask the human or the project's maintainer for a checkout with the existing project's committed manifest; do not bypass the refusal or invent a project id. Once that manifest exists, `mehen workspace bind` fills in `workspace` and `vault`; it never guesses a project from the path.

### A repo that is already a project

In a fresh clone, or a git worktree outside the main checkout, of a repo whose `origin` is already bound to a project this machine may use, `mehen init` creates nothing: it binds the checkout to that project. It writes `mehen.toml` naming the project, with every variable the project defines in any environment declared as `NAME = "vault"`, and says `bound this checkout to project <slug> (<id>); wrote <path>` (with `--json`, the usual report with `bound: true`). No `--slug` is needed; a `--slug` naming another project is refused, naming the bound one, and so is any `--env`, since the project's environments are changed on its page. Commit the `mehen.toml` so every other checkout and worktree gets it. A remote bound to a project this machine may not use looks the same as an unbound one.

When it creates a project, `mehen init` writes the `[vars]` entries as commented examples: declare the real variables before `mehen env check` or `mehen run`. `--slug` names the project (otherwise the repo name), and each `--env` adds an environment, the first being the default (otherwise just `dev`). `prod` and `production` are always protected and can never be the default.

Then point each `"vault"` variable at a credential the project may share (one whose home is this project or the workspace; a private one is refused), once per environment:

```sh
mehen request api-key --name openai-evals --provider openai --home project --project prj_3kQ9vXyZ7 --reason "run the evals for this project"
mehen wait <intake_id>
mehen env set OPENAI_API_KEY --env dev --item openai-evals
mehen env set LOG_FORMAT --env dev --plain json
```

Relay the request's ask before you wait. `--field` picks a field when the item's kind has no single primary field. `--plain` refuses a value that looks like a secret. Setting a variable needs `edit` on the project and an unprotected environment; a private credential can never back a shared variable (the human can use a personal override instead, on the project page), and a workspace credential in an environment shared with a guest or a team's machine needs an owner or admin in the browser.

## Run

In any clone or worktree, including a throwaway one under `/tmp`:

```sh
mehen env check                 # does every declared variable resolve for this environment?
mehen run -- bun dev            # run with the project's variables
mehen run --env staging -- bun test
```

MCP: `vault_env` for `ls` and `check`. There is no MCP tool for `mehen run`, `mehen env set` or `mehen init`.

What happens:

- The CLI finds `mehen.toml` by walking up from the current directory, stopping at the git worktree root, so a git worktree outside the main checkout does not see the main checkout's file. No `mehen.toml`, no project: `mehen run`, `mehen env check` and `vault_env` refuse. When the checkout's `origin` is a project this machine may use, the refusal names it, with `run mehen init to bind this checkout to project <slug>` as the next step. They never write `mehen.toml` themselves.
- It prints what it resolved on stderr every time: `mehen: prj_3kQ9... env=dev worktree=/tmp/wt-123 head=abc1234`. Read that line. If the project or environment is not what you expected, stop.
- The vault checks that the repo's reported `origin` remote is one bound to the project (`remote_mismatch` otherwise), and that your owner may use the project (`project_unshared` otherwise).
- A variable the human overrode for themselves resolves to that for their machines: `mehen env ls` says `override (your <slug>)` or `override (your plain value)`, and `mehen run` names each overridden variable in its banner. Values never appear.
- The child gets placeholders (strings like `sk-proj-jvph...` that look like keys but are worthless outside this run), plain values, or, only where the item, the machine and the environment all allow it, real values with the child's output redacted. You do not choose which: the vault does.
- A variable with no value stops the run before the command starts, naming the variable and the fix (exit 4). `mehen env check` prints the same, with one `run: mehen env set ... --item <slug>` line per variable.
- Variables the manifest declares are never inherited from your shell (a warning says so), and `MEHEN_*` variables are removed from the child.
- When the command exits, the run ends and its placeholders die; `mehen run` exits with the command's own exit code. A run lives at most 12 hours (2 hours for an approved protected run), unless it is a [service run](../concepts/projects.md#service-runs). Before that end the child gets SIGTERM, `--stop-grace` seconds early (10 by default), and `mehen run` exits 7; a refused renewal stops the child at once with the refusal's exit code. For a long-lived process, see [Keep a service running with mehen run](services.md).

Placeholders need the program to use `HTTPS_PROXY` and trust the run's CA, which `mehen run` sets. Bun, Node, curl and most Python and Ruby clients do. A program that ignores them sends the placeholder straight to the upstream, which rejects it as a bad key: the call fails, and the real key was never on the machine. [Which programs work with mehen run](run-compatibility.md) lists the clients checked, the ones that do not work, and the warnings `mehen run` prints for a `.env` next to the run, an old Node, or a run whose placeholders never reached the relay.

**Do not** print the environment (`env`, `printenv`, environment dumps) inside `mehen run` to "debug". Placeholders are useless to you and real values are exactly what must not reach your context. Use `mehen env check` and `mehen show`.

## Environments and production

`mehen env set` works only in unprotected environments, and never points a variable at a credential that backs a protected environment. Only a human, with a passkey, sets protected variables, protection and fences.

A protected environment such as `prod` runs only when you type `--env prod` literally on the command line, the machine is allowed protected environments, its owner holds the protected right on the project, and a human approves the run ([When a request needs approval](approvals.md#production-runs)). Never set `MEHEN_ENV=prod`, never try to make a protected environment the default, and never pick an environment from a branch name.

Protected credentials only reach approved protected runs. Wherever else one is named (a dev variable, `mehen fetch` without a context), the vault holds it back: in a dev run the variable is missing, and `mehen fetch` needs `--project <prj_id> --env <name>` naming the protected environment that references it, plus an approval of that exact request.
