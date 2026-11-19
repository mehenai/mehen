---
title: Projects, environments and runs
question: How do projects, environments, variables and mehen run work?
section: concepts
covers: both
order: 80
---

# Projects, environments and runs

## Projects and shares

A **project** is a coding project. It has a stable id (`prj_...`) committed in the repo's `mehen.toml`, a slug, the git remotes bound to it, a default environment, environments and variables. [mehen.toml](../reference/mehen-toml.md) is the manifest.

**Sharing.** Owners and admins manage every project. Anyone else gets a project through a **share**, to a member or a team, at a level: `use` (run it, see the credentials it references), `edit` (also set its unprotected variables) or `manage` (also share it, change its environments, protection and fences, delete it), with a tick that extends the level to the protected environments and an optional expiry. A member's effective access is the union of their direct shares and their teams' shares, level by level; no union invents a right absent from every source, and a guest never gets `manage` (a `manage` share reads as `edit` for them) or a share through a team. Sharing needs `manage` and a passkey; sharing with a guest, or any change that would give a guest's or a team's machine a workspace credential, needs an owner or admin. A member may create projects; a guest may not.

On the project page, the share form starts from the chosen person's or team's current share: its level, whether it includes the protected environments, and its end. The end is a UTC day, as the page shows every time in UTC: the share ends at 23:59 UTC on that day, at most 365 days away, and an empty end means none. Changing only the level keeps the end the share already has; making a share permanent means clearing the end. Before the passkey, the page says in one line beside the button when a change removes an end ("This share will no longer end.") or moves it later, and it refuses a day that has passed.

`mehen init` creates a project bound to the repo's normalised `origin` remote (`github.com/acme/app`) and writes `mehen.toml` with the workspace id and vault origin. In a checkout whose remote is already a project this machine may use (a colleague's clone, an agent's worktree), it binds the checkout to that project instead and creates nothing. Only a member's machine whose scope covers every project may create one. A remote belongs to one project. A project manager binds further remotes, or unbinds one, on the project page with a passkey; a project's last remote cannot be unbound. The page reads a pasted URL into the normalised form and shows it before the passkey, so a URL that reads as one repository but names another cannot be bound by mistake.

**How the CLI finds the project.** It walks up from the current directory to the nearest `mehen.toml`, stopping at the git worktree root; outside a repo it looks only in the current directory. No `mehen.toml`, no project: there is no guessing from paths. The manifest's `workspace` and `vault` pick the workspace that acts (`mehen workspace bind` fills them into an older manifest).

Every run sends the normalised `origin` remote with the project id. Mehen checks the remote the CLI reports against the project's bound remotes and refuses with `remote_mismatch` when it does not match, and with `project_unshared` when the project exists but is not shared with the machine's owner. This prevents accidental use from a mismatching checkout; it does not attest the repository's contents, and it does not protect against a hostile process on the same machine changing or misreporting that remote. A [workload](machines.md#workloads) whose scope names the project in `projects` may send no remote (`null`) even when the project binds remotes, since its device chose the project for it and it has no checkout to mismatch; a protected environment still needs a bound remote.

The manifest expresses intent only. Which environments are protected, which items back which variables, who the project is shared with and how each variable is delivered live in the vault. A pull request that edits `mehen.toml` cannot widen anything.

## Environments

An environment (`dev`, `staging`, `prod`, or any name of lower case letters, digits and dashes starting with a letter, up to 32 characters) has variables, a **protected** flag, a **four-eyes** flag and optional **fences**.

**Choosing an environment.** `--env` on the command line, then `MEHEN_ENV` (unprotected environments only, and removed from the child), then `default_env`. Branch names never pick an environment.

**Protection.** `prod` and `production` are always protected. A protected environment can never be the default. Only a project manager with a passkey can protect or unprotect an environment, turn four-eyes on or off or change its fences. Adding or removing a fence, and protecting or loosening an environment that references a workspace credential, need an owner or admin, and owners and admins are told of each. Protecting an environment clears every [override](#overrides) in it.

**Four-eyes** on a protected environment means a run there, or any use of a credential it references, is approved by a manager of every project whose four-eyes applies, and never by the machine's own owner.

## Protected environments

A run in a protected environment needs all of:

1. `--env prod` typed on the command line;
2. a machine whose scope allows protected environments, owned by someone with the protected right on the project;
3. a human's approval of that run, by an eligible decider ([Approvals](approvals.md)).

Otherwise the vault refuses with `environment_refused` (or `approval_required` when only the approval is missing). Machines may set variables only in unprotected environments, and only for an owner with `edit`; a human with the protected edit right sets protected ones with a passkey.

## Fences

**Fences** are hosts (exact, or `*.example.com`) that belong to one environment. A run in `dev` cannot reach hosts fenced to `prod` or any other environment of the project, so the wrong database at the wrong time is a refused connection, not an incident. Fences are enforced in two places:

- **The vault** refuses any run-mode relay request whose host matches another environment's fence, with `environment_refused`, and records a tripwire in the audit chain.
- **The local relay** of `mehen run` refuses a request to a fenced host before anything leaves the machine, and refuses a connection to an IP address while the run has fenced or intercepted hosts (loopback is exempt).

Fences match host names, not DNS aliases, and apply to traffic that goes through Mehen; they do not sandbox a program's direct network access. [The threat model](../security/threat-model.md#a-runs-own-program) says what that leaves open.

## Protected credentials

**A credential is protected when any protected environment's variable uses it.** Protection follows the credential, not the run, so a production secret cannot be leased through a dev variable.

- A protected credential reaches only an **approved run in a protected environment**, by a machine allowed protected environments whose owner holds the protected right there. In any other run, a variable that points at it is `missing`, with a message saying why.
- A machine cannot point a variable at a protected credential; only a human with the protected edit right can, with a passkey. Only an owner or admin can point a protected environment at a workspace credential at all.
- In item mode (`mehen fetch <item>`), a protected credential needs an explicit **context**, `--project <prj_id> --env <name>` naming a protected environment that references it, a machine allowed protected environments, its owner's protected right and an approval of that exact request, whatever its policy says; without the context it is `environment_refused`. The same context is how a guest's or a team's machine names the project environment through which it reaches a workspace credential. A context given when none is needed is still checked.
- When a human makes a credential protected, the vault warns which unprotected variables will stop receiving it. A new protected reference, or four-eyes turned on, stales the approvals, grants and live runs that depended on the old shape.
- A private credential is never protected: it cannot back a shared variable, and an override pointing at one is refused in a protected environment.

## Variables

A variable is `KEY` in an environment. Its source is an item field (`mehen://openai-personal#key`), a plain non-secret value, or unset. A plain value that looks like a secret (a PEM block, a URL with a password, a known key prefix, a long random-looking string) is refused; that is a heuristic, not proof that every plain value is harmless. Setting one needs `edit` on the project; the source must be a workspace credential or a credential of this project, never a private one or another project's. In a machine's view of a project, a variable backed by a credential outside its reach shows no item, so a machine cannot map the names of credentials it cannot use.

Delivery is decided by the vault per variable, item, machine and environment, never by the manifest:

| Delivery | What the child gets |
| --- | --- |
| `plain` | The non-secret value. |
| `placeholder` | A [placeholder](#placeholders), plus the hosts it may go to. Chosen when the item has an injection and its ceiling and the machine allow `placeholder`. |
| `lease` | The real value, only when nothing lower fits and the item's ceiling is exactly `lease` and the machine allows it. |
| `missing` | Nothing; the run fails before the command starts, by name, with a `next` step to fix it. |

A base-URL delivery, for SDKs that take a base URL instead of a key, is not built.

## Overrides

An **override** is one member's personal source for one variable in one unprotected environment of a project they may use: their own private credential or a plain non-secret value. It is chosen in the browser only, with a passkey; clearing it is the same. Guests may hold overrides too. There is no override in a protected environment, and protecting an environment clears every member's overrides in it; loosening it later revives none.

An override applies only to the owning member's own machines, and only those with the private-credentials tick when it points at a private credential: their runs get the override instead of the shared source; another member's or a team's machine gets the shared source and never learns the override exists. An unticked machine's run is refused as a whole with `not_found` rather than silently falling back. `mehen env ls` marks overrides (`override (your <slug>)`, `override: true` in `--json`) and `mehen run` names them in its banner, by name only. The audit records the environment and variable, never the source or the value.

## Runs

A **run** is one `mehen run` invocation: its project, environment, worktree path, HEAD, remote, the variable names it asked for, the command's first two words (for audit), its placeholders, its leases and its expiry.

A run lasts 15 minutes unless renewed; `mehen run` renews it every 5 minutes while the child lives and ends it on exit. **A run lives at most 12 hours, or 2 hours when an approval started it, however often it renews, unless it is a [service run](#service-runs).** The vault names that hard end as `endsAt` when the run starts and on every renewal. `mehen run` sends the child SIGTERM `--stop-grace` seconds before it (10 by default, at most 300) while the run still works, SIGKILL at the end, and exits 7. A renewal the vault refuses stops the child at once, except `rate_limited`, `upstream_failed` and `refresh_retrying`, which are retried. When a run ends or expires its placeholders die. A supervisor such as launchd or systemd starts a stopped service again ([Keep a service running with mehen run](../guides/services.md)).

### Service runs

A **service run** has no maximum life: `mehen run --service` asks for one, the vault answers `endsAt: null`, and the run lives as long as it renews. The banner says `service` after the environment. Only a machine whose scope has [`serviceRuns`](machines.md#scope-and-reach), which a human grants with a passkey, may start one (otherwise `forbidden`, with a link to the machine's page), and only in an unprotected environment (otherwise `environment_refused`): a protected run's approval covers one run of at most 2 hours, and a service run never changes that.

What the maximum life bounded for an ordinary run, the vault checks on every renewal of a service run instead. It plans the run again from the variables it asked for and compares the plan with the one it started with: a variable bound to another item or a plain value, an override set or cleared, a different delivery (a placeholder now a lease, say), a rotated credential or a changed fence on another of the project's environments refuses the renewal with `conflict`, `mehen run` stops the child and exits 7, and the supervisor starts it again with the new plan. A fence matters here because the local relay refuses fenced hosts from the list the run started with, and a leased value's requests never pass the vault; a new run brings the new list. A freeze, a revoked machine, a narrowed scope (May run services unticked included) or an unbound repository end it as they end any run. A service run started by a [workload](machines.md#workloads) still ends with the workload.

What `mehen run [--env staging] -- <cmd>` does:

1. Resolves the project and environment and prints them on stderr every time: `mehen: prj_3kQ9... env=dev worktree=/tmp/wt-123 head=abc1234`.
2. Creates the run and gets each variable's delivery, with the owner's overrides substituted and named. A protected environment needs an approval first. The approval page shows the project, environment, command arguments, variable names and which variables receive real values or placeholders. The request digest also binds the submitted remote, worktree and commit, but this page does not display those fields. Check the CLI's resolved context before requesting approval. The approval binds the hash of the whole command line; the audit records the command's first two words and the hash, never the later arguments.
3. If there are placeholders, starts a local relay on 127.0.0.1 with a per-run proxy password and a per-run CA, and sets `HTTPS_PROXY`, `HTTP_PROXY` (and their lower-case forms), `NO_PROXY` (empty), `NODE_USE_ENV_PROXY`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `GIT_SSL_CAINFO` for the child. Only hosts bound to a placeholder's item get TLS terminated; their requests go to the vault relay with the placeholders intact, and the vault swaps them. Everything else is an opaque tunnel. The per-run CA is constrained to exactly the bound hosts, by DNS name and IP address.
4. Builds the child environment from the parent's, minus every `MEHEN_*` variable and any inherited variable with a declared name (an ambient production `DATABASE_URL` from another shell is overridden, with a warning). Missing variables fail before the command starts.
5. Passes lease values to the child only, with its stdout and stderr through the [redactor](#leases).
6. On exit, ends the run and exits with the child's exit code. When it stops the child itself (maximum life, a refused renewal, a renewal that never succeeded), it exits with [the code for the reason](../guides/services.md#exit-codes) instead.

Use `mehen run` with HTTP clients that honour its proxy and CA settings: Bun, Node, curl and most Python and Ruby clients do. Supported clients receive placeholders without changing application code. Clients that ignore those settings (Go on macOS, some older Python builds), or use unsupported protocol upgrades, will not authenticate through the local relay: their placeholder reaches the upstream, which rejects it as a bad key.

## Placeholders

A **placeholder** stands in for a secret where a program insists on having "the key" in its environment but only ever sends it over HTTP. Its format is the real secret's well-known prefix (so SDK key-shape checks pass), then `jvph`, then 24 random letters and digits: `sk-proj-jvph` followed by 24 characters. Placeholders are random per run.

- Only the vault swaps a placeholder, and only in run mode: in the item's declared header or query parameter, on a host both the placeholder and the item are bound to, and outside any host fenced to another environment.
- A placeholder anywhere else in a request (a body, a query string, another header, a Basic credential, the address) or at an unbound host is refused with `surface_refused`, never substituted, and recorded as a tripwire. Otherwise an injected agent could write the real token into a comment on a bound host.
- A placeholder in tunnelled traffic is never seen and never swapped; at an unbound host it is a worthless string.
- A tripwire does not freeze the workspace by itself.
- A leaked placeholder is worthless once its run ends; while its run lives, it is a usable capability on that machine.

## Leases

A **lease** is the real value, delivered into one child process only. It is refused unless the item's ceiling is exactly `lease`, the machine's modes include `lease`, and the variable belongs to the run's project and environment. A protected credential is leased only in an approved protected run, and only for the variables that run's approval showed as real values. Leases are delivered through the environment.

The child's stdout and stderr pass through a streaming redactor, which replaces the value and its URL-encoded, JSON-escaped and base64 forms with `[redacted:<label>]`, across chunk boundaries.

Limits, stated plainly: values shorter than 6 characters are not redacted; redaction cannot catch a value the program transforms (reversed, split, hashed, encrypted, printed one character per line) or writes to a file or socket; and any process running as the same user can read the child's environment. **Lease mode exposes the value to the process.** That is why relay and placeholder, where the value never reaches the machine, come first.
