---
title: Connect an agent to one workspace
question: How do I install or update mehen, enrol this machine and register the agents?
section: guides
covers: both
order: 10
---

# Connect an agent to one workspace

An agent given the prompt from the Connect an agent page follows [Set up Mehen](../setup.md), which is the whole procedure for an agent. This page is the same path with the reasons, for a human or an agent who wants them. It is the same for a workspace on Mehen Cloud and on a vault you run on [another machine](../start/another-machine.md), which you name with `MEHEN_VAULT_URL`. For a vault on this machine, [`mehen up`](../start.md) does all of it.

## Is this machine enrolled?

```sh
mehen status --json
```

`mehen status` lists every workspace this machine may use: `{ home, allowed, workspaces, selected, next, cli }`. It exits 0 unless there are active workspaces and every one's check failed; then it exits with the first failure's code, `next` is that failure's next step, and top-level `error` and `message` say what failed. Status returns a list of state-specific entries. Active entries identify the workspace and contain its vault check; pending entries describe an enrolment; ended entries are an attempt that ended for good with its key kept, and their next step is to enrol again; corrupt entries describe a local failure; absent entries name an allowed workspace not enrolled yet. Read each by its state. A workspace is connected when its entry has `state: "active"`, the intended slug and origin, and `check.ok: true`; a locally active slot whose check failed is not a working connection, so read that entry's error and next step. With no active entry, follow `next.command`. `cli` is this `mehen`: version, path, whether it updates itself and an update in progress; `mehen doctor --json` adds what it installed and last did.

When anything fails and the error does not make the reason plain (a `proof_invalid`, a network error, a key file), run `mehen doctor` (MCP `vault_doctor`): it checks this machine, each vault and each workspace in one go and names the fix. It never migrates, writes or deletes anything.

```
mehen doctor: 1 check failed
  ok    home       /Users/sam/.config/mehen (default)
  ok    migration  /Users/sam/.config/mehen uses the workspaces layout.
  ok    vault_url  https://app.mehen.dev for a new enrolment (the default)
  warn  session    MEHEN_SESSION is not set.
vault https://app.mehen.dev
  ok    reachable  https://app.mehen.dev answers (84 ms).
  FAIL  clock      This machine's clock is 95 s ahead of the vault; the vault refuses proofs more than 60 s off.
next: Set this machine's clock (turn on network time), then run `mehen doctor` again.
```

## Install or update

On a machine with no `mehen`:

```sh
curl -fsSL https://mehen.dev/install | sh
```

Mehen is not on Homebrew yet; on npm, Mehen's packages are `@mehenai/cli` and `create-mehen` (the unscoped `mehen` package is an unrelated tool). The installer supports macOS and glibc-based Linux, including suitable WSL distributions, on arm64 and x64. Native Windows and musl-based Linux are not supported, and on a musl system it says so before fetching a binary; `curl`, `openssl`, and `shasum` or `sha256sum` are required. Before it trusts anything in the release manifest, it checks the manifest's signature against Mehen's release keys, then the binary's size and SHA-256 against that manifest. Its last line is a receipt, `mehen-install: {"v":1,"result":"installed","path":"/abs/path/mehen",...}`: use that `path` until a new shell has `mehen` on `PATH`. It writes one guarded `PATH` line for zsh and bash and gives advice for other shells, and never overwrites a file it does not own.

The installer is for a machine with no `mehen` only. On a machine that has one, it says so and changes nothing unless a human forces it; an installed `mehen` verifies its own updates and refuses an older release, which the installer, with no record of earlier installs, cannot. Bring an installed one up to date with:

```sh
mehen update --json
```

`result` is `updated` or `current` when it is current; `held` means the release on offer is not newer than one this machine already had; `locked` means another update is running. A refused update (a signature that does not verify, a downgrade, a directory you cannot write) is reported, never worked around by reinstalling. [Keys, proofs and signing](../security/keys-and-signing.md#releases) says how updates are signed.

## Enrol

```sh
mehen enrol --workspace acme
```

```
Human needed: approve this machine
  open:    https://app.mehen.dev/w/acme/e/K7Q2MXAB
  what:    Approve my-laptop (Secure Enclave key) and choose what it may use
  check:   the page shows fingerprint  5NZV DP67 PXT0 DB6E
  expires: in 60 min (17:50)
  then:    mehen wait enr_9m2kQ
  words:   puppy (violet)  potato (indigo)  juice (mint)  oven (olive)
  hidden:  the page hides the second group, DP67: type it on the page
```

- **`--workspace` is required.** Without it the command is a usage error (exit 2) and nothing is sent. The machine's name is its host name unless you add `--name <machine-name>`. `--team <team-slug>` enrols a machine a team owns ([A CI runner or a shared machine](ci.md)). `--connect <code>`, when the human's prompt gives a connect code, sends the approval to that human's own Needs you; only they can then accept it.
- **It prints the ask and exits 0.** With `--json` it is one object, `{ status: "pending", enrolment, url, code, fingerprint, backend, expiresAt, hardExpiresAt, renewals, claimed, slot, ask }`, or `{ status: "active", ... }` when this machine is already in that workspace (nothing changes then). Relay the ask, then finish with `mehen wait <enrolment> --json` (or `vault_wait`) from this shell or any other. A wait that times out exits 4 with the ask again; wait again. `--wait` waits inside `mehen enrol` instead.
- **The link stays alive while something waits.** A link lives an hour; `mehen wait` renews it in place when it is about to lapse (same id, same address, same fingerprint), for up to 24 hours. Only a terminal `expired` (exit 1) means a new attempt: run `mehen enrol --workspace <slug>` again and relay the new link.
- **It keeps its key.** Running `mehen enrol` again resumes the same attempt with the same key, so the fingerprint and words stay the same. `--fresh-key` throws the key away and makes a new one, with a new fingerprint.
- **Give the human the whole fingerprint.** The page hides one group and the human types it from your message.

The human accepts with a passkey ([Machines](../concepts/machines.md#enrolment) says what they check). `mehen wait` then prints `Enrolled as dev_... in Acme (acme) at https://app.mehen.dev, owned by <name>` and exits 0; read the owner it names.

## Register the agents

```sh
mehen setup --json
```

It registers one `mehen` MCP server and the skill in every agent it finds, at user level, and reports each one. [Register mehen with each agent](harnesses.md) covers the options. The command line works at once; the MCP tools arrive when each agent restarts.

## Confirm

```sh
mehen status --workspace acme --json
```

It must exit 0, with `workspace.slug` the slug you were given and `vault` the vault you were given. Without `--json` it reads:

```
my-laptop (dev_FOKtq..., Secure Enclave key) in Acme (acme) at https://app.mehen.dev, owned by Sam
  workspace id:    tn_aeAL...
  slot:            /Users/sam/.config/mehen/workspaces/app.mehen.dev/tn_aeAL...
  key fingerprint: 5NZV DP67 PXT0 DB6E
  session:         pi-4f2a (MEHEN_SESSION)
  items:           all
  projects:        all
  environments:    unprotected
  modes:           relay, placeholder
  private:         yes
  pending:         2 asks waiting for a human (mehen pending)
```

`private` says whether this machine may use your private credentials; when it is off it reads `no (ask with --home project or workspace)`. A machine not enrolled there is `workspace_unknown` (exit 2), with `next.command` the enrolment. `mehen whoami` is the same command.

## After that

Installed release builds with a compiled trusted release key check for signed updates automatically; a build with no trusted key updates nothing. Such a build checks for a signed release about every hour in the background after a command, installs only a newer signed one, and refreshes the skills setup manages. `MEHEN_NO_AUTO_UPDATE=1` turns that off; CI and source runs never update themselves. A running `mehen mcp` switches to a newer signed version in place by default; where it cannot, or the machine switched that off, it keeps the version it started with and says in a tool result when the agent should restart to load a newer one ([Signed releases](../security/keys-and-signing.md)).
