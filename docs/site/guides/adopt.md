---
title: Bring a machine's credentials into Mehen
question: I have .env files across my repos and services; how do I bring them all into Mehen at once?
section: guides
covers: both
order: 96
---

# Bring a machine's credentials into Mehen

You have enrolled your first machine, and it has `.env` files in a dozen repos, a `.local-secrets` folder and a few services with keys in their env files. `mehen adopt` brings them into the vault in one batch, which you approve with one passkey. A batch holds up to 500 credentials; more than that are split into a few batches, each approved with a passkey of its own. For a single key, [Move existing keys in](existing-keys.md) is quicker.

## What adopt does, and what it never does

- **It never rewrites or deletes an original.** Every `.env`, settings file, login file and service unit stays byte for byte as it was. You decide later when to remove them: `mehen adopt retire --yes`, run by you, moves the proven ones to a quarantine folder and nothing else ([8. Retire](#8-retire-when-you-are-sure)).
- **Values are sealed on the machine.** `mehen adopt submit` reads each value in its own process and seals it to the vault before it leaves. No value, part of one, its length or a hash of it is printed, written to a file or shown to an agent.
- **A human approves the whole batch.** You review every row on one page in the vault and confirm with one passkey. Nothing is stored until then.
- **You keep your own copy.** Submit is refused until a snapshot of every file the plan names exists, encrypted to a key that is on no enrolled machine ([Back up a machine before adopting](backup.md)).

The steps, in order: scan, plan, snapshot, submit, approve, apply, verify, and, once you are sure, retire. Run them in a terminal on the machine that holds the files. An agent may run scan and plan for you; the snapshot and the approval are yours.

## Quick path: one `.env` file

Want to move a single `.env` file from one repo without scanning the whole machine? `mehen adopt file` scans and plans that file alone in one step:

```sh
mehen adopt file .env
```

It classifies every variable without showing a value, writes the plan, and prints the exact `mehen backup snapshot`, `mehen adopt submit --wait`, and `mehen adopt apply` commands for that plan. Pass `--home <folder>=private|workspace|project:<slug>` or `--per-project` as with `mehen adopt plan`.

## 1. Scan

```sh
mehen adopt scan
```

With no flags it walks `~/code` (six folders deep), `~/.config`, `~/.local-secrets` and your service units (`~/Library/LaunchAgents` on macOS, `~/.config/systemd/user` on Linux), plus the usual login files (`gh`, kubeconfig, talosconfig, gcloud, Cloudflare, Docker and Claude Code settings). It reads `.env`, `.env.*`, `.dev.vars`, `*.env`, `.envrc`, settings JSON, launchd plists and systemd units. In `.local-secrets` it also reads every other file: as `NAME=value` lines when it has them, or else whole when it holds one key, a PEM block such as a GitHub App's `.pem` or an Apple `.p8`, a service account, or a token on one line. A key read whole is named by its file, so `ci-deploy-token` becomes the item `ci-deploy-token-local-secrets`. Any other file there, such as notes or a JSON export, is listed once as a file to move by hand. It skips example files (`.env.example`, `config.example.json`), `node_modules`, `.git`, `vendor`, `dist`, `build`, `.venv`, binaries, files over 1 MiB and files another user owns.

To scan only some folders, name them: `mehen adopt scan --no-defaults --root ~/code/billing-api`. `--depth`, `--include` and `--exclude` narrow it further.

Reading the scan:

- The last line counts what it found: `found 41 files, 96 secret variables (58 distinct values), 30 config, 4 unsupported; wrote ~/.config/mehen/adopt/<machine>/scan.json`. Distinct values tell you how many copies of the same key you have.
- A line such as `~/code/api/.env:5: not NAME=value` is a line that did not parse. It is never quoted, only its line number.
- `--json` prints the counts, one row per folder with its proposed home and how many secrets, config, unknown, unsupported and possibly stale names it holds, one row per file that did not parse, with its number of lines (the first 50 files), and the folders holding those files with how many each holds, most first. The scan file lists every name with its file, its class (`secret`, `config` or `unknown`), the template it matched (for example `openai`) and why. Values that are equal share a duplicate label such as `d3`; the label is random on each run and says nothing about the value.
- Ids, orderings, site keys and model names are config even when they look random: names ending in `_PRICE_ID`, `_TEMPLATE_ID`, `_ORG_ID`, `ORGANISATION_ID` or `ORGANIZATION_ID`, `_PROJECT_ID`, `_ORDERING` or `_ORDER` (`TEMPLATE_ORDERING`), `_SITE_KEY` or `_SITE_KEY_V2`, or `_MODEL`, and names containing `_MODEL_`, as is a Cloud KMS key's name (`projects/.../keyRings/.../cryptoKeys/...`). A secret's name still wins over an id or model name: `LLM_MODEL_PASSWORD`, `AZURE_OPENAI_MODEL_KEY` and `STRIPE_PROJECT_ID_TOKEN` are secrets; only a site key stays config with a name ending in `_KEY`. A value shaped like a secret, such as one starting `sk_live_`, `ghp_` or `AKIA`, a PEM block or a URL with a password, is still a secret whatever its name. `CLIENT_ID` stays half of an OAuth client.
- A Firebase web key is a generic secret, not a Gemini key: a Google API key (`AIza...`) named `FIREBASE_WEB_API_KEY`, ending in `_FIREBASE_API_KEY` or starting `NEXT_PUBLIC_FIREBASE_` is public by Firebase's design, since every page that uses it carries it, but the vault refuses a value of that shape as a plain value. Stored as a generic secret, `mehen run` delivers it. Only the name decides: a bare `GOOGLE_API_KEY` of the same shape stays a `google-gemini` item, and `FIREBASE_ADMIN_PRIVATE_KEY` and `FIREBASE_SERVICE_ACCOUNT` stay secrets of their own kinds.

## 2. Plan

```sh
mehen adopt plan
```

The plan reads the scan, asks the vault which names and projects already exist, and writes `~/.config/mehen/adopt/<machine>/plan.json`. It prints one row per folder with the home its credentials get, then any problems.

**Homes.** Every credential needs a home ([credentials](../concepts/credentials.md)):

- a repo's `.env` goes to that repo's project: the project the vault binds the repo's `origin` remote to, so every machine's checkout of a repo, a fresh clone with no `mehen.toml` included, lands in one project; else the one its `mehen.toml` names; otherwise submit creates one bound to the remote. When a committed `mehen.toml` names another project than the one the vault binds the remote to, the plan leaves that repo's variables alone and prints one line, `problem: <repo>: mehen.toml names project X, but the vault binds this repo's remote to project Y; its variables are left alone: fix mehen.toml or the remote, then plan again`; its items still upload. When the remote is bound to a project this machine cannot use, submit says so: ask an owner or admin to share the project, then plan again;
- a service's env file goes to a project for this machine's services, `<machine>-services`;
- `.local-secrets`, settings files and login files go to your private home.

**Worktrees and clones.** Every worktree and clone of one repository (the same `origin` remote) shares one project, since the vault binds a remote to one project; apply writes a `mehen.toml` naming it in each checkout. A value found in several checkouts or files becomes one item, and so does a credential of several parts, such as an OAuth client's id and secret, when every part matches. A project holds one value per environment for each variable, so when files disagree on a variable the plan keeps one and maps the rest to `skip` with the reason, naming the file that wins. The winner is, in this order: a file that is not possibly stale, an override file over its base (`.env.local` over `.env`), the file nearest its checkout root, the main checkout (the shorter path) over a worktree, then the first path alphabetically. Services in `<machine>-services` follow the same rule: a source that is not possibly stale, then the first unit by path. A losing secret is still adopted as an item of its own; it backs no variable.

**Backup copies.** A file kept aside beside the one in use, such as `.env.bak-20260908-174826` or `.env.production.orig`, is not an environment of its own. Every variable in it maps to `skip` with the reason `backup copy`, and it adds no environment to the project. A value found only in backup copies makes no item; the plan lists it as possibly stale (see [What is listed as possibly stale](#what-is-listed-as-possibly-stale)). A value that is also in a live file stays one item, with the copy listed among its sources so submit checks they still agree. The snapshot still holds every backup copy.

**Values several projects share.** The same Stripe test key or Sentry token often sits in the `.env` of several repos. When equal values would land in two or more projects, the plan makes them one workspace credential instead of one item per project: one copy to rotate, named without a project (`stripe`, `sentry`, or `stripe-2` when an item of another kind or template has the name), with every project's variables pointing at it. A name the vault already holds is reused only with evidence that it holds this value: a project already points one of these variables at it and none at another item, or this machine's own approved batch stored it from one of these same variables and no project points at another (submit records where each item's value came from, never the value). So plan again after the batch is approved and the variables point at the stored credential rather than a second copy. Kind, provider and the `adopted` tag are no evidence, since another admin's `openai` may be another key: without evidence the plan sends this value under that name to be compared with the vault's, with a note that starts `compare with openai in the vault: the reviewer decides which value it keeps` ([Values already in the vault](#values-already-in-the-vault)). Its note says `used by 3 projects (api, web, worker): one workspace credential; every member's machine may use it`, naming the first three projects and how many more (`used by 12 projects (api, billing, jobs and 9 more)`), and the plan says how many values became workspace credentials. Every member's machine may use a workspace credential, not only the machines of a project's members (a guest's machine may not). Only an owner's or admin's machine can store one, so on a member's machine the plan keeps one item per project and says so. It never merges a value in your private home, a folder you gave a home with `--home`, a name already in the vault, a live key, which stays one item per project (see **Live keys** below), a value with any copy in a protected environment, or copies that would differ in kind, template or fields. A protected value stays one item per project: as a workspace credential every member's machine could use it until you set it on the project page, and then only an owner or admin could set it. A machine cannot point a variable at a workspace credential in a project shared with a guest or a team, so for such a project, or when members should not reach every repo's keys, plan with `--per-project` to keep one item per project:

```sh
mehen adopt plan --per-project
```

**Config that looks like a secret.** The vault refuses a plain value that looks like a secret, such as a long random-looking string or one starting with a provider's prefix. The scan records, without the value, whether a config value looks like one, and the plan maps its variable to `skip` with the reason `looks like a secret, so it is not set as a plain value: store it with mehen request or set it by hand`, so `--check`, apply and the vault agree. This covers an id or an ordering that is config by its name, such as a `_PRICE_ID` or a `MENU_ORDER` that looks random.

**Logins and OAuth tokens are connectors.** The gh login in `~/.config/gh/hosts.yml`, Google OAuth tokens (a value starting `1//` or `ya29.`, or a Google `*_REFRESH_TOKEN`), gcloud application default credentials and the Cloudflare CLI login are never uploaded. The plan lists each as a connector, `connector, never uploaded: <file> <variable>: <why>; then: <command>`, where the command is the `mehen connect` that replaces it, if there is one, and the file stays as it is:

- the gh login: `mehen connect github-oauth --name github-oauth --reason "adopt: the gh login token"`;
- a Google token whose name says the service, such as `GMAIL_REFRESH_TOKEN`: `mehen connect google-gmail --name google-gmail --reason "adopt: GMAIL_REFRESH_TOKEN"`, and likewise `google-calendar` and `google-drive`. A Google token whose name says no service is not guessed: its variable is skipped until you connect the service it uses and map it;
- gcloud application default credentials: none, since they need a new sign-in anyway;
- the Cloudflare CLI login: none, since its tokens rotate; adopt a `cloudflare-api-token` instead.

When the vault already holds exactly one connection of that provider, the plan uses it and its name replaces the provider in `--name`. A variable that held such a token maps to `{ connection: <slug> }`, and apply sets it once exactly that connection exists, printing the command until then. A `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` pair is still a `google-oauth-client` item ([Connect an OAuth account](oauth.md)).

**Live keys.** Every value adopted into a project's environment reaches every machine that runs the project there, so a production key left in a developer's `.env` would reach every colleague's laptop. The scan records, without the value, whether a secret is shaped like a live key: a Stripe secret or restricted key starting `sk_live_` or `rk_live_`. Test keys (`sk_test_`, `rk_test_`) are not live, and neither is a webhook secret (`whsec_`), whose shape says nothing about the mode. An item holding a live key read from a repo file for an environment that is not protected starts unticked, with a note such as `a live stripe key in a dev file: every machine that runs billing-api dev would get it. Adopt it into a protected environment on the project page, or tick it if dev really uses live keys.` A live key in a `prod` or `production` file, or in an environment an existing project protects, stays ticked as any other key, and you set its variable yourself after approval. The same key in both, such as in `.env` and `.env.production`, or in one repo's `.env.production` and another's `.env` merged into one item, stays ticked for the protected environment, and the plan maps the other files' variables to `skip` with the reason `a live key: only the protected environment gets it`. So does a live key whose item is already in the vault, since apply would otherwise point the dev variable at it. A live key in several projects' files is never made one workspace credential: each project keeps its own item, unticked in a dev file, and `--check` lists each with its own project. The `planned ...` line counts the live keys held back, unticked or skipped.

**Names already in the vault.** A project's item is named after the project, such as `openai-billing-api`, and the plan reuses an item the vault already holds only with evidence that it holds this value: the project already points every one of the value's variables at one adopted item of the same kind and template, whatever its name, as after apply or on a second machine with the same repo, leaving aside a variable no one has set yet where apply never sets it (in a protected environment, such as the `prod` copy in `.env.production`, in one the project lacks, or a live key's variable the plan skips); or this machine's own approved batch stored that name from one of these same variables and the project points none of them at another item. Before apply, while the project still points them at the items they had, as when you plan again after the batch is approved, the batch is enough when it stored that name from each variable the project points at another item, so the plan never reuses a name `--check` would refuse. Once apply has set a variable, even in a run with `--repo` or where another repo failed, a plan leaves it on any other item you point it at yourself, as when you rotate the key. Otherwise, when the held item is of the same kind and template, the plan sends the value under that name to be compared, as for a workspace credential, and never as a second copy; a held item of another kind or template, or one this plan proves holds another of its values, gives the next free name, such as `openai-billing-api-2`. An item already proven in the vault goes to be compared too (its note starts `compare with openai-billing-api in the vault, which mappings use already`), so a value changed here since it was stored is seen by the reviewer. Rotate a key only after this machine's apply, and a production or other protected key only after a full apply with no `--repo` or `--env`: until then, a plan again here moves the variable back onto the item the batch stored, or for a protected one tells you to set it back. If you add an environment `--check` says the project lacks and then plan again on another machine, that machine finds the variable unset there and sends the value to be compared with the held item rather than reusing it.

A repo or service gets a project only when at least one of its credentials is ticked or already in the vault, as on a second machine. One with only plain config (a launchd `PATH`) or only possibly stale credentials is left as it is: no project, no `mehen.toml`, no variable.

A private credential cannot back a project variable, so anything `mehen run` should deliver to a repo or service needs a project or workspace home. Change a folder's home and plan again:

```sh
mehen adopt plan --home ~/.local-secrets=private --home ~/code/side-project=skip --home ~/code/shared-tools=project:shared-tools
```

Each `--home` takes `<folder>=private`, `workspace`, `project:<slug>` or `skip`. It covers every folder below it too, so `--home ~/code/research=skip` skips each repo under `~/code/research`; a deeper `--home` wins. A folder with nothing the scan found at or below it is refused, since it would change nothing.

**Workspaces per folder.** A plan is for one workspace: the one this machine is enrolled in, or the one `--workspace <slug>` names when it is enrolled in several. When some folders belong to another workspace, skip them in this plan, then plan for the other workspace into a file of its own, skipping the folders that stay behind:

```sh
mehen adopt plan --home ~/code/client-app=skip
mehen adopt plan --workspace client-co --out ~/client-co-plan.json --home ~/code/billing-api=skip
```

Pass that file with `--plan` to the snapshot, `submit`, `apply` and `verify`; `apply` and `verify` take only the batches this machine submitted for that plan's workspace.

**Editing the plan file.** The file is JSON with no values in it. For each item you may change `include` (true or false), `slug`, `home` and `tags`; for each repo file, a variable maps to an item, to `plain` (non-secret config) or to `skip` with a reason. Then check it without changing anything:

```sh
mehen adopt plan --check
```

`--check` catches what would otherwise fail later: a slug used twice, a field the kind does not have, a private credential mapped to a project variable, a project this machine may not create, checkouts of one project that disagree on its id, one variable of a project and environment mapped from two files to different values, and a variable a project already points at one item in the vault that the plan would move onto another item already there, which may hold another value, unless this machine's approved batch stored that item from the same variable in the same file and apply has not yet set that variable. It also lists the variables in protected environments (`prod`, `production` and any you protected), which you set yourself on the project page after approval. It lists the items to add by hand: the vault keeps public fields, such as an OAuth client's id or an access key id, in the clear and refuses one whose value looks like a secret, so the plan leaves such an item out with a note, and `--check` refuses it if you tick it again. Add it from the web app instead. It checks every public field an item sends the way the vault does, including the file name the plan gives a whole file, which it replaces with the item's slug and the file's extension (or `file` and the extension) when the file's own name looks like a secret. It lists the live keys held back, each environment named with its project, such as `stripe-billing-api (billing-api dev)` for one left unticked or `stripe-billing-api (kept for billing-api prod, skipped in billing-api dev)` for one kept for a protected environment, marked `already in the vault` for one the vault holds; tick one or map its variable only if that environment really uses live keys. A plan with more than 500 items to upload is not a problem: the check says how many batches submit will split it into, for example `checks clean: 620 items to upload in 2 batches, each approved on its own`. It lists each item sent to be compared as `a004: compare with openai in the vault`, never how the values compare, and each variable a project binds to another item, which apply leaves as it is, as `billing-api dev: OPENAI_API_KEY: set to openai by another machine; apply leaves it`.

## 3. Take the snapshot

Before you submit, take an encrypted snapshot of every file the plan names:

```sh
mehen backup snapshot --plan ~/.config/mehen/adopt/<machine>/plan.json --to ~/Backups/mehen --recipient age1...
```

[Back up a machine before adopting](backup.md) shows how to make the key, where to keep it and how to check the snapshot. Take a new one whenever you plan again or a file changes.

## 4. Submit

```sh
mehen adopt submit --reason "bring this laptop's keys into the vault"
```

Submit refuses, with nothing sent, until a passed snapshot on this machine holds every file the plan names, none changed since. It uses the newest such snapshot; `--snapshot <snp_id>` names another, for example one you have since copied off the machine. Then it checks the plan again, creates the projects the plan needs, reads each value, checks it still matches the scan (a value that changed is skipped and listed as `changed since scan`), seals it and uploads the batch. It prints what it uploaded and the snapshot it relied on:

```
uploaded 58 items from sam-laptop to adp_7Hq2xK; snapshot snp_4fQ9cR2mT7 holds every file the plan names
```

then the review link, `https://app.mehen.dev/w/<slug>/b/adp_7Hq2xK`, and the next step, `mehen wait adp_7Hq2xK, then mehen adopt apply`. The batch is open for 24 hours; if another machine is off until later, choose **Keep open** on the review page, which adds up to 3 days, at most 7 days in all. `mehen adopt status adp_7Hq2xK` shows where it stands, and `mehen pending` lists the link again.

Each source goes with its path, its variable and when its file last changed, so the reviewer can see which machine's copy is newer. After the rows, submit sends the plan's index for the [inventory page](#see-every-name-in-one-place): every item, ticked or not, with where it was found and the variables it backs, built from the plan and checked by the output guard, never a value. An index over 900 000 bytes is not sent, and submit says so in one line, `the plan's index is <n> bytes, over the vault's 900000, so it was not sent; the inventory page does not list this machine's items`; the rows already sent stand, and so does an index the vault refuses.

**More than 500 items.** A batch holds at most 500 credentials, so submit splits a bigger plan into consecutive batches of up to 500, keeping each project's items (and each other home's) in one batch where they fit. It prints one `uploaded` line and one review link per batch, and says `this machine's items are in 2 batches (adp_7Hq2xK, adp_9Rt4mW): each is approved on its own, at its own link`. With `--json`, `batches` lists every batch with its link and its ask. At most three batches of yours can be open at once.

## 5. Approve on the review page

Open the link. The page lists every item, grouped by repo and folder. For each row you see:

- the name, the service it is for and where it sends the credential. A destination from a template is marked as such; one the agent proposed is shown in red with every host spelled out, with its limits and how it is sent, for you to check. A secret with no template and no host, such as `JWT_SECRET` or `DATABASE_URL`, reads "No host: only delivered into a process with `mehen run`" (or "No host: stored only" for a signing secret or an SSH key): the vault never sends it anywhere ([lease-only credentials](../concepts/credentials.md#bindings));
- where it belongs, as a menu of the homes you may choose;
- each secret field as its length, its well-known prefix (such as `sk-proj-`) and a fingerprint, never the value;
- where it was found: machine, file, variable and any stale hints, and the other rows that hold the same value.

Rows with a problem, only stale sources or a destination no template vouches for start unticked. Untick any row you do not want; it is left out. Change a row's home from its menu, or pick one under **Home for every ticked row** and choose **Set home** to move every ticked row at once; **Untick stale rows** leaves out every row whose sources are all stale. Apart from keeping both under another name for a row sent to be compared (below), names cannot be changed here: untick the row and adopt it again under the name you want. Filters show only problems, custom destinations, stale rows or one machine's rows.

**Approve** stores every ticked row in the home you chose, all or nothing, with one passkey. If any row fails a rule, nothing is stored and the page marks the rows to fix. **Cancel batch** stores nothing. A batch is open for 24 hours; while it is, choose **Keep open**, which adds up to 3 days, at most 7 days in all, so a machine that is off can still join it.

### Values already in the vault

A row sent to be compared, which plan and submit print as `compare with <slug> in the vault`, carries a value under a name the vault already holds: a credential stored before, or a row another machine put in an open batch. The vault compares the two values, field by field, for the review page alone. The row says whether they are the same, differ or could not be compared, with the holder's hints: for a stored credential when it was last rotated and used, for a staged row its machine, file and when that file last changed. Every such row needs a decision before you can approve:

- **Keep the vault's value.** Nothing is stored, and this machine's variables use the credential that holds the name. This is the default when the values are the same.
- **Replace it with this value.** The row's value becomes the stored credential's new value, as a rotation. It needs the right to rotate that credential, and, where a protected environment uses it, the right to change that environment. The page lists what the change reaches: the project variables that use it, the machines whose adopted files map to it, how many devices hold a lease of its current value and the OAuth connections that depend on it. The value it replaces is kept for 30 days and can be restored with a passkey from the credential's page ([Previous values](../concepts/credentials.md#previous-values)). Against a row staged in the same batch, this row is stored and the other one uses it.
- **Keep both, this one under another name.** The row is stored under the name you give, which is tested as any new name is. You may move variables that use the held credential onto the new one: the vault moves them when you approve, so apply finds them already set.

If the stored credential changes after the page loaded, approval fails with nothing stored; load the page again. While the holder is a row in another open batch, keeping or replacing it waits until that batch is decided. If that batch is cancelled or expires, the row is stored as an ordinary one.

**The machine never learns the result.** The vault gives the machine the same answer, and does the same work, for a row sent to be compared as for any other row. `mehen adopt status` and apply see only `created`, `mapped` or `replaced`, and `mapped` stands both for a value the vault already held and for a differing one you kept the vault's for.

**Who sees a comparison.** Only a reviewer who may see the batch and the credential or row holding the name sees a result. Anyone else sees no comparison. A row whose holder you cannot see can only be kept under another name or left out, and a row whose holder is gone with the name taken can only be left out. For short or guessable kinds (a password login, basic auth, SMTP or IMAP, a one-time code secret, or a generic secret) the result is shown only to someone who may rotate or reveal the stored credential, and never against a row staged in a batch; everyone else sees it as not compared. One stored credential is compared at most 10 times a day; after that the result is not compared. Every comparison is recorded in the audit with the credential and never its result.

## 6. Apply

Back on the machine:

```sh
mehen adopt apply --dry-run
mehen adopt apply
```

Apply runs only after approval. For each repo and service in the plan it:

- writes a `mehen.toml` with every mapped name set to `"vault"`, where there is none. Where there is one, it changes nothing and prints the lines to add under `[vars]`;
- sets each variable in the vault: secrets point at their credential, and plain config becomes a vault plain value, never a literal in the committed file. A row whose vault value you kept or replaced points at the credential that held the name, and one kept under another name at its new name. It never moves a variable a project already binds to another item, onto a new item or one already in the vault, and never sets a plain value over one: it prints `set to <slug> by another machine` and leaves it, as `--check` lists it. The one exception is an item already in the vault that this machine's approved batch, not yet applied, stored from that same variable. Variables you moved with **Keep both, this one under another name** were moved by the vault when you approved, so apply finds them already set;
- runs `mehen env check` for each environment;
- lists the variables in protected environments for you to set on the project page, and any `.env` that is committed to git, whose values you should rotate because history still holds them.

**A machine on 0.3.15 or earlier.** Its apply reads only the rows a batch created, so when another machine's row in the same batch replaces one of its rows, that row ends `mapped` and apply leaves its variable unset. Update it to 0.3.16 with `mehen update` and apply again.

The `mehen.toml` apply writes is new and untracked. Commit it, so colleagues' clones and your agents' worktrees get it. Until you do, `mehen init` in any other checkout of the repo binds it to the same project: on a machine that may use the project, it writes a `mehen.toml` naming the project and every variable it defines, and creates nothing ([A repo that is already a project](projects.md#a-repo-that-is-already-a-project)).

Without `--adoption`, apply takes every batch this machine submitted to for the plan's workspace that is still open or approved: it applies the ones approved so far and lists those still waiting, so run it again after each approval; applying a batch again changes nothing. `--adoption <adp_id>` applies one batch.

For a service it only prints the change the unit needs (`mehen run --env local --` before the command, the working directory, the names to remove from its environment). It never edits a plist or a unit: you, or the tool that owns the unit, make that change ([Keep a service running with mehen run](services.md)). `--repo <dir>` applies one repo, and `--env <env>` one environment.

## 7. Verify

```sh
mehen adopt verify
```

Verify proves the vault copy works without the local files. It checks the repos and services apply binds; one apply leaves alone, with no credential ticked or already in the vault, is left out, and retire still holds its files. For every name in each of their source files it checks that Mehen provides it for that repo and environment, or that the plan skips it on purpose. It runs `mehen env check`, and makes one read-only call through the vault for every item whose template has one (for example, listing models for an OpenAI key).

A **gap** is a name a program would lose if the file went: it is not in the plan, not declared in `mehen.toml`, does not resolve for that environment, or sits on a line that did not parse. Frameworks such as Bun, Next.js and Vite load `.env` by themselves, so a gap is exactly what would break. Fix each one (map it, declare it or skip it in the plan, then apply again) until verify says `verified`. Verify changes no file.

## 8. Retire (when you are sure)

Once verify passes and your programs have run on Mehen for a few days, `mehen adopt retire` takes the `.env` files Mehen has proven out of play. It never deletes one: it moves it to a quarantine folder and prints the command to put it back.

```sh
mehen adopt retire --compared compare.json
```

Without `--yes` it changes nothing. It lists every source file in the plan as `ready` or `held`, with every reason a held file is held. `--repo <dir>` and `--path <file>` list only those. A file is ready only when all of these hold:

- **It is a `.env`, or `NAME=value` lines in `.local-secrets`.** A `.envrc`, a JSON settings file, a plist or unit, a login file, a kubeconfig, or a key or certificate kept whole in a file is never moved: retire says to edit it by hand, and why.
- **It is yours to move.** A regular file, not a link and with no other hard link to it (its other names would share the quarantined copy), not tracked by git (a committed file says to rotate those values instead), and not changed since the newest snapshot that holds it. A file changed since then needs a new snapshot, export and compare.
- **Mehen provides every name in it.** Verify's checks for that file, run again by retire: no gap, no name left out of the plan (a name you left out is still needed by whatever reads the file), `mehen env check` passing, and every credential behind it passing its live check or having none.
- **A program gets these values from Mehen.** `mehen run` records each run it finishes in `~/.config/mehen/runs.jsonl`: when, how it exited, the folder of the `mehen.toml` it used, the project and environment, never the command line or a value. The file's repo or service needs a `mehen.toml` and at least 3 clean runs since its batch was applied, the first and the last at least 2 days apart, and its newest run must be clean. A run is clean when the program exited 0, or when it ended on a SIGINT or SIGTERM that `mehen run` itself received and passed on, as Ctrl-C on a dev server or a service manager's stop does; the run log records that signal with `forwarded: true`. A crash is never clean. `--min-runs` and `--min-days` change those numbers. A service that runs for weeks is logged only when it stops, so its file stays held until it has stopped cleanly often enough; once you have checked that the service gets its values from Mehen, name its file with `--path` instead. Apply records when it applied a batch only once every repo and service using it applied without an error and no `--repo` or `--env` left part of it out; until then it prints `when <adp_id> was applied is not recorded` with the reason, and retire holds the file. A file no repo or service reads, such as `~/.local-secrets/ci.env` that a tool reads by itself, is held until that program runs under `mehen run`, unless you name it with `--path` to say nothing reads it any more; the output notes that this check was skipped.
- **Your backup matches Mehen.** `--compared` names the output of `mehen backup compare --json` for the snapshot that holds the file and an export taken after the batch was applied, and every variable of the file is in its matching list. Where you kept the vault's value over a differing one, the file still holds the other value, so it never matches and retire holds the file: decide which value is right, then change the file or replace the vault's.

To make `compare.json`, take an export and save the batch's map on this machine:

```sh
mehen backup export --to ~/Backups/mehen
mehen adopt status adp_7Hq2xK --json > adoption.json
```

then, on the key machine, with the snapshot, the export and `adoption.json`:

```sh
mehen backup compare ~/Backups/mehen/snp_4fQ9cR2mT7.age ~/Backups/mehen/mehen-acme-2026-11-03-bkx_8Lm2pQ.age --identity - --map adoption.json --json > compare.json
```

`compare.json` holds names and counts, never a value; copy it back here ([Compare with Mehen](backup.md#6-compare-with-mehen)). For files adopted in another batch, compare with that batch's map. Without `--compared`, every file is held with these commands.

When the list is what you expect, move the ready files:

```sh
mehen adopt retire --compared compare.json --yes
```

It checks each file again just before it moves it, and moves it to `~/.config/mehen/adopt/<machine>/quarantine/<date>/<folder>/` (folders 0700, the file 0600), keeping a line per file in `quarantine/index.jsonl` there: both paths, the mode, and the quarantined copy's device, inode and times, never its size or a hash of it. Unretire adds a line for each file it puts back, and, when it copies one back from another volume, a line naming that copy's device, inode and mtime before it deletes the quarantined copy; neither ever rewrites the index, so one never loses a line the other adds. Before a move's first step it adds a line saying the move has begun, naming the hidden `.<name>.retiring_...` file the original is renamed to beside itself and where it goes, and it ends that line once the move is done or undone; if it cannot add that line, the file is not moved. A move a crash or kill cuts short is never lost: `mehen adopt retire`, with or without `--yes`, and `mehen adopt unretire` print `a move of <path> begun at <time> never finished`, with where the file is now and how to put it back by hand. It prints `moved <path> to quarantine; put it back with: mehen adopt unretire <path>` for each, then the count and the folder. A file that cannot be moved stays where it was, the others still move, and retire exits 1. A file that did move is always reported as moved; anything that went wrong after that is a note naming where the file is, and a file moved whose index line could not be written or saved, which unretire may then not find, makes retire exit 1 too. A move the index records as begun but whose original is still at its path, with nothing aside or in quarantine, is named as one that looks never to have moved. Run your programs as usual: they read their values from Mehen.

To put a file back, with the mode it had:

```sh
mehen adopt unretire ~/code/billing-api/.env
mehen adopt unretire --all
```

Unretire refuses a file whose path is taken again, or whose quarantined copy has changed or been replaced since it moved, leaving both for you to compare by hand. It never deletes or overwrites anything at the path: if a file appears there as it puts one back, or a copy from another volume does not read back as the quarantined one, that file is left as it is, the quarantined copy stays in quarantine and in the index, and unretire says to compare them by hand. If an unretire stops after it put a file back but before the index says so, the next one sees the quarantined copy is gone and the file at the path is that same file, or the copy the index says it made there, unchanged, and marks it restored with a note that it was already back, giving it its recorded mode again if it lacks it. The quarantine folder is yours: Mehen never deletes it. Delete it when you are sure, or keep it as one more copy.

## More machines

Each of your machines adds to the same batch, so you still approve once, as long as the batch has room: it holds 500 credentials from all machines together. On every other machine, scan, plan and take that machine's own snapshot, then:

```sh
mehen adopt submit --join adp_7Hq2xK
```

`--join` is no exception to the snapshot rule. The batch must still be open and yours. Submit asks the vault how much room the batch has left and uploads what fits, keeping each project's items together; the rest goes into a new batch, and it prints both. Give `--join` more than once to fill several open batches in order, for example after the first machine's plan already took two: `mehen adopt submit --join adp_7Hq2xK --join adp_9Rt4mW`. The review page shows which machine each row came from. Each machine's rows carry refs of their own in the batch, a tag from the machine followed by the plan's number (`a001` becomes something like `a7kq001`); `mehen adopt status` on that machine shows them by the plan's refs again.

Machines that share a repo plan the same names for it, such as `openai-billing-api`, and the vault holds each name once. So `--join` reads the names already in each batch it joins. An item whose name another machine staged there goes as a row to be compared with that machine's row, and the reviewer sees whether the two values agree and decides, as for a [value already in the vault](#values-already-in-the-vault). A workspace credential's name, such as `openai`, is compared the same way. Only this machine's own row already in the batch is left out: submit prints `not uploaded: openai-billing-api: this machine's own row for it is already in adp_7Hq2xK, so it was not sent again`. Once the batch is approved, `mehen adopt apply` on this machine sets its variables as the decision says, and `mehen adopt verify` checks that copy works here.

## See every name in one place

The inventory page, `https://app.mehen.dev/w/<slug>/adopt`, lists every name your adoptions touch, from all your machines: the rows in your open batches, what your approved batches stored, kept or replaced, and each machine's latest index, the plan it last submitted, ticked or not. For each name it shows the kind, home, machines and files with when each changed, the projects and environments it backs, and whether the copies agree where the review page would show it. A team machine's index is seen by owners and admins. A machine's index is replaced by its next submit and dropped after 30 days, or when the machine or its member is removed.

On a machine, `mehen adopt inventory` prints this machine's side: every plan item with its kind, home, files and when each changed, the variables it backs and whether it is included, possibly stale or stored only; then, for each batch it submitted to, what became of its rows; then the page's link:

```
/Users/sam/.config/mehen/adopt/sam-laptop/plan.json: 2 items (2 included) for workspace acme on sam-laptop
a001 openai-billing-api (api-key, project:billing-api): included
  from /Users/sam/code/billing-api/.env OPENAI_API_KEY, changed 2026-11-01T09:12:44.000Z
  used by billing-api dev: OPENAI_API_KEY
a002 session-secret-billing-api (generic, project:billing-api): included
  from /Users/sam/code/billing-api/.env SESSION_SECRET, changed 2026-11-01T09:12:44.000Z
  used by billing-api dev: SESSION_SECRET
batch adp_7Hq2xK: approved, expires 2026-11-05T10:00:00.000Z; https://app.mehen.dev/w/acme/b/adp_7Hq2xK
  a001: mapped to openai-billing-api
  a002: left out
inventory page: https://app.mehen.dev/w/acme/adopt
```

A row's outcome is `created` (with the name it was stored under), `mapped to` or `replaced` (with the credential that held the name), `refused` with the vault's reason, `left out`, or `waiting for review` while the batch is open. The command reads the plan, this machine's adopt state and each batch's status, the same answer `mehen adopt status` gets, and nothing only your account sees, so a machine learns no name it could not already see, and never a value or whether values agree. A batch the vault no longer answers for (for example after this machine re-enrolled) is listed with its outcomes unknown. `--json` prints `{ plan, workspace, machine, items, batches, url }`, and `--workspace <slug>` picks the workspace as for the other steps.

## What is listed as possibly stale

The plan lists a source as possibly stale when the file has not changed for 12 months, sits under an `archive`, `archived`, `old` or `attic` folder, a folder put aside with a suffix (`ci-runner.retired-20261003`, `ci-runner-retired`, `ci-runner_retired_20261003`, `app.bak`, `app.bak-20261027`, `app.backup.1`, `config.old`, `config.old-2024`, `billing-old`, `app.orig`, `app~`; a `-old` folder that is itself a repo with an `origin` stays live) or a test or example folder (`test`, `tests`, `fixtures`, `testdata`, `examples`), is a backup copy (`keys.env.bak-20261027`, `.env.orig`), belongs to a repo with no commit for 12 months or no `origin`, or a newer file in the same folder holds the same name with another value. For a repo, the same folder includes that folder in its other worktrees and clones, so an old worktree's `.env` is superseded by a newer one in the main checkout. It leaves the item out when every file holding that value is possibly stale; a value also in a fresh file is current, and the item's note counts the stale copies. Adopting a dead key only adds noise. Check each one: if it is still in use, set `include` to true in the plan; if not, revoke it at the provider.

A value found only in backup copies makes no item, so there is nothing to tick. The plan lists each of its sources as possibly stale with the reason `backup copy only: not adopted; add it by hand if you still use it, or revoke it`, and the possibly stale count on the `planned ...` line of `mehen adopt plan` includes them. If you still use it, add it from the web app; if not, revoke it at the provider. An old key left in a plaintext `.env.bak` is worth revoking either way.

## Undoing

- **Before approval:** `mehen adopt cancel adp_7Hq2xK`, or **Cancel batch** on the page. The staged values are dropped and nothing is stored. An unapproved batch also ends by itself after 24 hours, or when the days it was kept open for run out.
- **After approval:** your files are as they were until you retire them, so nothing local needs undoing; `mehen adopt unretire --all` puts back every file retire moved. A vault value you replaced on the review page is kept for 30 days: **Restore it with passkey** on the credential's page puts it back. Delete a `mehen.toml` that apply wrote if you do not want it, and delete any credential you did not mean to keep from its page under Credentials in the web app.
- **A file lost or changed by something else:** restore it from the snapshot with `mehen backup restore` ([Back up a machine before adopting](backup.md#5-restore)).
