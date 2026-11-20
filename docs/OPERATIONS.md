# Operations

How to run your own Mehen Cloud deployment: the vault (the Worker `mehen-app`, from `apps/vault`), its secrets, the database, deploys, rebuilding and releasing `mehen`, release keys, local development, key rotation, backups, freezing, revoking devices, reading the audit chain, what to do when a device key leaks, and platforms, with the operator console and platform admins. Then the lander (the Worker `mehen-web`, from `apps/web`) and the docs site (the Worker `mehen-docs`, from `apps/docs`).

The examples use the names of the reference deployment: the zone `mehen.dev`, the vault at `https://app.mehen.dev`, the lander at `https://mehen.dev` and the docs at `https://docs.mehen.dev`. Put your own names in their place. All three Workers live on one Cloudflare account, in one zone. Only the operator (whoever runs the deployment, from a machine no agent reaches) deploys, creates Cloudflare resources or sets secrets.

The committed `wrangler.jsonc` files are templates: they carry no account id, placeholder resource ids and the feature switches off. [Your deployment's identity](#your-deployments-identity) says what to fill in before the first deploy.

Commands run from `apps/vault` unless stated. From the repository root, run a package's scripts as `bun run --cwd apps/vault <script>`; `bun --cwd apps/vault run <script>` prints Bun's help on 1.4.2 and runs nothing.

## Your deployment's identity

The committed `wrangler.jsonc` files describe a deployment without naming one. Before the first deploy, fill in your own values in a copy you keep out of the repository (or in your fork's own commit, if the fork is private):

| File and key | Committed | Yours |
| --- | --- | --- |
| every `wrangler.jsonc`: `account_id` | absent | Set `CLOUDFLARE_ACCOUNT_ID` in the shell that deploys, or add `account_id`; with neither, Wrangler uses the account you are logged in to and asks when there are several |
| `apps/vault`: `routes`, `vars.VAULT_ORIGIN`, `vars.RP_ID` | `vault.example.com` | The host name the vault answers on. All three change together ([Custom domain](#custom-domain)) |
| `apps/vault`: `d1_databases[0].database_id` | all zeros | The id `bunx wrangler d1 create mehen --jurisdiction eu` prints ([Database (D1)](#database-d1)) |
| `apps/vault`: `vars.GOOGLE_SIGNIN_CLIENT_ID` | empty | Your Google OAuth client's id, with `GOOGLE_SIGNIN_CLIENT_SECRET` set as a secret; empty hides Google sign-in |
| `apps/vault`: `vars.APPLE_WEBCREDENTIAL_APPS` | empty | Your native apps, `TEAMID.bundle.id`, comma-separated; empty serves no association file |
| `apps/vault`: `vars.EMAIL_FROM`, `send_email[0].allowed_sender_addresses` | `no-reply@example.com` | An address in a zone you onboarded to Email Sending ([Email Sending](#email-sending)) |
| `apps/vault`: `vars.POLICY_RULES`, `APPROVAL_BATCHES`, `BROWSER_FILL`, `PUSH`, `POLICY_POSTURES`, `MANDATES`, `APPROVAL_DIAL` | `off` (`APPROVAL_DIAL` unset, which is off) | `on`, `off`, or the workspace ids to try each in first ([Database (D1)](#database-d1) describes each) |
| `apps/vault`: `vars.STEPUP_GRACE` | `on` | `on` or `off` |
| `apps/web`, `apps/docs`: `routes` | the reference deployment's hosts | Your own, if you deploy the lander or the docs at all |

The bucket names (`mehen-vault-backups`, `mehen-releases`), the database name (`mehen`), the service binding to `mehen-web` and the rate limiter namespaces are the same for every deployment and stay as committed. The `test` and `local` environments need nothing filled in: the test suite and `wrangler dev -e local` run as committed. Never deploy the template unfilled: it would point the vault at `vault.example.com` and a database that does not exist.

## Ground rules

- **Never generate, view or store vault secrets on a machine an agent runs on**, if you can avoid it. That includes every enrolled device. Use a machine (or a live, offline session) that no agent can reach.
- **Never put a vault secret in a repo, in a local secrets folder, in a chat, or in the vault itself.** The one file allowed is the first deploy's secrets file (below): mode 0600, outside every repo and synced folder, and removed or moved to the offline escrow once the deploy is done.
- Secrets never go in `wrangler.jsonc`. Its `test` environment carries test-only keys that are worthless elsewhere; never reuse them.

## The secrets

| Secret | What it is | Backed up? |
| --- | --- | --- |
| `ROOT_KEYS` | JSON map of root key version to the base64url of 32 random bytes, for example `{"1":"<43 characters>"}`. The highest version encrypts new fields and keys the fingerprints; every listed version decrypts. | **Yes, offline. Losing every root key means losing every secret in every workspace.** |
| `SEAL_PRIVATE_JWK` | The P-256 ECDH private key, as a JWK (`kty`, `crv`, `x`, `y`, `d`), that the browser seals secret fields to. | No need. Nothing at rest depends on it; replacing it only breaks seals in flight. |
| `BOOTSTRAP_CODE` | A one-time code, at least 8 characters, that is the operator's invite for the first account. It works only while no account exists. | No. Delete it after first use. |
| `GOOGLE_SIGNIN_CLIENT_SECRET` | The client secret of the vault's own Google OAuth client, used only to verify Google identities for the [identity gate](https://docs.mehen.dev/concepts/workspaces#the-identity-gate). Optional: without it, Google entry points are hidden. | No. Rotate it at Google and set it again. |

Non-secret settings live in `wrangler.jsonc` `vars`: `VAULT_ORIGIN` (for example `https://app.mehen.dev`, the prefix of every URL the vault prints), `RP_ID` (for example `app.mehen.dev`, the WebAuthn relying party), `GOOGLE_SIGNIN_CLIENT_ID` (the public id of that Google client, whose registered redirect URI is `https://app.mehen.dev/auth/oidc/google/callback`), `APPLE_WEBCREDENTIAL_APPS` (the native apps that may use passkeys and the gate callback for this host) `WORKSPACE_CREATION` (`accounts`: every account may create workspaces unless an operator denied it; `operator`, or unset: only accounts an operator allowed; also the widest the operators' Settings may set; see Who creates workspaces under [Deploy](#deploy)) and `SIGNUP_MODE_MAX` (the widest sign-up the operators' Settings may set: `invite`, `request` or `open`; missing or anything else is `invite`; production and local development set `invite`; see [Settings](#settings)).

The server refuses a root key that does not decode to exactly 32 bytes, a version that is not a positive integer, and an empty map.

### The first deploy: a secrets file

For the first deploy, upload all three secrets with the code, so the Worker never runs without them. `wrangler deploy --secrets-file` takes a JSON file of name to string value, and is additive: secrets left out of the file are kept.

On the operator machine, with Bun and the repo checked out:

```sh
cd apps/vault
umask 077
SECRETS_DIR=$(mktemp -d)
bun -e '
const b64url = (bytes) => Buffer.from(bytes).toString("base64url")
const root = b64url(crypto.getRandomValues(new Uint8Array(32)))
const k = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
const j = await crypto.subtle.exportKey("jwk", k.privateKey)
const secrets = {
  ROOT_KEYS: JSON.stringify({ "1": root }),
  SEAL_PRIVATE_JWK: JSON.stringify({ kty: j.kty, crv: j.crv, x: j.x, y: j.y, d: j.d }),
  BOOTSTRAP_CODE: b64url(crypto.getRandomValues(new Uint8Array(24))),
}
await Bun.write(process.argv[1] + "/secrets.json", JSON.stringify(secrets))
' "$SECRETS_DIR"
```

Then, in the same sitting:

1. Copy `ROOT_KEYS` to the offline escrow (see [The root key](#the-root-key)). Wrangler cannot read secrets back.
2. Hand `BOOTSTRAP_CODE` to the first owner out of band.
3. Deploy with the file (see [Deploy](#deploy)): `bunx wrangler deploy --secrets-file "$SECRETS_DIR/secrets.json"`.
4. Remove the file: `rm -rf "$SECRETS_DIR"`.

### Setting one secret later

Pipe the value straight into `wrangler secret put`, without writing it to a file:

```sh
# a new seal key
bun -e 'const k = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
const j = await crypto.subtle.exportKey("jwk", k.privateKey);
process.stdout.write(JSON.stringify({ kty: j.kty, crv: j.crv, x: j.x, y: j.y, d: j.d }))' \
  | bunx wrangler secret put SEAL_PRIVATE_JWK

# the whole ROOT_KEYS map, from the escrow
printf '%s' '{"1":"<existing>","2":"<new>"}' | bunx wrangler secret put ROOT_KEYS

# after the first owner has signed up
bunx wrangler secret delete BOOTSTRAP_CODE
```

A new root key is `openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'`.

## Database (D1)

The global directory is a D1 database (`mehen`, EU jurisdiction) bound as `DB`. It holds no secrets: accounts, workspaces and their slugs and aliases, memberships, passkeys, web and app sessions, recovery codes, challenges, invite codes, pending enrolments, Google identities and sign-in flows, and OAuth `state`, with every token and code hashed. It is created once, before the first deploy, with `bunx wrangler d1 create mehen --jurisdiction eu`, and its id replaces the placeholder in `wrangler.jsonc` (`d1_databases`). Migrations are numbered and append only:

| Migration | What it does |
| --- | --- |
| `migrations/0001_directory.sql` | The pre-workspace directory: one tenant, its members, passkeys, sessions, invites, challenges |
| `migrations/0002_identity.sql` | Enrolments (the code hashed) and OAuth `state` |
| `migrations/0003_enrol_group.sql` | The typed hidden-group counter on enrolments and one live link per key |
| `migrations/0004_auth.sql` | Named passkeys, recovery codes, session metadata, member status and restriction, reset links, security notices |
| `migrations/0005_accounts.sql` | The workspace directory: drops the pre-workspace tables (a fresh start, nothing is migrated) and creates accounts, workspaces, slugs and aliases, memberships, security transitions, passkeys, sessions, recovery, challenges, notices, invite codes, account events, enrolments, OAuth `state`, enrol nonces and auth attempts |
| `migrations/0006_oidc.sql` | Google identities, sign-in flows and results for the identity gate |
| `migrations/0007_cutover.sql` | The fresh-generation marker (`workspace_cutover`, one row naming the generation) that the readiness check reads, and the hashed queue of operator break-glass intents |
| `migrations/0008_needs_you.sql` | The renewable enrolment lease (hard cap, renewal metadata, expiry reason), the persisted hidden fingerprint group, the start session label, the claimed account, the connect codes and the inbox indexes |
| `migrations/0009_requested_scope.sql` | What a machine asked for at enrolment (`requested_scope`), when it asked for less than the usual scope; additive |
| `migrations/0010_platforms.sql` | Platform mode ([Platforms](#platforms)): `platforms` (slug, name, status, the operator's limits, the platform's defaults and their revision), `platform_keys` (public JWKs only), `managed_workspaces` (one row per subject: its `tn_` id, status, purge date and, once purged, only the subject's hash) and `platform_events` (the operator's actions); additive, and holds no secret |
| `migrations/0011_platform_delete_attempts.sql` | When the cron last tried to delete a subject marked `deleting` (`managed_workspaces.delete_attempted_at`), so it takes the least recently tried first; additive |
| `migrations/0012_operator_console.sql` | The operator console ([The operator console](#the-operator-console)): the operator role on an account (`accounts.is_operator`, set by `scripts/operator.ts` or an applied two-operator proposal, whose trigger writes the operator event and the account's notice), `platform_admins` (a platform's admins, ended rather than deleted) and the removal columns on `platforms` (`removing_at`, `removing_by`, `removed_at`, `removed_slug`); additive |
| `migrations/0013_vault_backups.sql` | The operator's backup ([Backup and recovery](#backup-and-recovery)): `vault_backup_runs` (each workspace's daily dump: date, bytes, sha256, root key version and outcome) and `vault_restore_intents` (the restores `scripts/vault-backup.ts` records, hashed, which the cron carries out); additive, and holds no secret |
| `migrations/0014_device_cli_versions.sql` | The fleet view ([Releasing the CLI](#releasing-the-cli), step 7): `device_cli_versions`, one row per active machine with the CLI version its `mehen/<x.y.z>` User-Agent named and when that version was first seen, written by the machine's workspace object when the version changes and deleted when the machine is revoked, read by `scripts/fleet-versions.ts`; additive, and holds no name and no secret |
| `migrations/0015_operator_proposals.sql` | Several operators ([Operators](#operators)): `operator_proposals` (a change to the operator role one operator proposes and another approves, with `CHECK`s that refuse an approval by the proposer and a target that is the proposer or the approver, and one open proposal per kind and target) and `deployment_events` (every operator action outside a platform, with its proposer and approver); additive |
| `migrations/0016_email_proofs.sql` | Emailed invitation codes ([Email Sending](#email-sending)): `email_proofs`, one row per six-digit code sent to an email-bound invitation's address, with the code only as an HMAC under a key derived from `ROOT_KEYS`, the browser it was sent to (its cookie hashed), its tries, its place among the invitation's sends that hour (rows are kept a day, and indexed by invitation and by address, for the daily limits), and its state once typed back (a proof the sign-up and the join take as they take Google's); additive, and holds no code |
| `migrations/0017_account_suspension.sql` | An operator's suspension of an account ([Accounts](#accounts)): `accounts.suspended_at` and `accounts.suspended_by` (an `operator:` actor), both NULL while it is not suspended; additive, no table rebuild |
| `migrations/0018_deployment_settings.sql` | The operators' Settings ([Settings](#settings)): `deployment_settings` (one row per setting the operators have set, with who set it last, whose `CHECK` refuses a change with no `operator:` actor), and the indexes the Audit view ([Audit](#audit)) reads `platform_events` and the `operator.*` rows of `account_events` by; additive |
| `migrations/0019_invite_emails.sql` | Emailed invitation links ([Email Sending](#email-sending)): `invite_emails`, one row per link emailed as an invitation was made (the address, the inviting account, the workspace and when), indexed by address and by inviter for the limits and swept after a day; additive, and holds no link or code |
| `migrations/0020_enrolment_prune.sql` | The index the enrolment prune step for attempts that never reached a workspace reads expired enrolments by, oldest first (`enrolments_settled` on status and `created_at`); additive, `CREATE INDEX IF NOT EXISTS` |

```sh
bunx wrangler d1 migrations list mehen --remote
bunx wrangler d1 migrations apply mehen --remote
```

**Apply D1 migrations before deploying code that needs them.** On a new database, apply every migration, in order, before the first deploy. 0005 to 0007 replaced the pre-workspace directory with the workspace one: 0005 drops the earlier tables and nothing in them is carried over, so on an empty database they simply build the current schema.

**Two readiness guards, both fail closed.** No session, account, device or workspace route runs until the readiness check has passed: the directory has no legacy table, the D1 marker names the current generation, and the bound Durable Object class answers with the same generation. The check runs after the rate limiter (a rate-limited request never reaches it), a passing result is cached per isolate for about a minute and keyed to the actual database and namespace bindings, and a failure is never cached; so a marker or schema change made under a running Worker is noticed within about a minute, and when the check fails, every request that passes the limiter is refused with `upstream_failed` and `retryAfter: 60`, which is an incident to repair, never a guard to disable. Inside storage, the fresh class refuses to serve unmarked storage that holds known legacy application tables (Cloudflare's own internal tables do not count), so a legacy object can never be adopted by accident; nothing is adopted, renamed or migrated across the class boundary.

**Durable Objects.** The bound class is `WorkspaceVault` (binding `TENANT_VAULT`), a fresh namespace over the `TenantVault` implementation. The `wrangler.jsonc` migration tag `v2-workspaces-fresh` adds `new_sqlite_classes: ["WorkspaceVault"]` after the original `v1` tag, and a separate tag `v3-tenant-vault-deleted` adds `deleted_classes: ["TenantVault"]` (its own tag, because Cloudflare refuses to delete a class that the live version still binds, code 10061). A new deployment applies every tag in order on its first deploy. Platform mode adds the class `PlatformVault` (binding `PLATFORM_VAULT`, one object per platform, named by its `plt_` id, holding no secret: the platform proofs' spent nonces, its limits' one-minute counters, the last 25 hours of calls counted by route and outcome, and its own audit of platform-level changes, defaults and delete-all) under the tag `v4-platform-vault`; managed workspaces are ordinary `WorkspaceVault` objects. Tags are append only; never edit an earlier one. Each area (`src/vault/areas/*.ts`) still carries its own append-only SQL migrations, applied in order inside each workspace's object when it next starts; there is nothing to run by hand.

**Rolling back the vault keeps every area migration that has run.** An object records how many of each area's migrations it has applied (`_migrations`), and refuses to start when its code carries fewer (`applyMigrations`: "area ... has fewer migrations than applied"). So once a deploy has added an area migration and any workspace object has started on it, a rollback that removes that entry from `src/vault/areas/*.ts` stops every such workspace: roll back by reverting the code that uses the new tables while keeping the migration entry itself, never by a plain revert of the commit that added it. This holds for the `policy` area's third migration (`WORKSPACE_POLICY_RULES_MIGRATION`: standing rules, `policy_rules` and `policy_rule_anchors`, and the `rule_terms` and `stage` columns on `policy_proposals`), which runs on deploy even with `POLICY_RULES` off.

**`POLICY_RULES` takes three forms** (`apps/vault/wrangler.jsonc` vars; `policyRulesOn` in `src/vault/areas/policy-rules-workspace.ts` reads it for the Worker's routes and pages and for each workspace's object alike):

- `"off"`: standing rules are off for every workspace.
- `"on"`: standing rules are on for every workspace.
- a comma-separated list of workspace ids, such as `"tn_AAAAAAAAAAAAAAAAAAAAA, tn_BBBBBBBBBBBBBBBBBBBBB"`: on for those workspaces only, which is how to try a switch in a few workspaces before everyone. Name each by its `tn_` id (the operators' Workspaces page shows it), never by its slug, which a rename changes. Whitespace around each id is ignored.

Any other value fails closed: one entry that is not a `tn_` id (a slug, `on` inside a list, an empty entry from a stray comma) turns standing rules off for every workspace, the listed ones too. A workspace the list leaves out answers exactly as with `"off"`. Taking a workspace off the list does not delete its rules: they stop applying, and apply again if it is listed again before they end. The request copies the vault kept for them are still deleted at their usual time.

`APPROVAL_BATCHES` (batch approvals: asks record their review group, shape and floor, a machine may replace its own open ask, and it may ask for up to 20 requests at once as a bundle through `POST /v1/approvals/bundles`, read back with `GET /v1/approvals/bundles/:id`) takes the same three forms, read by the same parser (`workspaceSwitchOn` in `src/vault/workspace-switch.ts`). The `approvals` area's batch migration runs on deploy even with it off.

`PUSH` (a machine may ask to put a credential into GitHub, Vercel, Cloudflare or Fly, and the vault sends it after a human approves) takes the same three forms, read by the same parser. Off, a push ask and the credential page's allowance answer `forbidden` "Pushing is not available yet."; the `pushes` area's migration and the items `pushable` column are added on deploy even with it off.

`BROWSER_FILL` (fill: an item's fill ceiling and the pages it may be typed into, fill in a machine's or workload's modes, and `POST /v1/fill`) takes the same three forms and parser. Off, a fill ceiling, a change to an item's pages and fill in a machine's or workload's modes are refused with `mode_refused` "Typing into web pages is not available yet.", and `POST /v1/fill` with `forbidden` "Typing into web pages is not available in this workspace." The `browser` area's tables and the items `browser` column are added on deploy even with it off.

`POLICY_POSTURES` (how careful a credential is: a person who may change a credential may set it to let routine building through or to trust the machines of those who manage it, the relay lets what that covers through without asking, and the home counts asks for its nudge) takes the same three forms, read by the same parser. A managed workspace has no postures whatever it says. Taking a workspace off the list keeps each credential's posture but stops it applying; the `items` area's posture migration runs on deploy even with it off.

`APPROVAL_DIAL` (the approval dial: an owner or admin chooses how often Mehen asks in a workspace, Ask on writes or Let it work, on its Settings page; Let it work lets through what a credential's posture trust would and refuses what would still ask, instead of asking) takes the same three forms, read by the same parser. The template leaves it unset, so it is off; local dev and the test env have it on. Off, or in a managed workspace, the setting cannot be changed (`forbidden`), the settings read leaves it out and every workspace asks as Ask on writes, whatever it stored. Taking a workspace off the list keeps its stored level, which applies again if it is listed again.

`MANDATES` (a person signs terms in advance, with a passkey, for one of their own machines) takes the same three forms, read by the same parser; the `mandates` area's migration runs on deploy even with it off.

`STEPUP_GRACE` (passkey grace: after a real passkey confirmation or a passkey sign-in, the same browser session confirms further actions for 15 minutes without asking again, except the actions `WORKSPACE_STEP_UP_GRACE` in `packages/protocol/src/step-up-rules.ts` marks fresh) is per account, not per workspace: `"on"` or off, and any other value is off. Off, no window is opened, a step-up start always asks for the passkey, and a proof that rides a window is refused. The template and local dev have it on; the test env has it off. The app's `/app/v1/stepup` never offers a window whatever it says. A window is never opened or used while the account has a pending security change or is cooling off, and starting either deletes the account's windows. Every audit row a confirmation that rode a window wrote, private records included, carries `confirmation: { kind: "grace", provenAt }`, `provenAt` being when the passkey was used.

## Deploy

```sh
bun install --frozen-lockfile
bun run typecheck
bun test packages/protocol apps/cli
bun run --cwd apps/vault test
cd apps/vault
bunx wrangler d1 migrations apply mehen --remote
bunx wrangler deploy        # mehen-app; or: bun run deploy
```

The server suite runs in workerd with a 20 second timeout per test (`testTimeout` in `apps/vault/vitest.config.ts`), so the end-to-end scenarios survive a loaded CI host; a test that needs longer is a test to split.

**`wrangler deploy` builds the web UI itself:** `wrangler.jsonc` has `build: { command: "bun scripts/build-ui.ts" }`, which bundles `src/ui/client` into `dist/assets/app.js` and `dist/assets/app.css`. The Worker serves them from the `ASSETS` binding at `/assets/*`; every page is rendered by the Worker. `bun run build:ui` runs the same build on its own.

**The docs are on the docs site, not in the vault.** The vault's old `/docs` and `/docs/<slug>` answer a 301 to the matching page on `https://docs.mehen.dev`, signed in or not, and anything else under them to its home (`DOCS_REDIRECTS` in `src/routes/ui.ts`). `README.md` and the documents in `docs/` other than `docs/site/` are not served anywhere; [The docs site](#the-docs-site) says how the public pages are built and deployed.

**The UI check is the gallery.** `apps/vault/scripts/ui-gallery.ts` renders every page in every state (home, credentials, item, machines, projects, audit, and the enrol, intake, connect and approval pages open and closed, with hostile text) at 390, 1024 and 1280 pixels in light and dark, from fixtures, and screenshots them with headless Chrome:

```sh
cd apps/vault
bun run build:ui
bun scripts/ui-gallery.ts /tmp/mehen-gallery    # one <id>.html per state, png/<id>-<width>-<scheme>.png and index.html as a contact sheet
```

It also checks every page's layout at each width and prints what it finds: the page scrolling sideways, text squeezed into a narrow column, anything spilling out of its card (`layout.json` keeps the list). Every page CSS file is bundled into one `app.css`, so a class one page styles reaches every other page that uses the same name; the check is what catches that. Look at the PNGs before deploying a UI change. `bun scripts/contrast.ts` checks the colour pairings.

After a deploy, check:

```sh
curl -s https://app.mehen.dev/healthz          # {"ok":true}
curl -s https://app.mehen.dev/v1/seal-key      # { jwk, kid }
curl -sI https://app.mehen.dev/signin          # 200
```

**The first account and workspace.** After the first deploy, the first person opens `https://app.mehen.dev/signup#<BOOTSTRAP_CODE>`, registers a passkey and saves their recovery codes. That creates their account, and in the same guarded signup batch grants it the right to create workspaces (recorded as `operator:bootstrap`, with the operator event and the account's notice); it creates no workspace by itself, and the first person goes straight on to create one. Then delete `BOOTSTRAP_CODE`.

**Who creates workspaces.** Every account exists only through an invitation, so every account was invited by a person. Workspace creation is on for every account by default: production sets `WORKSPACE_CREATION` to `accounts` in `wrangler.jsonc`. The operators may narrow that default in the app to only accounts an operator allows, and widen it again up to `WORKSPACE_CREATION` ([Settings](#settings)). Creating one still needs a passkey step-up, recovery set up, no cooling-off after a recovery and no account security change pending, and there is no cap on how many workspaces an account creates, or on how many members or open invitations a workspace has. An operator decides for one account on its page in the Accounts view ([Accounts](#accounts)): Allow, Deny or Back to default, each with one operator's passkey, and that decision wins over the default. Allow is needed only to undo a deny, or while the default is only accounts an operator allows (the Settings view's, or a deployment that sets `WORKSPACE_CREATION` to `operator` or leaves it unset), where an account creates workspaces only once allowed. The console writes the columns, the operator event and the account's notice the script writes, and a `deployment_events` row. The script stays as the break-glass, from the operator's machine:

```sh
cd apps/vault
bun scripts/operator.ts --remote deny-workspaces acc_<id> --actor operator:<your-name>    # stop this account creating workspaces
bun scripts/operator.ts --remote allow-workspaces acc_<id> --actor operator:<your-name>   # undo a deny
```

The script says where the account's permission comes from now (the deployment default, or allowed or denied by which operator), prints the D1 time-travel bookmark, and asks for the account id typed back. An `UPDATE` that changes the flag writes the operator event and the account's notice in the same statement, through its trigger. Denying an account the operator never decided on leaves the flag as it was, so that trigger writes nothing: the script then writes the same `operator.deny_workspaces` event and notice itself, in the same batch as the `UPDATE`, and only if the `UPDATE` recorded the deny. The operator's list page in the console says which default is in force; the account's own read (`GET /api/account`) gives `canCreateWorkspaces` and `workspaceCreation` (`default`, `operator-allowed` or `operator-denied`), and its New workspace page says when the operator turned creation off for it.

An account that may create them creates its workspaces on `/workspaces` (`workspace.create`, a passkey step-up) and invites everyone else from each workspace's People page: an owner or admin invites with a role, teams and project shares, an email-bound invite is proved with Google before it can be redeemed, and the membership is active once an owner or admin confirms it. An account that has lost every passkey and recovery code is recovered only by the operator's [account break-glass](#account-break-glass); no workspace role can reset another person's factors.

**Enrolling the first machine.** The easiest way is the workspace's Connect an agent page: it gives the human one line to paste into their agent, which follows `https://mehen.dev/setup.md`. By hand, on the machine: `mehen enrol --workspace <slug>` prints the link and exits; `mehen wait enr_...` finishes it. The person whose machine it is opens the link (or scans the QR code; eligible deciders may also find the enrolment under Needs you), checks the words and the three fingerprint groups the page shows, when and from where the machine asked, and the scope it will get, types the hidden group from the terminal, and accepts with a passkey; a team's machine (`--team <team-slug>`) is admitted by an owner or admin instead. A link lives 60 minutes and `mehen wait` renews it in place, up to 24 hours.

**Connect codes.** The Connect an agent page mints a connect code for the signed-in member (`POST /api/w/:ws/connect-code`): hashed in D1, bound to that account and workspace for 24 hours, rate limited per account. An enrolment started with it is claimed for that account and lands in their Needs you; only they can accept it. Every refused code (unknown, malformed, expired, another workspace, a removed account or membership, a suspended member) answers with the same bytes after the per-address limiter (`enrol-connect:<ip>`, 20 a minute). The refusals are not constant-time: a well-formed code that still matches a suspended member's row costs one more workspace lookup before the same refusal, and a workspace that is unavailable at that moment answers with an error instead. That distinguishes a matching suspended member's code from an unknown one; it reveals no account or workspace name. Do not describe the refusal as timing-indistinguishable, and treat the per-address limit as a bound on one address, not on a distributed guesser.

The Worker has a cron trigger every 15 minutes that deletes expired challenges, sessions, recovery codes, OAuth states and connect codes (and codes whose account or membership is no longer active), expires pending enrolments past their 24-hour hard cap and Google sign-in flows, deletes, in a step of its own, each enrolment that never reached a workspace once it is past its hard cap, with no 30-day wait, deletes, in another step, each expired or rejected enrolment 30 days past its hard cap once its workspace has heard of it or when the workspace it names does not exist (by id, slug or old slug), finalises workspace renames, delivers queued workspace notices, reconciles enrolments whose reply was lost, carries out recorded workspace restores and dumps each workspace to R2 once a day ([Backup and recovery](#backup-and-recovery)). An enrolment that never reached a workspace is one expired at its hard cap or superseded by the same key, claimed and accepted by no account, and never recorded as registered in its workspace (no tenant); any copy a workspace object holds of it is refused for everything past its hard cap. Each of the two enrolment prune steps deletes oldest first in batches of 500, at most 10 batches a run, and stops at the first batch that comes back short: at most 5,000 rows a step a run, 480,000 a day, more than the 172,800 starts one address can make in a day within `RATE_LIMITER` (120 a minute). A deleted attempt still answers its poll and renewal as expired (`hard_cap`), so its machine starts afresh.

**Reconcile fair progress.** The enrolment reconcile scan (`reconcileEnrolmentMirrors` in `directory/workspace-enrolment.ts`) keeps two queues. Rows D1 has already settled (expired or rejected, their source not yet told) drain oldest first, in batches of 50, at most 4 batches a run (200 rows a run, 19,200 a day), stopping at the first short batch, and leave the scan once their source acknowledges; a row whose source fails is asked once a run and stays for the next. A row that never reached a workspace (the same test as the prune step that deletes it at its hard cap) is not in this queue: that step takes it without its source being told, so a flood of anonymous starts never takes this queue's places. Pending rows, live or lapsed, which may have nothing to do until their 24-hour hard cap, are visited in a window that moves on by one batch every 15 minutes, so a later start whose acceptance reply was lost is reached behind any number of earlier starts: with a backlog of N pending rows, within ceil(N / 50) runs (96 runs a day cover 4,800 pending rows). Lapsed attempts are never expired early: that would break the lease. A growing count of unreconciled rows still deserves a look, since a source that keeps failing is retried every run and logs `enrol.source_reconcile.pending`.

## Rebuilding `mehen` for a test machine

The CLI is a standalone binary built from `apps/cli` with the protocol compiled in. Machines with a released `mehen` update themselves (https://docs.mehen.dev/security/keys-and-signing#releases); rebuild by hand only to test a change before it is released.

```sh
cd apps/cli
bun scripts/build.ts --target darwin-arm64      # one target; repeat --target for more, or leave it out for all four
bun scripts/build.ts --no-mehen-se                 # skip the Secure Enclave helper (it builds on macOS only)
```

Targets are `darwin-arm64`, `darwin-x64`, `linux-x64` and `linux-arm64`; the binaries land in `apps/cli/dist/` as `mehen-<target>`, with the Secure Enclave helper embedded in each darwin binary. `bun run --cwd apps/cli build` builds every target. To install one, move it into place with `mv` on the same filesystem (usually `~/.local/bin/mehen`); never `cp` over a running binary. A hand-placed binary is recorded by the next update as installed by hand: it is not signed, the background updater replaces it with the next signed release, and a running `mehen mcp` never switches to it. Enrolments live under `MEHEN_HOME` (default `~/.config/mehen`, one slot per workspace), not in the binary, so a rebuild keeps them. `mehen status` prints the fingerprint `mehen enrol` recorded; a machine enrolled before `mehen` recorded it shows the one the vault holds for its key (from `GET /v1/me`), marked as such, and needs no re-enrolment.

## Releasing the CLI

Run this from the repository root on a Mac. Only the operator creates the bucket, uploads or deploys. Building is local and does not touch the vault or enrolment. The public downloads have no credentials in them.

Every release is signed with a release key ([Release keys](#release-keys)); `--release` refuses to start while `packages/protocol/src/release-keys.ts` holds none.

1. Set `version` in `apps/cli/package.json` to a new semver version, above every published one, commit it and every release change, and leave the tree clean. The package is the one source of truth. `mehen version --json` returns `{ version, commit, build, helper }`, with the short source commit and `build: "release"` stamped by a release build. The signed release manifest is `{ version, commit, builtAt, files, signatures }`; each file records `name`, `os`, `arch`, `url`, raw `sha256` and `size`, and compressed `gzSha256` and `gzSize`. `build` and `helper` are binary probe fields, not manifest fields. Never reuse an immutable version.

2. Build all four targets and the universal macOS Secure Enclave helper (embedded in each darwin binary), gzip and checksum them, sign the manifest, then write (not run) the upload script:

   ```sh
   RELEASE_DIR="$HOME/mehen-releases"
   bun tools/release/release.ts --out "$RELEASE_DIR" --release --upload-script "$RELEASE_DIR-upload.sh"
   ```

   This writes `v<version>/mehen-<os>-<arch>.gz`, `v<version>/mehen-se.gz`, `v<version>/manifest.json` and `latest.json` under `RELEASE_DIR`. The manifest is signed through the freshly built helper with the only key in `RELEASE_KEYS` (or `--key <id>`), and the signature is verified against `RELEASE_KEYS` before anything is written; a key whose sidecar disagrees with its compiled entry, `presence` included, signs nothing. A presence key asks for Touch ID or the password, so run the release in a desktop session on the release Mac, not over SSH. Before assembling, the tool checks the host binary's `version --json`, `codesign --verify --strict` on every darwin binary, and that the host's darwin binary extracts its helper (`version --extract-helper`) as a signed file that runs. `mehen-se.gz` is still published so that an old 0.2.0 `mehen update` completes. An existing version directory or a dirty tree is refused. `--allow-dirty` is for local trials only, never a public release. `--upload` and `--upload-script` are refused without `--release`, which stamps the binaries as a release build. The tool runs the host binary's `version --json` and checks its version and commit before publishing the local manifest.

   For a local single-platform build, pass `--target darwin-arm64` (repeatable). Partial target sets refuse `--upload` and `--upload-script` unless `--partial` is explicit. Cross-target Bun builds download the target runtime on their first build unless it is cached; prepare that cache before an offline build. A partial upload script says so in its first comment; never run one for a public release.

   With no `MEHEN_NOTARY_PROFILE`, the named `notarise` hook says it is a no-op. Without an Apple Developer ID certificate, leave that variable unset. The helper stays ad-hoc signed with hardened runtime; curl downloads carry no quarantine attribute. A notarised release needs Developer ID signing before enabling the profile hook. Do not claim ad-hoc signed binaries are notarised.

3. Verify the local tree before uploading:

   ```sh
   bun test tools/release/release.test.ts tools/release/install.test.ts
   bun -e '
   const root = process.argv[1];
   const m = await Bun.file(root + "/latest.json").json();
   const hash = bytes => new Bun.CryptoHasher("sha256").update(bytes).digest("hex");
   for (const f of m.files) {
     const gz = new Uint8Array(await Bun.file(root + "/v" + m.version + "/" + f.name + ".gz").arrayBuffer());
     if (gz.length !== f.gzSize || hash(gz) !== f.gzSha256) throw new Error(f.name + " compressed checksum mismatch");
     const raw = Bun.gunzipSync(gz);
     if (raw.length !== f.size || hash(raw) !== f.sha256) throw new Error(f.name + " raw checksum mismatch");
   }
   console.log("Verified " + m.version + ": " + m.files.length + " files");
   ' "$RELEASE_DIR"
   ```

   Exercise the installer against a local release tree or fixture server on both `sh` and `dash`. It checks the manifest's ES256 signature against the release keys written into the script (`release_keys`, kept equal to `RELEASE_KEYS` by `install.test.ts`) with `openssl`, then compressed and raw checksums, before replacing anything. It is for a machine with no `mehen`: on one with a verified install it says `Already installed`, downloads nothing and changes nothing unless a human passes `--force`; installed machines update through `mehen update`. The automated fixture tests cover both shells when available, macOS plus Rosetta and Linux platform detection, an unrelated target, missing checksum tools and openssl, truncation and checksum failures, a good, tampered, unsigned and wrongly signed manifest, and the real 0.4.0 manifest against the pinned key.

4. The first time only, create the release bucket. The web Worker already declares binding `RELEASES` for this exact bucket:

   ```sh
   cd apps/web
   bunx wrangler r2 bucket create mehen-releases
   cd ../..
   ```

5. Inspect `"$RELEASE_DIR-upload.sh"`. Once approved, the operator runs it from the repository root:

   ```sh
   sh "$RELEASE_DIR-upload.sh"
   ```

   The printed script uses `bunx wrangler r2 object put ... --remote`. The required order is all five versioned `.gz` files, then that version's `manifest.json`, then `latest.json` last. Never upload latest first, or overwrite a versioned file. Keep the local release tree for rollback. The web routes stream allowed keys only; they do not list the bucket.

6. Deploy the web routes and static guides only after the signed artefacts are uploaded, then run the following checks from the repository root.

   ```sh
   bun run --cwd apps/web test
   bun run --cwd apps/web typecheck
   cd apps/web
   bunx wrangler deploy
   cd ../..
   curl -fsSI https://mehen.dev/install
   curl -fsS https://mehen.dev/dl/latest.json
   curl -fsS https://docs.mehen.dev/skill.md | cmp - skills/mehen/SKILL.md
   curl -fsS https://docs.mehen.dev/setup.md | cmp - apps/docs/public/setup.md
   ```

   `/install` must be `text/plain` and `no-cache`; versioned downloads are immutable and `latest.json` has a 60 second cache. The setup guide, the skill and the short guide are on the docs site ("The docs site" below); deploy `mehen-docs` with the release, after the signed artefacts are uploaded, so `setup.md` never describes a release that cannot be installed. Give a colleague the one-line prompt from a workspace's Connect an agent page. Do not test enrolment without their consent and workspace invite.

7. Check one installed machine picks the release up: `mehen update --check --json` names it and verifies its signature, and within the hour the background updater installs it (`mehen doctor --json` `cli.lastUpdate`). Nothing needs raising by hand: usually within 5 minutes, on its next vault calls, a machine sees the vault's advice header, `Mehen-Cli: minimum=<v>; recommended=<v>`, recommend the published release. The vault reads `latest.json` through its `RELEASES_WEB` service binding to `mehen-web` and recommends its version only when its signature verifies against `RELEASE_KEYS` (`apps/vault/src/published-release.ts`), so every machine that talks to the vault checks at the end of its next call. Each Worker isolate holds its own copy, so it is not one switch: a cold isolate recommends only the floor until its first read finishes, and one with no recent traffic answers its first call with what it read up to an hour before. For a while a machine can see the floor and the release by turns; the CLI does not count that as new advice. `CLI_RECOMMENDED_VERSION` in `apps/vault/wrangler.jsonc` is now a floor: the vault never recommends less, and recommends only that before an isolate's first good read and when its reads fail for an hour. Raise `CLI_MINIMUM_VERSION` only after the fleet view shows no active machine below it, and never above the version in `latest.json`:

   ```sh
   cd apps/vault
   bun scripts/fleet-versions.ts --remote --below <new minimum>
   ```

   It is read-only: it counts the active machines of every workspace per CLI version, from the version each machine's `mehen/<x.y.z>` User-Agent last named (`device_cli_versions`, migration 0014), and lists each one below the version given by workspace slug, device id and version. A machine that has not called the vault since that migration shipped has no row and is not counted, so check any machine you know of that is missing with a direct `mehen version --json`; device labels are not an inventory. Each workspace's Machines page shows the same version per machine.

   The raise is a reviewed change to `apps/vault/wrangler.jsonc` and a vault deploy; a client below the minimum is refused with `cli_outdated` (HTTP 426) on everything but freeze and self-revoke.

8. In the next change after the release, add the release's skill hash to `RELEASED_SKILL_SHA256` in `apps/cli/src/setup/skills.ts` (`git show <release commit>:skills/mehen/SKILL.md | shasum -a 256`) and its commit to `RELEASE_COMMITS` in `apps/cli/src/setup/setup.test.ts`. Without it, `mehen setup` and `mehen update` call a copy of that release's skill saved from docs.mehen.dev external and leave it stale.

### A security release

1. Release as usual. The vault then recommends the fixed version, usually within 5 minutes, on a machine's next vault calls, so every active machine updates at the end of its next vault call, and idle ones (an idle `mehen mcp`, or a machine that runs a command now and then) within the hour, at their next scheduled check. A machine that runs no `mehen` command at all never checks.
2. See who is still behind, from `apps/vault`:

   ```sh
   bun scripts/fleet-versions.ts --remote --below <fixed>
   ```

3. To force it, raise `CLI_MINIMUM_VERSION` to the fixed version in a reviewed PR to `apps/vault/wrangler.jsonc` and deploy the vault. An installation below it that updates itself then updates in the foreground (up to 90 seconds) before it does anything else that talks to the vault, and the vault refuses anything below it with `cli_outdated` until it has updated.
4. Know the cost first: a running `mehen mcp` on an older image answers "restart the agent" until its host restarts it, unless in-place handover is on (`HANDOVER_ENABLED` in `apps/cli/src/mcp/self-watch.ts`, off today).
5. If the release will not install somewhere (its smoke test fails on one platform, it has no binary for it, or downloads are blocked there), a machine on a later CLI tries again at most every 15 minutes. Machines already on 0.3.9 or earlier keep the old retry behaviour: every command they run launches the updater, which downloads the release again. To stop the retries, pause the release (below). If step 3 raised `CLI_MINIMUM_VERSION` to that release, lower that too, with a vault deploy: machines below it update in the foreground, and download it again, on every command that talks to the vault, and after the pause the vault still refuses them with `cli_outdated`. Where `latest.json` itself is blocked, pausing stops the downloads, but a machine on 0.3.9 or earlier never completes a check, so it keeps launching the updater on every command, each one only a cheap failed fetch, until the vault's advice is no longer above it.

### Roll back a CLI release

**Fix forward.** Installed clients refuse a downgrade, so repointing `latest.json` at an older manifest helps only fresh installs; it never moves an installed machine back. To fix a bad release, publish a higher version with the good code. Repointing is still the way to stop new installs picking up a bad release while the fix is built, and only to a release that works against the deployed server (0.2.0 or later; never 0.1.0, which predates workspaces):

```sh
cd apps/web
bunx wrangler r2 object put mehen-releases/latest.json --file "$HOME/mehen-releases/v0.3.0/manifest.json" --content-type application/json --remote
```

The uploader publishes whatever manifest it is given; it does not check the server. Do not delete or mutate immutable versioned files. The short latest cache takes up to 60 seconds to age out. Pausing also lowers the version the vault recommends: usually within 5 minutes, on a machine's next vault calls, it recommends the release `latest.json` now names, never below `CLI_RECOMMENDED_VERSION`, so machines that have not updated stop hurrying to the paused one. That is also how to stop the retries when a release will not install somewhere: machines already on 0.3.9 or earlier launch the updater on every command while the vault recommends a release they cannot install, so pause it, and lower `CLI_RECOMMENDED_VERSION` with a vault deploy if it names that release. If a security release's step 3 raised `CLI_MINIMUM_VERSION` to it, lower that too, with a vault deploy. Where `latest.json` itself is blocked, pausing stops the downloads, but machines on 0.3.9 or earlier keep launching an updater whose fetch fails, which costs little, until the vault's advice is no longer above them. On one machine, a human can go back to the previous binary with `mehen update --rollback --json`, which verifies `.mehen.previous` against its retained signed manifest and then holds back the version it left, and anything older, until a higher one is published; `mehen update --force --version <v> --json` installs a named signed release even when it is older. Both are explicit, local and still signature-checked. Updating preserves enrolment, verifies both hashes, replaces the binary with one rename next to it, then runs the new binary's skills-only setup to refresh managed skills and records each skill's status; foreign and symlinked skills stay untouched, and a skill failure leaves the verified new binary installed (`mehen doctor` warns until the next clean refresh).

### Switching MCP servers in place on one machine

By default a running `mehen mcp` switches to the new binary in place after an update, where automatic updates are on. A server started before 0.3.15 decided at its start and asks for one agent restart, then switches in place from then on. To check a machine:

```sh
mehen doctor --json | jq .cli.mcpHandover    # { "handover": "on" }
```

`off` comes with the reason (`MEHEN_NO_AUTO_UPDATE is set`, `autoUpdate is false in settings.json`, `a development build`, ...). After the next update, `vault_status` in an agent shows `cli.mcp.action: "switch"` until the server has switched, then no `cli.mcp`; a server that could not switch says `restart` with the reason and asks for a restart in a tool result, and its stderr log has `mcp handover cancelled` with why. To turn it off, add `"mcpHandover": false` to `settings.json` under the machine's `MEHEN_HOME` (default `~/.config/mehen/settings.json`); removing the key turns it on again for servers started after that. Turning it off reaches servers already running too: each reads the setting again before it switches, so the next switch does not happen and the server asks for a restart instead (its log says `the handover was turned off`).

## Release keys

Release manifests are signed with P-256 keys in the Secure Enclave of the release Mac; the public halves are compiled into every binary as `RELEASE_KEYS` in `packages/protocol/src/release-keys.ts` (the CLI re-exports it as `apps/cli/src/release-keys.ts`), and the vault advertises a published release only when one of them signed it. A release binary against `https://mehen.dev/dl` trusts that set and nothing else: `MEHEN_RELEASE_KEYS` and `MEHEN_DL_BASE` cannot widen it (the override is honoured only for a loopback download base or a non-release build, which is what tests use).

Make the key on the release Mac after the release owner chooses user presence. Build the helper first with `apps/cli/native/mehen-se/build.sh`; a release build cannot bootstrap an empty trusted-key set.

```sh
bun tools/release/keys.ts create --id rk-release-2026
```

Append `--user-presence` to that command if the release owner chose presence-required signing; the square-bracket notation in usage text is not a literal shell argument. Run presence-required ceremonies in a desktop session on the release Mac.

It writes the enclave-wrapped blob `~/.config/mehen-release/rk-release-2026.se` and the sidecar `rk-release-2026.json` (`{ id, alg, jwk, presence, created }`) in a 0700 directory, and prints the `ReleaseKey` literal and the installer's line for it. Add the literal to `RELEASE_KEYS` and the line to `release_keys` in `tools/release/install.sh` in one reviewed commit (`install.test.ts` fails while the two differ, so a first install trusts exactly the keys an update does); the release tool refuses to sign when the sidecar and the compiled entry disagree. An existing key is never replaced: a new key gets a new id. `--user-presence` makes every signature a human act (Touch ID or the password); without it anything running as that user on the unlocked Mac can sign. Either way the private key never leaves that enclave, and the compiled set decides what clients accept. Record the release owner's choice for this key in the threat model and release report before signing a public release.

The key compiled in today is the reference deployment's (`rk-studio-2026-auto`, made without `--user-presence`, so its release Mac signs unattended). A deployment that publishes its own CLI releases from its own download base replaces it with its own key; one that only runs the vault keeps it and uses the released `mehen`.

- **Add a key** (do this in the first release after a second Mac exists): make it on the other Mac with `keys.ts`, add its public half to `RELEASE_KEYS`, ship a release signed by the existing key, and redeploy the vault, which trusts only the keys of the build it runs: until then a release signed by the new key alone does not verify there (`unknown_key`), so the vault recommends its floor. From the next release either key signs.
- **Remove a key**: ship a release without it, and redeploy the vault, which trusts the key until it runs a build without it.
- **A compromised key**: sign the next release with a surviving key and drop the compromised one, and redeploy the vault at once, so it stops recommending a release that key signed; then raise `CLI_MINIMUM_VERSION` to that release once every machine reports it, so nothing keeps trusting the old set.
- **The only key lost** (the release Mac is gone before a second key ships): no installed machine can take a signed update again, because clients trust only the compiled set, and nothing automatic can get round that by design. Recovery is one explicit manual hop per machine: make a new key on another Mac, build a release whose `RELEASE_KEYS` holds only the new key, signed by it, and on every machine have a human run `curl -fsSL https://mehen.dev/install | sh -s -- --force`. That trusts TLS and the web Worker for the script, whose `release_keys` must already name the new key (it is kept equal to `RELEASE_KEYS`), and is recorded as installed by hand.

## Local development

Local development uses `wrangler dev -e local` (`bun run dev`, on `http://localhost:8787`, with `RP_ID` `localhost`). Its secrets go in **`apps/vault/.dev.vars.local`**, which wrangler loads for the `local` environment only:

```sh
cd apps/vault
bun -e '
const b64url = (bytes) => Buffer.from(bytes).toString("base64url")
const k = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
const j = await crypto.subtle.exportKey("jwk", k.privateKey)
const lines = [
  `ROOT_KEYS='${JSON.stringify({ "1": b64url(crypto.getRandomValues(new Uint8Array(32))) })}'`,
  `SEAL_PRIVATE_JWK='${JSON.stringify({ kty: j.kty, crv: j.crv, x: j.x, y: j.y, d: j.d })}'`,
  `BOOTSTRAP_CODE=local-bootstrap-${b64url(crypto.getRandomValues(new Uint8Array(6)))}`,
]
await Bun.write(".dev.vars.local", lines.join("\n") + "\n")
'
chmod 600 .dev.vars.local
bunx wrangler d1 migrations apply mehen-local --local -e local
bun run dev
```

`ROOT_KEYS` and `SEAL_PRIVATE_JWK` are raw JSON in single quotes: wrangler reads the file as dotenv, which does not unescape `\"` inside double quotes, and the vault reads each value with `JSON.parse`.

**Never create a plain `apps/vault/.dev.vars`.** Wrangler loads it for every environment, including the `test` environment the server suite runs in, where it overrides the test keys in `wrangler.jsonc` and breaks the suite. Both files are gitignored. Never copy production values into either.

Point a CLI at the local server with `MEHEN_VAULT_URL=http://localhost:8787` and a separate `MEHEN_HOME` (for example `MEHEN_HOME=$HOME/.config/mehen-local`), so it does not touch the machine's real enrolments; after the local enrolment, that `MEHEN_HOME` alone selects it (a `MEHEN_VAULT_URL` that disagrees with the selected workspace is `workspace_mismatch`). Set `MEHEN_NO_AUTO_UPDATE=1` on a test machine whose `mehen` you built yourself. Local Google sign-in uses the redirect URI `http://localhost:8787/auth/oidc/google/callback`.

## Custom domain

`apps/vault/wrangler.jsonc` routes `mehen-app` to one host name (the reference deployment's is `app.mehen.dev`, in the `mehen.dev` zone) as a Cloudflare custom domain, with `workers_dev` and preview URLs switched off, so the vault is reachable only at that name. `wrangler deploy` creates the DNS record and certificate. The same name is in `vars`: `VAULT_ORIGIN` is `https://<host>` and `RP_ID` is `<host>`. The CLI's default `MEHEN_VAULT_URL` is the reference deployment's origin, so machines of another deployment set `MEHEN_VAULT_URL` to theirs when they enrol.

`/.well-known/apple-app-site-association` lists the apps in `APPLE_WEBCREDENTIAL_APPS`, so a native app can sign in with a passkey for the vault's host and receive the identity gate's callback (`/app/v1/gate/callback`).

Changing the domain is not cosmetic: passkeys are bound to `RP_ID`, so a new domain means every member registers new passkeys, every enrolled CLI must be pointed at the new `VAULT_ORIGIN` (`MEHEN_VAULT_URL`, or a fresh `mehen enrol`), and the native app needs the new domain in its associated domains. Change `routes`, `VAULT_ORIGIN` and `RP_ID` together.

## Email Sending

An email-bound invitation's address is proved with Google or with a six-digit code the vault emails to it. The code goes out through Cloudflare Email Sending, a Workers `send_email` binding: `wrangler.jsonc` binds it as `EMAIL`, allowed to send only from the address in `allowed_sender_addresses`, and the `EMAIL_FROM` var (for example `Mehen <no-reply@mehen.dev>`) is the From. Sending to any recipient needs the Workers Paid plan. There is no other provider and no secret.

Onboard your zone to Email Sending once, with `wrangler email sending enable <zone>`: it enables sending, with the DKIM selector `cf-bounce` and the return path `cf-bounce.<zone>`, and lists the DNS records to add. Add DMARC (`p=reject` once mail flows) so mail from the sender address is DKIM-aligned, and put that address in `allowed_sender_addresses` and `EMAIL_FROM`. If it is ever switched off, or the records go missing, every send is refused (`E_SENDER_DOMAIN_NOT_AVAILABLE` or `E_SENDER_NOT_VERIFIED`) and the page offers only Google. Check it with:

```sh
cd apps/vault
bunx wrangler email sending settings <zone>    # sending is enabled for the zone
bunx wrangler email sending dns get <zone>     # the DNS records it expects, all present in the zone
```

Then send one code to yourself: invite your own address to a test workspace, open the link signed out and choose Email me a code. A send the binding refuses is logged as `email.code.send` with the error code only (never the address or the code), and the person is told to verify with Google instead.

The rules (`apps/vault/src/directory/email-proof.ts`, `migrations/0016_email_proofs.sql`): the code comes from the CSPRNG, goes only to the address the invitation names, lasts 10 minutes and dies after 5 wrong tries; an invitation gets at most 3 codes in any hour, and a new one replaces the last. D1 keeps it only as an HMAC under a key derived from `ROOT_KEYS` (the version is kept with the row). Typed back, it is a proof for 10 minutes, bound to the browser that asked by its `__Host-mehen_email` cookie, which the sign-up and the join take as they take Google's. It proves control of the inbox and carries no Google Workspace domain, so it never satisfies a workspace identity rule: a role under one is offered Google only. Both routes spend `AUTH_RATE_LIMITER` by address.

The same binding emails a new invitation's link to the invited address when the inviter leaves Email the link to them ticked (`apps/vault/src/directory/invite-email.ts`, `migrations/0019_invite_emails.sql`): only at creation, since D1 keeps only the code's hash, and never for an open link. One inviting account sends at most 10 an hour and 30 a day, and one address receives at most 3 a day across every inviter and workspace, each a condition of the insert that counts the send; rows are swept after a day and hold no link or code. Over a limit, or when the binding refuses (logged as `invite.email.send` with the error code only), the invitation is still made and the page shows the link to copy. A sent link is recorded in the workspace's audit as `invite.emailed`, with the invitation and the address.

`wrangler dev -e local` simulates the binding and logs each message instead of sending it; the server suite binds a fake.

## Root key rotation

Each secret field stores the root key version its data key was wrapped under. Rotation re-wraps data keys; it never re-encrypts the secrets themselves (`rewrapRecord` in `packages/protocol/src/envelope.ts`).

1. **Add version n+1.** Fetch the current map from the offline escrow, add a new 32 byte key under the next version number, and set the whole map:

   ```sh
   printf '%s' '{"1":"<existing>","2":"<new>"}' | bunx wrangler secret put ROOT_KEYS
   ```

   From now on new and updated fields are wrapped under version 2, and version 1 still decrypts. Update the offline escrow with the new map in the same sitting.

2. **Re-wrap.** Not built: there is no sweep yet that re-wraps existing data keys. Until there is, a field moves to the new version only when its secret is replaced.

3. **Retire version n.** Only once every field in every workspace uses the new version, remove the old entry from the map and set it again. If you remove a version that still wraps a field, that field cannot be decrypted until you put the version back. There is no report yet that shows which versions are still in use, so in practice keep every version.

Fingerprints are keyed under the **current** root version. After a rotation, a secret stored or replaced from then on gets a fingerprint under the new version, while existing fields keep the fingerprint they were stored with. The same value stored before and after a rotation therefore shows two different fingerprints.

Emailed invitation codes are hashed under a key derived from the root version current when each was sent; one sent just before a retired version is removed stops working, and the person asks for a new one ([Email Sending](#email-sending)).

Keep retired versions in the offline escrow for at least a year: each daily dump of a workspace object is sealed under the root key version current when it was written ([Backup and recovery](#backup-and-recovery)).

## Seal key rotation

The seal key protects secrets for the few seconds between the browser sealing them and the Durable Object opening them. Nothing stored depends on it.

1. Generate a new `SEAL_PRIVATE_JWK` and `wrangler secret put` it, as above.
2. The public half at `GET /v1/seal-key` changes immediately; responses carry `cache-control: public, max-age=300`, and its `kid` (the first 16 characters of the key's thumbprint) changes with it.
3. Anything sealed to the old key and not yet submitted fails to open. A human with an intake page open reloads it and submits again.

The server holds one seal key at a time. Rotate whenever you like, and immediately if the seal key may have leaked.

## Backup and recovery

Mehen must never be the only copy of what it stores. What exists, and where each copy lives:

| What | Its copies | What opens them |
| --- | --- | --- |
| `ROOT_KEYS` | The offline escrow, two copies in two places ([The root key](#the-root-key)) | Nothing else: there is no back door |
| Workspace objects (`TENANT_VAULT`) | Cloudflare's point-in-time recovery, any moment in the last 30 days; a daily dump of every workspace object in the R2 bucket `mehen-vault-backups` (binding `VAULT_BACKUPS`, EU jurisdiction, the same as D1), 35 daily and 12 monthly copies under a 30-day bucket lock; and the weekly pull on an offline disk | The root key version each dump names |
| The D1 directory (`DB`) | D1 Time Travel, any minute in the last 30 days, and the weekly pull's `wrangler d1 export` | Nothing needed: it holds no secret |

Neither of Cloudflare's own features survives losing the account, a deleted class, an attacker with dashboard rights, or a mistake noticed after 30 days; the dumps and the pull are for those.

### The root key

- Keep the full `ROOT_KEYS` map offline: on paper in a safe, or on an encrypted hardware token, ideally two copies in two places. Never on an agent machine, a synced folder, a password manager an agent can reach, or in the vault itself.
- Update the escrow in the same sitting as every rotation, and keep every retired version for at least a year: each dump names the root key version it was sealed under.
- Recovery: if the Worker's secrets are lost (a mistaken `wrangler secret delete`, a rebuilt account), set `ROOT_KEYS` again from the escrow. The encrypted data is in the Durable Objects and is untouched.
- If every copy of a root key version that still wraps data is lost, the secrets under it are gone, and so is every dump sealed under it. There is no recovery and no back door.

### Daily dumps to R2

The cron (every 15 minutes) asks every `active` workspace in D1 to dump itself once a UTC day, 50 a run, those not yet tried that day first and, among them, those whose last good dump is oldest, so 96 runs cover 4,800 workspaces and, past that, no workspace is always the one left out (`directory/vault-backups.ts`). The object writes the dump itself (`vaultbackup.dump`, a system call no member, machine or platform can make) and the cron records the tenant, date, bytes, sha256, root key version and outcome in `vault_backup_runs`. One failure never stops the rest; a failed workspace is tried again on the next run, and an `ok` row is never changed. The object writes a dump only for today's UTC date. An object already at today's key is answered as it is only if it opens as this workspace's dump of today, so a retry never writes another; anything else there (planted, damaged, another workspace's or another day's) is recorded `failed` as `backup_corrupt`, and so is a monthly copy that is not the first's bytes. The lock keeps such an object for 30 days, so that workspace has no dump for the day: look at who could write the bucket. An object the directory lists as active but which is empty is refused, not dumped: that is an incident, and `status` shows it. A workspace whose storage is above 32 MiB is refused as `too_large`, because the dump is built whole in the object's 128 MB of memory, and is not tried again until the next UTC day; `status` lists it with its size, and it relies on point-in-time recovery until dumps are written in parts.

- **Key:** `ws/<tenant>/<yyyy-mm-dd>.bin`. On the first of each month the same bytes are also written to `monthly/ws/<tenant>/<yyyy-mm>.bin`.
- **Format:** one cleartext JSON line `{ format: "mehen-vault-backup/v1", tenant, date, rootVersion }`, then `0x01 | 12-byte IV | AES-256-GCM ciphertext and tag` of a gzipped NDJSON dump: every table in the object's SQLite except SQLite's and Cloudflare's own, `_migrations` and the generation marker included, rows in creation order, BLOBs in base64.
- **Encryption:** the whole dump is sealed, not only the secret fields, because slugs, bindings, plain variables, members and the audit are stored in the clear in the object. The key is `HKDF-SHA256(root v<n>, salt "mehen/root/v<n>", info "mehen/backup/v1/<tenant>")` (`deriveBackupKey` in `packages/protocol/src/envelope.ts`), with AAD `mehen-backup|<tenant>|<date>|<rootVersion>`. There is no new key to escrow: whoever holds the root key and the bucket can read every dump, which the root key and the live objects already allow. A dump opens only in the object with the same name, because the key and the AAD both bind the tenant; restoring under a new id is impossible by design.
- **Not dumped:** platform-managed workspaces (they are listed in `managed_workspaces`, not `workspaces`); they rely on point-in-time recovery.

Set the bucket up once, before the deploy that binds it, then apply the migration:

```sh
cd apps/vault
bunx wrangler r2 bucket create mehen-vault-backups --jurisdiction eu
bunx wrangler r2 bucket lifecycle add mehen-vault-backups daily-35-days ws/ --expire-days 35 --jurisdiction eu
bunx wrangler r2 bucket lifecycle add mehen-vault-backups monthly-12-months monthly/ --expire-days 366 --jurisdiction eu
bunx wrangler r2 bucket lock add mehen-vault-backups lock-30-days "" --retention-days 30 --jurisdiction eu
bunx wrangler d1 migrations apply mehen --remote    # 0013_vault_backups.sql
bunx wrangler deploy
```

The lock refuses deleting or overwriting any object for 30 days after it is written; the lifecycle rules delete daily dumps after 35 days and monthly ones after a year. Unverified: whether an account administrator can lift a bucket lock.

```sh
bun scripts/vault-backup.ts --remote status
```

prints today's dumps and their total size, every active workspace with no dump since yesterday, the last week's failures with their reason, and the recent restores with their state and undo bookmarks.

### The weekly pull

Once a week, from the operator's machine, onto a disk that is otherwise kept offline:

```sh
bun scripts/vault-backup.ts --remote pull --to /Volumes/<disk>/mehen
```

It fetches every dump of the last 35 days that is not already there (`wrangler r2 object get`), keeps one only when its size and sha256 match `vault_backup_runs`, never overwrites a file that differs, and writes a D1 export (`wrangler d1 export mehen --remote`) beside them. It prints every command before it runs it and exits non-zero on any mismatch. The pulled files open only with the root key, so the disk holds ciphertext and a directory with no secret in it. The pull records nothing in D1, so the console's Workspaces view cannot show it: its record is the operator's log.

### Restoring a workspace

A restore records one intent in `vault_restore_intents` that lives an hour, and the cron does the work. The intent carries a digest over every field, which the cron checks in every state, so an intent edited after it was recorded is refused. That digest catches accidental edits only: it is not a signature, and anyone with D1 write access can record a valid restore of any workspace. Treat D1 write access as the power to restore.

**In the app.** In the Operator area, Workspaces (`/operator/workspaces`) lists every workspace and opens one (`/operator/workspaces/tn_<id>`) with its last dump, its recent restores and the days it can be restored from. Its Restore card shows the checklist below first; then one operator proposes a restore (`workspace.restore`), to a point in time or from a day's dump, typing the workspace id back and signing with a passkey, and a different operator approves it on the Operators view with theirs within 24 hours ([Operators](#operators)). The approval records exactly the intent the script records, with the proposer's `operator:<account id>` as its actor, in the same batch as its `deployment_events` row, whose details name the intent (`intent: vri_<id>`); every operator and the workspace's owners get a notice. A restore of the same workspace already in progress refuses the proposal and the approval, and so does a workspace that is not active: one being created has nothing to restore, and a restore does not stop a deletion, so one that is deleting or deleted is refused too. Until there are two operators, Restore is disabled and says "Needs a second operator; use the script".

**The script is the break-glass**, for when the app is down or there is only one operator. It runs the way [account break-glass](#account-break-glass) does: from the operator's machine, it prints the D1 bookmark and the plan, needs the workspace id typed back, and records the same intent (`newRestoreIntent` in `directory/vault-backups.ts` builds both).

```sh
bun scripts/vault-backup.ts --remote restore --tenant tn_<id> --pitr 2026-10-31T08:15:00Z --actor operator:<your-name>
bun scripts/vault-backup.ts --remote restore --tenant tn_<id> --dump 2026-10-30 --actor operator:<your-name>
```

- **To a point in time** (`--pitr`, with `Z` or an explicit offset such as `+01:00`; a time with no zone is refused), any moment in the last 30 days: the cron asks the object for the bookmark at that time, keeps it and the undo bookmark the object returns with the intent, and restarts the object, which comes back as it was at that time. This is the restore for a workspace that still exists but is wrong. Cloudflare does not offer it in local development, so only the drill proves it. Unverified: whether it survives a deleted class or `deleteAll()`.
- **From a dump** (`--dump`): only into an empty object, which is what a lost workspace is (a deleted class, a wiped object, or a new account or deploy with the same `ROOT_KEYS` and the same tenant id). The object fetches the dump itself and opens it with its own root keys, so the operator never handles plaintext. It refuses an object that is not empty, another workspace's dump, a dump from another storage generation, one under a root key version the deploy lacks, and one written by newer vault code; an older dump is migrated forward when the object restarts. A date older than 35 days restores only if it is the first of a month. After losing the bucket, put the pulled file back first (`bunx wrangler r2 object put mehen-vault-backups/ws/<tenant>/<date>.bin --file <file> --remote --jurisdiction eu`) and restore its `vault_backup_runs` row from the pulled D1 export.

Once the object has restarted, it appends `system.restore` (the intent, the source, the point or date, and both bookmarks) to its own audit chain, with the intent's `operator:<label>` as its actor, and the intent shows `done` in `status`. A refused intent shows `failed` with the reason; nothing was changed, so fix the cause and record a new one. The object keeps the intent it last staged, so when a reply is lost the cron asks again and gets the same answer: a dump restore is not refused as "not empty", and a point-in-time restore keeps its first undo bookmark. The object also logs each undo bookmark as `vault.restore.staged` when it takes it, because a point-in-time restore rolls the object's own record back. An intent the cron did not reach within the hour expires. One the object has not confirmed within 6 hours of being recorded fails as `restart_timeout`, so it no longer blocks the next restore of that workspace: the restore may have taken effect without its `system.restore` event, so read the workspace and its audit before recording another.

**A restore rolls back everything after its point**: revocations, removals, suspensions, freezes, approvals and their denials, standing rules ended, and rotations. A machine revoked after the point works again, a standing rule ended after the point allows requests again until its own end, and a credential rotated after the point holds its older value. So, before recording the intent, freeze the workspace ([Freezing and unfreezing](#freezing-and-unfreezing)), so nothing widens between the saved tail and the restore. Then save the audit tail past the restore point: as an owner, page `GET /api/w/:ws/audit` back with `before` until the events reach the point, and keep the JSON ([Reading the audit chain](#reading-the-audit-chain)). From the moment the cron stages the restore until the object restarts, the object refuses every call but the restore's own, so nothing lands in that window and is lost. A point-in-time restore to before the freeze undoes the freeze too, so freeze again first thing afterwards. Then re-apply what it undid, revocations first: revoke those machines and workloads again, remove or suspend those people again, deny or revoke those approvals, end again every standing rule the saved tail shows ended after the point (its `rule.end` events) with **Stop** on the credential's or the machine's page, or as an owner `POST /api/w/:ws/policy/rules/:id/revoke` (`GET /api/w/:ws/policy/rules?item=<slug>` or `?device=<dev_id>` lists them; `mehen policy ls --workspace <w> --json` on a machine lists its own), and rotate again at the provider every credential rotated since. A restore also takes back what the object keeps of each account's security: its installed security epoch, its cooling-off after a recovery and the session ids it has revoked. These are the directory's, not the workspace's, so nobody re-applies them: the cron run that records the restore `done` forgets the deliveries the restore lost (every pending account security change, and every committed change, sign-out and account security event made from a day before the restore point on) and delivers them again in the same run, retrying any that fail on the runs after. Until they have all landed, a recovered account's machine may still write here during its cooling-off, so keep the workspace frozen until this reads `0` (run it once the intent shows `done`):

```sh
bunx wrangler d1 execute mehen --remote --command "SELECT (SELECT COUNT(*) FROM account_events e WHERE e.action IN ('account.signout','account.security','account.recovery_keep') AND EXISTS (SELECT 1 FROM json_each(e.targets) WHERE value='tn_<id>') AND NOT EXISTS (SELECT 1 FROM json_each(e.mirrored_to) WHERE value='tn_<id>')) + (SELECT COUNT(*) FROM account_security_transitions t WHERE EXISTS (SELECT 1 FROM json_each(t.targets) WHERE json_extract(value,'$.workspace')='tn_<id>') AND CASE t.state WHEN 'pending' THEN NOT EXISTS (SELECT 1 FROM json_each(t.acknowledged) WHERE json_extract(value,'$.workspace')='tn_<id>' AND json_extract(value,'$.reservedEpoch')=t.reserved_epoch) ELSE NOT EXISTS (SELECT 1 FROM json_each(t.commit_delivery) WHERE value='tn_<id>') END) AS undelivered"
```

Unfreeze once it reads `0` and the tail is re-applied. The restored chain carries on from its restored head with the `system.restore` event; the saved tail is the record of what was undone.

### D1

D1 Time Travel restores the whole directory to any minute in the last 30 days (`bunx wrangler d1 time-travel info mehen`, then `bunx wrangler d1 time-travel restore mehen --timestamp <time>`); the weekly pull's export is the copy beyond that. A D1 restore also undoes later account changes, sessions, passkeys, memberships and break-glass barriers among them, so it is a last resort, never a shortcut for break-glass.

### The quarterly drill

In a throwaway workspace on production: create a credential, note the time, delete it, restore the workspace to the noted time with `--pitr`, and check that the credential is back, that the audit page says `verified`, and that `system.restore` is the newest event. Then restore the same workspace from its latest dump into a staging deploy with the same `ROOT_KEYS` and tenant id, and check it the same way. Finally check that the last weekly pull completed with no mismatch. Note the date and the outcome in the operator's log.

## Account break-glass

For a person who has lost every passkey and every recovery code. Keyed by account, never by a member or a workspace, and only after verifying the person's identity out of band; no workspace role, owner included, can do it.

**In the app, two operators.** On the account's page in the Accounts view ([Accounts](#accounts)), one operator proposes Recover access for an account that is not an operator's, typing how they verified the person (kept in the proposal's `deployment_events`), and a different operator approves it within 24 hours. Approving records the same one-hour intent the script records, as `operator:<proposer>`, and the cron installs the same barrier. Once every workspace has acknowledged, the proposer, and only the proposer, takes the single-use `/signup#<code>` link on the account's page with their passkey (`operator.break_glass_link`): it is shown once, never again, and taking it is a `deployment_events` row. A lost link is let expire and proposed again. Redemption and its cooling-off are the script's. An operator's access is never recovered in the app, since the proposer alone takes the link and would hold a second operator account: end their role first, or use the script.

**The script is the break-glass**, for when the app is down or there is one operator. It runs only from the operator's machine with `wrangler` access to D1.

```sh
cd apps/vault
bun scripts/break-glass.ts --remote --list
bun scripts/break-glass.ts --remote --account acc_<id> --actor operator:<your-name>
```

The script prints the D1 bookmark and the plan, requires the account id typed back, then records one hashed one-hour intent (the code never touches disk; the same insert writes the operator event and the account's notice). The link is not usable yet: the cron (every 15 minutes) first installs the account's security barrier in every workspace it belongs to, ending its passkeys, sessions, recovery codes and any earlier operator link; only when every workspace has acknowledged does the script, still running, print the single-use `/signup#<code>` link once, to be handed over privately. Keep the terminal open while it waits; an interrupted script cannot recover its code, so let the intent expire and issue a fresh one. Redemption registers a passkey and starts the account's 24-hour cooling-off; it restores no removed membership and bypasses no Google rule. An unavailable workspace keeps the intent pending: repair it and let the cron retry, never force a transition or fabricate an acknowledgement, and never use a D1 bookmark as a recovery shortcut.

## Freezing and unfreezing

Freeze when something looks wrong and you have not worked out what yet. A freeze is one workspace's: it refuses every credential use by that workspace's devices and everything that widens (`frozen`, HTTP 423) and leaves the account's other workspaces alone. Reads and narrowing carry on: devices can still run `mehen status`, list and describe, see pending, end runs and revoke themselves; members can still read, deny, revoke devices and unfreeze.

- From any enrolled machine whose owner is not a guest, a team's included: `mehen freeze` (`POST /v1/freeze`).
- From the web UI: any member who is not a guest, on the workspace's home page, "Freeze everything". No passkey needed: pulling the brake is always allowed.
- From the operator console: any one operator, on the workspace's page under Workspaces, "Freeze with passkey" (`workspace.freeze`, no second operator). It is the workspace's own freeze, recorded in its own audit chain as `operator:<account id>`, and in `deployment_events`; the workspace's owners and admins and every operator get a notice. The operator's standing and the workspace are read again just before the object freezes. Once it has, the freeze is recorded even when the operator's standing or the workspace changed meanwhile: that `deployment_events` row carries `unguarded: true` and a `reason` (`operator-changed` or `target-changed`), the notices still go out, and the answer says so. When an owner froze it first, nothing is recorded and the console says it was frozen already. The console never unfreezes.
- Tripwires (a placeholder out of place, a fenced host) are recorded in the audit chain but do not freeze the workspace.

Unfreeze from the workspace's home page as an **owner**, with a passkey step-up (`workspace.unfreeze`). Read the audit chain first.

## Revoking a device

- From the web UI: the workspace's Machines page, pick the machine, revoke, confirm with a passkey (`device.revoke`). Its owner, an owner or an admin can; for a team's machine, an owner or admin.
- From the device itself: `mehen revoke [--workspace <slug>]` (`POST /v1/devices/self/revoke`), which also removes that workspace's slot from the machine once the vault confirms; the machine's other workspaces' keys stay. When the vault cannot be reached, `mehen workspace forget --slot <path>` retires the slot on the machine only, and the device stays listed until someone revokes it on the Machines page.

A revoked device's proofs fail with `device_revoked`. Grants held by that device become unusable because the device can no longer authenticate. To use the machine again, enrol a fresh key with `mehen enrol --workspace <slug>`. Narrowing a machine instead (fewer tags or projects, no protected environments, no private credentials) is `device.rescope` on the same page, by the same people; widening one needs its owner's own acceptance again.

Removing a person from a workspace (People, `member.remove`, an owner or admin; an owner for an owner) revokes all their machines, deletes their private credentials, voids every approval they decided and records which credentials they had been exposed to, so the rotation list is in the audit; suspending them (`member.suspend`) stops their machines at once and keeps everything for reinstatement.

## Reading the audit chain

Each workspace has its own chain. The web UI's Audit page (`/w/<slug>/audit`) shows events newest first. The API is `GET /api/w/:ws/audit` with `before=<seq>` or a `cursor`, returning `{ events, head, verified, filtered, next }`, 50 events a page by default and up to 200 with `limit`, where `head` is `{ seq, hash }` of the newest event and `verified` is the server's own walk of the whole chain. Owners and admins read the whole chain and get `head`; everyone else gets `head: null` and only the events their rights cover (a member: their own actions and machines, the projects they edit or manage, their teams, the credentials they may see, their own private credentials' minimised events; a guest: their own actions and machines only), with `filtered: true` exactly when some stored event was left out. Each event has:

| Field | Meaning |
| --- | --- |
| `seq` | Sequence number, from 1 |
| `at` | Time, milliseconds since the epoch |
| `actor` | `device:<id>`, `enrolment:<id>`, `member:<id>`, `system` or `public` |
| `action` | For example `item.create`, `relay.allow`, `relay.refuse`, `relay.tripwire`, `relay.echo`, `approval.approve`, `run.lease`, `member.remove`, `override.set`, `workspace.freeze` |
| `target` | The slug or id acted on, or null |
| `detail` | Canonical JSON of extra fields: slugs, ids, hosts, field names, never values; for a private credential only the minimal fields (`PrivateEvent` in the protocol package), never hosts or paths |
| `prev` | The previous event's hash (`mehen/audit/v1` for the first) |
| `hash` | This event's hash |

As implemented in `apps/vault/src/vault/audit.ts`:

```
hash = base64url(SHA-256(prev + "\n" + canonicalJson({ seq, at, actor, action, target, detail })))
```

where `detail` is the canonical JSON string as stored, and canonical JSON sorts keys and has no whitespace (`canonicalJson` in `packages/protocol/src/canonical-json.ts`). To verify: page back to `seq` 1, walk forward checking each `prev` equals the previous `hash` and each `hash` recomputes; the API does the same walk on every read and reports it as `verified`. Keep a note of `head` from time to time somewhere outside the vault; if a later read does not extend from it, history was rewritten. There is no `mehen` command that does this check.

What the audit chain does not hold: refusals by the local relay of `mehen run`, which happen on the machine.

## Incident playbook: a leaked device key

"Leaked" means a `software` key file was copied, or a machine (Secure Enclave or not) was compromised, so someone else can sign as that device.

1. **Contain.** If you are not sure which device or how far it went, freeze the workspace first ("Freeze everything", or `mehen freeze` from any other enrolled machine in it). Then revoke the device from the web UI with a passkey. A key is scoped to one workspace, so a leaked key reaches one workspace; a compromised machine enrolled in several has one key per workspace, each to be revoked in its own.
2. **Scope.** Read the audit chain for `actor` `device:<id>` from the earliest time the key could have leaked, as an owner or admin so nothing is filtered. Note every item it used, in which mode, against which hosts, and any intakes, connects, runs, leases and approvals it asked for. A private credential's events carry no hosts or paths: ask its owner to check the provider's own logs.
3. **Rotate what was exposed.**
   - Items the device **leased** (`run.lease` events): the value reached that machine. Rotate each at its provider, then replace it in the vault through an intake: an owner or admin, or a manager of its project, from its credential page, or `mehen request <kind> --name <slug> --home workspace` (or `--home project --project <prj_id>`, naming the credential's current home: rotation keeps the home and a different one is refused) from another machine that may use it.
   - Items it used in relay or placeholder mode: the value never left the vault. Rotation is not needed for the secret itself, but review what was done with it (the requests are in the audit) and undo what you can at the provider.
4. **Review approvals and grants** the device held or asked for. Deny anything pending you do not recognise.
5. **Look for persistence** at the providers: new deploy keys, webhooks, OAuth apps, mail forwarding rules, API tokens. Templates deny or hold many of these, but check.
6. **Clean the machine** (or retire it), then enrol a new key with `mehen enrol --workspace <slug>`. Never re-enable the old key.
7. **Unfreeze** as an owner with a passkey once you are satisfied.
8. **Write it down**: what leaked, how, what was rotated.

## Incident: a leaked root key or a hostile deploy

If a root key, or the right to deploy the Worker, may have reached someone else, assume every secret is exposed: the threat model (https://docs.mehen.dev/security/threat-model) explains why. Freeze, secure the Cloudflare account, rotate every credential at its provider, and add a new root key version as above. Rotating the root key alone does not help against someone who already decrypted. Check who and what holds deploy rights on the Cloudflare account, and keep agents off it.

## Platforms

A platform is a business that serves its own users through Mehen, with one managed workspace per user and no Mehen page, account or passkey anywhere ([Platforms and managed workspaces](https://docs.mehen.dev/concepts/platforms)). The operator registers it, and afterwards only watches, limits, suspends, rotates, retires and removes it. The operator never opens a secret and never acts inside a managed workspace: there is no command or page for either.

Two ways in reach the same D1 state, because they run the same plans (`src/platform/operator-plan.ts`): the operator console in the web app, for an account holding the operator role, and `scripts/platform.ts` from the operator's machine, which stays the break-glass beside it. A platform's admins manage that one platform in the web app ([Platform admins](#platform-admins)). The commands below are the script's; each has its action on the console's platform page, with the same checks and the same refusals.

### What platform mode adds to a deploy

- **D1:** `migrations/0010_platforms.sql`, applied before the deploy that reads it (it is additive; nothing existing changes).
- **Durable Objects:** the `PlatformVault` class under the tag `v4-platform-vault`.
- **Rate limits** (`src/rate-limits.ts`): a platform call meets `PLATFORM_IP_RATE_LIMITER` (6000 a minute per address), then, once its proof verifies, the platform's own limits, counted by its `PlatformVault` (the operator changes those without a deploy). A device or workload call meets `DEVICE_IP_RATE_LIMITER` (6000 a minute per address), then `DEVICE_RATE_LIMITER` (600 a minute) keyed by the workspace and device its proof claims. The outer limits are high because a platform's Workers reach the vault from Cloudflare's shared egress addresses, and one address can carry many unrelated callers. Signing in keeps `AUTH_RATE_LIMITER`, and every other route `RATE_LIMITER`, per address, as before. All five bindings must be in the Worker's configuration: a missing one refuses every request it would have counted with `rate_limited`, and logs `limiter_unbound` with the binding's name.
- **The cron** (`maintainPlatforms` in `src/platform/sweeps.ts`, run by the directory's maintenance): every run retires platforms whose `retire_after` has passed (their live subjects are marked `deleting`; once none is left the platform's object is erased, its keys revoked and its row marked `retired`), marks `deleting` any subject whose creation was interrupted more than 10 minutes ago, deletes up to 50 subjects marked `deleting`, purges up to 50 deleted subjects whose audit retention has passed, and copies each platform's last day of activity into `platform_events` for `show`.

After the deploy, `curl -s https://app.mehen.dev/v1/platform` answers `unauthenticated`.

### The operator console

The operator console is the Operator area of the web app. It shows only to an account holding the operator role, and every one of its routes (`/api/operator/...`) answers every other account, signed in or not, exactly as a route that does not exist (`not_found`), with a method it does not take too (an operator gets `405`). Who holds the role, and how it changes, is under [Operators](#operators).

Its Workspaces view (`/operator/workspaces`) lists every workspace, a page at a time and newest first, searched by part of its name or slug or by its whole id, and filtered to active, creating, deleting or platform-managed ones: each with its status, its owners by name (from the workspace itself), its members counted and who created it. One workspace (`/operator/workspaces/tn_<id>`) adds its earlier slugs, its people counted by role and how many are unconfirmed, its dumps and restores, and its operator events. Its only changes are [restoring it](#restoring-a-workspace) and [freezing it](#freezing-and-unfreezing). It never shows a credential, a project, a member other than its owners, a machine or the audit chain's contents. A platform's workspaces are listed by platform, never by subject.

In the console the operator lists every platform (status, subject counts by status, keys, limits and admins), reads one (with its defaults' revision, the last day's usage and its events) and does everything the script does: register (with a public JWK pasted, or a key pair made in the browser whose private key is shown once and never sent), suspend, resume, rotate a key with an overlap, revoke a key, set limits, delete every subject, retire, remove, and add or remove admins. Every write:

- needs a fresh passkey step-up from the operator's account, started on `/api/operator/stepup/start`, bound to the platform's slug and id (a new platform's slug alone, for register), the command and the SHA-256 of the whole command, at most five minutes old and used once;
- for a destructive command (suspend, revoke a key, delete every subject, retire, remove), and for one that adds a key (register, rotate a key), also needs the platform's slug typed back;
- is planned by the script's own planner and applied in one batch that first checks the account still holds the role, so a revoked role writes nothing;
- writes one `platform_events` row with actor `operator:<account id>` (the script's are `operator:<your-name>`), and gives the operator's account a notice; adding or removing an admin also gives that admin a notice, removing a platform gives each admin it ends one, and adding a key (register, rotate) gives one to every other operator account and every live admin of the platform.

The console refuses every write, before any passkey is asked for and again in the write's own batch, from an account that lacks anything an operator account must have ([Operators](#operators)): it says exactly what is missing at the top of the Operator area, and reads stay open. It never shows anything inside a managed workspace.

### Operators

An operator is a Mehen account with the operator role (`accounts.is_operator`). The role opens the Operator area: the platforms, the [Settings](#settings) and [Audit](#audit) views, and the Operators view (`/operator/operators`), which lists every operator with their passkeys (how many are security keys), whether recovery is ready and when they were last seen, the open and recent proposals, and the operator events.

**What an operator account must have.** Recovery set up; at least two passkeys, at least one of them a security key (a passkey whose transports are USB, NFC or Bluetooth only, as Your account labels "A security key"); no cooling-off after a recovery; and no security change pending. It is checked on every operator write (the platform pages' too) and when the role is granted: at the proposal, at the approval, and when the account itself accepts. An account missing something is told exactly what in the Operator area, and its writes are refused with the same words before any passkey is asked for. Resigning is the one exception: it only removes power.

**Two operators for a change to the role.** In the app the role changes only by proposal:

- **Making an operator** (`operator.grant`): one operator proposes the account (found by its id or the email of its Google sign-in, a lookup rate limited per operator account), a different operator approves it within 24 hours, then the account accepts on Your account with its own passkey; only then is the role set.
- **Ending another operator's role** (`operator.revoke`): proposed by one operator, approved by another.
- **Resigning** (`operator.resign`): your own role, with one passkey and no second operator.

Each proposal is a row in `operator_proposals`, bound by the SHA-256 of the canonical JSON of its kind, target and parameters; proposing and approving are each signed with a passkey for that digest (`operator.propose` and `operator.approve`, started on `/api/operator/stepup/start`), and accepting with the target's own (`operator.accept`, on `/api/account/stepup/start`). The proposer cannot approve their own proposal (refused in the code and by the table's `CHECK`), nobody proposes or approves a change to their own account, there is one open proposal per kind and account, and a proposal not approved within 24 hours expires (the cron, and every read). Another operator may decline a proposal, except the one it names (refused in the code and by the table's `CHECK`), and the proposer may cancel it, without a passkey. Approving or accepting first works the digest out again from the stored kind, target and parameters and refuses a proposal whose stored terms no longer give it. Applying it is one batch that checks again that the proposal is open, unexpired and has the digest signed, and that both operators still hold the role with everything an operator account must have. The last operator cannot resign or be revoked in the app: it says "Mehen needs at least one operator; use the script". Until there are two operators, every two-operator change is disabled and says "Needs a second operator; use the script".

Every operator action outside a platform is a row in `deployment_events` (`kind`, `actor` `operator:<proposer>`, `approver` `operator:<approver>` for a two-operator change, `target`, `details`), as a platform's changes are rows in its `platform_events`: proposing, approving, declining, cancelling, expiry (actor `system`) and each change applied, and the scripts' `grant-operator` and `revoke-operator` too, each only when the role changes (granting an operator or revoking a non-operator changes nothing and records nothing). Each also gives every operator account a notice, and the account it names one when it is approved for it and when that approved grant expires; a change to the role also writes that account's own `account_events` row and notice, through the 0012 trigger.

**Adding the first extra operators.** With one operator there is nobody to approve a proposal, so the first extra operators are added once by script, from the operator's machine:

```sh
cd apps/vault
bun scripts/operator.ts --remote grant-operator acc_<id> --actor operator:<your-name>
bun scripts/operator.ts --remote revoke-operator acc_<id> --actor operator:<your-name>
```

Like `allow-workspaces` and `deny-workspaces`, it prints the D1 bookmark, asks for the account id typed back, and runs one `UPDATE` whose trigger refuses a change without an explicit `operator:` actor and a fresh operation id, and writes the operator event (`operator.grant_operator` or `operator.revoke_operator`) and the account's notice in the same statement, then records the `deployment_events` row only if the `UPDATE` landed. Each account's id is on its own Your account page. Check that each new operator's account has everything an operator account must have; the script does not, and the Operators view shows what each lacks. After that, every change to the role happens in the app.

### Accounts

The Accounts view (`/operator/accounts`) lists every account at the deployment, newest first, 50 to a page: its name and id, the email of its first Google sign-in, pills for an operator, a suspension, a cooling-off, a security change still pending and recovery not set up, when it was last seen, how many workspaces it is in, its passkeys (how many, how many synced, how many security keys), its recovery and where its workspace creation comes from. It is searched by name, `acc_` id or linked Google email, and filtered to the suspended, those cooling off, those without recovery, those in no workspace, or the operators. One account's page (`/operator/accounts/acc_<id>`) adds its workspaces (the directory's role, labelled a hint, since each workspace holds its members' roles), its passkeys (name, kind, synced, added, last used), its live sessions as counts by kind, and its events, newest first. Nothing in it is a key, a hash or a token, and nothing opens a workspace.

Its changes are operator proposals, under the rules in [Operators](#operators) (an operator account with everything it must have, a passkey for the change's digest, a `deployment_events` row, and never your own account):

- **Workspace creation** (`account.workspace_creation`): Allow, Deny or Back to default, one operator; only the account is told.
- **Suspend** and **Lift** (`account.suspend`, `account.lift_suspension`): one operator, never on an operator's account (end the role first). Suspending sets `accounts.suspended_at` and deletes every session of the account in the same batch, so lifting never brings one back; the account's security transition then raises its epoch in every workspace, and the cron reserves it again if that first try fails. While suspended the account cannot sign in with a passkey or a recovery code, redeem a recovery link, use a session or step up, and it is told why once it has proved who it is. Its machines keep their scope in each workspace: that is the owners' call, and each workspace's owners and admins get a notice ("An operator suspended <name>'s account"). Lifting clears the flag; the person signs in again. Every operator and the account are told of both.
- **Recover access** (`account.break_glass`): two operators, never on an operator's account ([Account break-glass](#account-break-glass)).
- **Delete account** (`account.delete`): two operators, the account's name typed back, never an operator's account, and only for an account in no workspace (the page lists the workspaces whose owners remove it first) and no platform's admin (the refusal names each platform; remove them on its page first). The proposal keeps only a hash of the typed name, bound to the account, never the name. Applying it sets `status='deleted'` and `deleted_at`, makes the name "Deleted account", and deletes its passkeys, sessions, recovery codes, linked Google sign-ins and notices; its row and its events stay. It cannot be undone.

Until there are two operators, Recover access and Delete account are disabled and say "Needs a second operator; use the script".

**The scripts are the break-glass.** `scripts/operator.ts`, `scripts/platform.ts` and `scripts/break-glass.ts` need no role and no second operator: they are for when the app is down or every operator is locked out. Whoever can write D1 or deploy the Worker bypasses all of this, the two-operator rule included, so keep those powers with the people who hold the operator role and nobody else.

### Settings

The Settings view (`/operator/settings`) holds what the deployment decides for every account, each value in force capped by a ceiling the deploy sets in `wrangler.jsonc`:

| Setting | Values, narrowest first | Ceiling | With nothing set |
|---|---|---|---|
| Workspace creation (`workspace_creation`) | only accounts an operator allows (`operator`), every account (`accounts`) | `WORKSPACE_CREATION` | the ceiling, as before there were settings |
| Sign-up (`signup_mode`) | invitation only (`invite`), request access (`request`), open (`open`) | `SIGNUP_MODE_MAX` | invitation only |

The value in force is the one the operators set, capped by the ceiling; a ceiling that is missing or not one of the setting's values is its narrowest. **Narrowing is one operator with a passkey** (`settings.narrow`, applied at once); **widening is a two-operator proposal** (`settings.widen`, approved by a different operator within 24 hours), and never past the ceiling, so even two operators cannot widen what the deploy does not allow: raising a ceiling is a change to `wrangler.jsonc` and a deploy. Both are proposals like a change to the operator role ([Operators](#operators)): signed with a passkey for their digest, checked again in the batch that applies them (a change made meanwhile, such as another operator narrowing first, makes the approval apply nothing), recorded in `deployment_events` with the value set, and told to every operator. A widening names the value in force it was proposed from and applies only while that is still the value in force. A narrowing is a brake: it cancels every open widening of the same setting (a `proposal.cancel` event whose reason is that the setting was narrowed, and a notice to the operator who proposed it), so an approval already on its way cannot undo it. A value stored above a ceiling a later deploy lowered can be narrowed to the value in force, so raising the ceiling again does not bring it back. The view shows each setting's value, who set it and when, the ceiling and the variable it comes from, and says why a wider choice is disabled.

Workspace creation set to only accounts an operator allows applies at once to the creation check: an account no operator decided on can no longer create workspaces, and an operator's decision for one account (in the Accounts view, or `allow-workspaces` and `deny-workspaces` in the script) still wins over it. Sign-up is stored and shown only: request access and open sign-up are not built, so the view shows them as not available yet and the vault refuses a change to either, `SIGNUP_MODE_MAX` stays `invite` in production, and sign-up is by invitation whatever the setting says.

A lone operator can narrow but not widen in the app. The break-glass for that, or for any setting when the app is down, is the script, which reads the ceiling for the database it names from `wrangler.jsonc` (the top-level `vars` for `--remote`, `env.local` for `--local`) and refuses a value above it, or a run where it cannot read one:

```sh
cd apps/vault
bun scripts/operator.ts --remote setting workspace_creation accounts --actor operator:<your-name>   # widen, up to WORKSPACE_CREATION
bun scripts/operator.ts --remote setting workspace_creation --default --actor operator:<your-name>  # clear it: the deploy's default again
```

Like the other commands it prints the D1 bookmark and asks for the setting's key typed back; it writes the setting and a `settings.set` row in `deployment_events` in one batch.

### Audit

The Audit view (`/operator/audit`) is one read-only list, newest first, across every operator and deployment change the database records: `deployment_events` (proposals and their outcomes, the operator role, settings), `platform_events` (everything done to a platform, but its rolling activity counter) and the `operator.*` rows of `account_events` (the operator script's flags on an account, and the role's own rows). Each row names its actor and approver, with the account's name where it is one; a proposal's row says its outcome and who proposed, approved or declined it. It filters by actor, action and target (any part of each; the actor filter matches the approver too), and by a range of UTC days, 50 rows a page, the next page after the last row's time and id.

It is a record in D1, not a hash chain: anyone who can write D1 can change it. That is why Cloudflare's own audit log of the account (who deployed, who ran D1 commands) is the second record, and the one to read when this one is in doubt.

### Platform admins

A platform has zero or more admins: Mehen accounts the operator adds on its console page (or `add-admin <slug> acc_<id>` and `remove-admin <slug> acc_<id>` with the script), each change a `platform_admins` row (ended, never deleted) and an `operator.add_admin` or `operator.remove_admin` event. An admin sees the Platforms area of the web app, listing only the platforms they administer, and every route of any other platform (`/api/platforms/...`) answers `not_found`. For each of theirs they read its status and limits, subject counts by status, the last day's usage, its events, its keys and its defaults, and change, each with their own passkey (started on `/api/platforms/<slug>/stepup/start`) and audited with actor `admin:<account id>`:

- the defaults, with the same schema and rules as the platform's own `defaults.put`, from the revision they read, which moves;
- the keys: add one, ending the others after an overlap, or revoke one, each with the slug typed back, never the last live key; adding one also gives every operator account and the platform's other admins a notice;
- one subject, deleted by the subject string the platform knows, typed in with the slug: it is marked `deleting` and deleted at once, and the cron finishes it if that fails; the event names its workspace and the subject's hash, never the subject, and the workspace's own audit, which the platform reads until the purge, names the admin (`admin:<account id>`).

An admin cannot register, suspend, resume, retire or remove a platform, change its limits, add admins, or read anything inside a managed workspace through the console. Removing a platform ends all its admins, and each is given a notice.

A key added in the console, by the operator or an admin, is the platform: until it is revoked, whoever holds its private half can provision devices, use every credential by relay, decide held requests, and read item lists and audits in every one of that platform's users' workspaces ([threat model: a platform](https://docs.mehen.dev/security/threat-model#a-platform)).

### Register a platform

The platform makes its own P-256 key on its own machine and sends you the public JWK; never accept, see or keep a private key. Then, from the operator's machine:

```sh
cd apps/vault
bun scripts/platform.ts --remote register <slug> --name "<Name>" --key <public-jwk.json> [--limits <limits.json>] --actor operator:<you>
```

The script refuses a key file holding a private part (`d`). Like every platform command it prints the D1 bookmark and the plan, asks for the platform's slug typed back, runs one guarded batch and writes one `platform_events` row. It prints the platform id (`plt_...`) and the key id (`pky_...`): send both to the platform. Without `--limits` the platform gets the defaults ([Platform API: limits](https://docs.mehen.dev/reference/platform#limits)); a limits file names only the limits that differ from them. The slug is 3 to 40 lower-case letters, digits and single hyphens, starting with a letter; the name at most 64 characters; the actor `operator:<you>`.

### See a platform

```sh
bun scripts/platform.ts --remote show <slug>
bun scripts/platform.ts --remote subjects <slug> [--status <status>]
```

`show` is one platform with its workspaces: its status (with who set it, when and why, and any retirement date), keys, limits and defaults' revision, its workspaces counted by status, the last 24 hours' counts of devices made, items added and deleted, decisions and refusals, as of the cron's last copy (every 15 minutes), and how many operator actions it had in the last 24 hours. Those counts are the signal for a platform behaving oddly. `subjects` lists its workspaces one line each: the `tn_` id, the subject (`(purged)` once purged), the status and the dates; `--status` takes `creating`, `active`, `deleting`, `deleted` or `purged`. Neither shows anything inside a workspace.

### Suspend and resume

```sh
bun scripts/platform.ts --remote suspend <slug> --reason "<words>" --actor operator:<you>
bun scripts/platform.ts --remote resume <slug> --actor operator:<you>
```

A suspension stops the platform's own calls at once (`platform_suspended`) and its devices' calls within 30 seconds, because each managed workspace reads its platform's status at most every 30 seconds; consents the platform gave are honoured for that long too. A device may still freeze its workspace or revoke itself. Scheduled OAuth refreshes wait, looking again every 5 minutes. Nothing is deleted. Suspending a retiring platform clears its retirement date. `resume` undoes a suspension, or a retirement whose date has not passed.

### Rotate or revoke a key

```sh
bun scripts/platform.ts --remote rotate-key <slug> --key <new-public-jwk.json> [--overlap-hours 24] --actor operator:<you>
bun scripts/platform.ts --remote revoke-key <slug> <pky_id> --actor operator:<you>
```

`rotate-key` adds the new key and ends every other live key after the overlap, 24 hours by default and at most 168; tell the platform to deploy the new key inside it. `revoke-key` ends a key at once: use it for a leak.

### Limits

```sh
bun scripts/platform.ts --remote limits <slug> --limits <limits.json> --actor operator:<you>
```

The file is a JSON object of the limits to change; the ones it does not name keep their values, and the result must pass `PlatformLimitsSchema` (the plan prints the limits before and after). Every managed workspace reads the new limits within 30 seconds, and the platform's own call counters use them at once; no deploy on either side. The defaults are guesses until the platform has run for a while: read `show`'s counts before raising or lowering them.

### Delete a platform's users, or retire it

```sh
bun scripts/platform.ts --remote delete-subjects <slug> --reason "<words>" --actor operator:<you>
bun scripts/platform.ts --remote retire <slug> --after-days <n> --actor operator:<you>
```

`delete-subjects` marks every live subject `deleting` at once (their platform calls stop at once, their devices' within 30 seconds) and leaves the platform registered; the cron then deletes them 50 a run, and `show` counts them down. A platform can do the same itself (`DELETE /v1/platform/subjects`). With no live subject it changes nothing.

`retire` (from `active` or `suspended`, `--after-days` 0 to 365) stops new subjects at once and keeps everything else working until the date; from the date the platform's calls are refused as if suspended, then the cron deletes every subject, empties the platform's object, revokes its keys and marks it `retired`, keeping the row as a tombstone. Retiring a suspended platform with a later date lifts the suspension until that date. For an abusive platform: `suspend`, then `retire --after-days 0`, which keeps it stopped.

Deleting a subject revokes every device, deletes every secret at once, hands Google tokens back to Google (GitHub's and Microsoft's grants stay at the provider), and keeps the audit, which holds no secrets, for the platform's retention (30 days by default, 0 to 90); then the workspace's storage is erased and the `managed_workspaces` row keeps only the subject's hash and the chain's final head.

### Remove a platform and set it up again

Removing a platform frees its slug for a new registration and keeps what Mehen keeps for the record. Use it when a platform is to be set up again from scratch, or is gone for good:

```sh
bun scripts/platform.ts --remote remove <slug> --reason "<words>" --actor operator:<you>
```

or **Remove** on the console's platform page, with the slug typed back and a passkey. From `active`, `suspended`, `retiring` or `retired`, in one batch:

1. The platform is retired at once (`retiring` with today as its date, unless it is already `retired`): its calls are refused at once and its devices' within 30 seconds, and no command or admin change applies to it from then on.
2. Every live subject is marked `deleting`, and every admin is ended.
3. One `operator.remove` event records the reason, the status it had, its slug and its live subjects.

Then the cron, with no further step: it deletes each subject through the subject lifecycle (devices revoked, secrets deleted, Google tokens handed back), 50 a run; purges every deleted subject without waiting for its audit retention, because once the platform's keys are revoked no one can read that audit; empties the platform's object, revokes its keys and marks it `retired` (`platform.retired`); and once every subject is purged renames its slug to `removed-` and 24 random characters, keeping the old slug in `removed_slug` (`platform.removed`). With up to 50 subjects that takes two cron runs, about half an hour; `show` and the console say when it is done (the console's `removal.completedAt`).

**What is kept:** the `platforms` row (name, limits, defaults, status, every date and who set it, and the slug it had), its keys' public halves (revoked), every `platform_events` row, the `platform_admins` rows (ended), and each subject's `managed_workspaces` row as a tombstone holding only the subject's hash and its audit chain's final head. **What goes:** every subject's workspace (secrets, items, devices, audit), each subject's name, and the platform's object (its spent nonces, counters, activity and its own audit of defaults and delete-all), exactly as a retirement and a purge already do. Nothing secret is left: D1 never held a secret.

**Setting it up again**, for example a platform with the slug `acme`:

1. Remove it: `remove acme --reason "Set up again"` (or the console). Watch `show acme` until the removal is complete; then `show acme` answers "No platform with that slug." and the old platform is listed under its `removed-...` slug.
2. Ask the platform for a **new** key pair (or make one in the console, which shows the private key once for the platform's server): a key's thumbprint belongs to one platform for good, so the old public key is refused ("that key is already registered").
3. Register the slug again, from the console or with `register acme --name "Acme" --key <new-public-jwk.json>`. It gets a new `plt_` id and `pky_` id; give both to the platform for its configuration, with the new private key.
4. Add its admins again on the console page.
5. The platform's users start again: every managed workspace is new, and the platform makes each one on its next call for that subject.

A slug starting `removed-` cannot be registered.

### Incident: a platform key leaked, or a platform behaving oddly

1. **Suspend first:** `suspend <slug>`. The platform's calls stop at once and its devices' within 30 seconds.
2. **Read** `show`'s counts, and ask the platform for its users' audit (it reads each workspace's chain; you do not).
3. **Revoke** the leaked key (`revoke-key`), and register the platform's new key with `rotate-key --overlap-hours 0`.
4. **Tell the platform** what you saw and what you did; it tells its users.
5. **Resume** once the platform has a new key deployed and agrees the cause is closed.

A hostile platform can use and approve within its users' credentials' destinations and policies, but cannot read a stored key; whatever its users typed into its pages while it was hostile must be treated as exposed, and that is for the platform's users to rotate.

## The lander

`https://mehen.dev` is a static page served by its own Worker, `mehen-web`, from `apps/web`. It has no secrets, has `ASSETS` and the public `RELEASES` R2 binding, and nothing in common with the vault at run time. `src/index.ts` sends `www.mehen.dev` to the apex with a 301, then serves the file from `public/` with a strict content security policy and cache headers.

Build and check, from the repository root:

```sh
bun run --cwd apps/web build    # brand assets and the exact installer
bun run --cwd apps/web check    # build, typecheck, every link and anchor resolves, no em or en dashes, wrangler deploy --dry-run
```

`public/fonts`, `public/favicon.svg` and `public/install` are build output and gitignored. The installer is copied from `tools/release/install.sh` at build time, byte for byte; `style.css` carries the Papyrus palette and `@font-face` rules itself. Other files in `public/` are source. Links from the pages may go only to `mehen.dev`, `app.mehen.dev`, `docs.mehen.dev` and `github.com`, over https, and mail links only to an address at `mehen.dev`.

The guides moved to the docs site. The Worker answers the old addresses with a 301 and a one-line plain-text body naming the new URL, so an agent whose fetch tool does not follow redirects still lands: `/setup.md`, `/skill.md` and `/SKILL.md`, `/llms.txt`, `/setup` and `/setup/`, and `/docs` and anything under it. `/setup.md` keeps redirecting indefinitely, because 0.3.0 binaries in the wild print it. `/install` and `/dl/` stay with the lander.

Deploy, as the operator:

```sh
cd apps/web
bunx wrangler deploy            # runs the build first; or: bun run deploy
```

The first deploy creates the custom domains `mehen.dev` and `www.mehen.dev`. Then check:

```sh
curl -sI https://mehen.dev/                 # 200, with content-security-policy
curl -sI https://www.mehen.dev/some/path    # 301 to https://mehen.dev/some/path
curl -sI https://mehen.dev/nope             # 404, the lander's own 404 page
curl -sI https://mehen.dev/setup.md         # 301 to https://docs.mehen.dev/setup.md
```

## The docs site

`https://docs.mehen.dev` is the public documentation, for humans and agents, served by its own Worker, `mehen-docs`, from `apps/docs`. It has no secrets and no bindings but `ASSETS`. The sources are the markdown under `docs/site/` (one file per page, `key: value` front matter, `site.json` for the category line, the promise, the sections and the hosts pages may link to); the five reference pages are generated at build time from the CLI's command table, the protocol's error and exit tables, the MCP tool fixture, the template catalogue and the protocol's platform route table, so they cannot drift. A platform route whose prose is missing fails the generation, and so does a platform limit with no `### <limit>` entry in `docs/site/reference/platform.md`. Every page says which side it covers with `covers: both`, `local` or `cloud` in its front matter, which the build prints under the title as "Covers: Local and Cloud", "Local only" or "Cloud only" and a page without it fails the build (a page that serves another file's bytes has none). Every page is also served as markdown at `<path>.md`, and as markdown to a request with `Accept: text/markdown`; `/llms.txt`, `/llms-full.txt`, `/index.json` and `/reference/*.json` are for agents. The Worker adds the security headers, answers `/search` without JavaScript and serves the 404. No public page names a file in this repository.

The security contact is `security@mehen.dev` (`/security/disclosure`). All three Workers serve `/.well-known/security.txt` from code (`securityTxt` in `apps/docs/src/index.ts`, `apps/web/src/index.ts` and `apps/vault/src/routes/well-known.ts`); its `Expires` is about a year out and their tests fail once it has passed, so move it forward in all three files before then.

Build and check, from the repository root:

```sh
bun run --cwd apps/docs build   # generated/ from the CLI and protocol, then public/: pages, twins, llms, indexes, scripts, brand files
bun run --cwd apps/docs check   # build, typecheck, the docs lint (commands, flags, codes, tools, variables, links, internal words, dashes, shape), tests, wrangler deploy --dry-run
```

Everything in `apps/docs/public/` except `docs.css` is build output and gitignored, and so is `apps/docs/generated/`. The build is reproducible: no dates, and `index.json` carries the CLI version and the short commit only. The role tokens in `docs.css` are the app's (`apps/vault/src/ui/client/app.css`); a test fails when they drift.

Deploy, as the operator, before `mehen-web` and `mehen-app`, so no redirect points at a site that is not there:

```sh
cd apps/docs
bunx wrangler deploy            # runs the build first; or: bun run deploy
```

The first deploy creates the custom domain `docs.mehen.dev` in the `mehen.dev` zone. Then check:

```sh
curl -sI https://docs.mehen.dev/                                     # 200, with content-security-policy
curl -sI https://docs.mehen.dev/setup.md                             # 200, text/markdown
curl -sI -H 'Accept: text/markdown' https://docs.mehen.dev/concepts  # 200, text/markdown, Vary: Accept
curl -sI https://docs.mehen.dev/nope                                 # 404, no-store
```
