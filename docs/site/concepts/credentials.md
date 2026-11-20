---
title: Credentials
question: What is a credential, and where may it go?
section: concepts
covers: both
order: 30
---

# Credentials

## Items

An **item** is one credential. It has:

- a unique **slug** (`openai-personal`, `github-work`): lower case letters, digits and single dashes, 2 to 64 characters, starting with a letter, not ending with a dash; unique across the whole workspace, whichever home it has;
- a **kind** from the closed list below;
- a [home](#homes): the workspace, one project, or one member;
- an optional **provider template** ([Providers and templates](../reference/providers.md));
- the **account** it acts as, and whether that account was verified with the provider;
- **tags**, public fields, secret fields (encrypted), a [binding](#bindings), an [injection](#injections), a [policy](policy.md), a [ceiling](#the-exposure-ladder), a status, an optional [review flag](audit.md#review-flags) and a version.

Agents can describe an item safely (`mehen show`): kind, provider, account, tags, ceiling, hosts, binding, policy, injection, public fields, and for each secret field whether it is set, its length, a well-known prefix (`sk-proj-`, `ghp_`, never secret characters) and a fingerprint. That answers "is the key set, and is it the one I think?" without seeing the value.

A secret field's fingerprint is keyed: the first 12 characters of an HMAC of the item and the value under a per-workspace key derived from the root key, so someone holding only the stored data cannot test guesses against it.

Item status in summaries is one of `active`, `needs_reauth`, `refresh_retrying` or `disabled`.

## Kinds

The kinds are a closed list. New kinds arrive by code review, never from an agent or a request.

| Kind | Fields (secret in bold) | Default ceiling | Highest ceiling allowed |
| --- | --- | --- | --- |
| `api-key` | **key** | placeholder | lease |
| `bearer-token` | **token**, expires_at | placeholder | lease |
| `basic-auth` | username, **password** | relay | lease |
| `custom-headers` | **headers** (JSON map of header to value) | relay | relay |
| `oauth-client` | client_id, **client_secret** | relay | relay |
| `oauth-connection` | **access_token**, **refresh_token** | relay | mint |
| `google-service-account` | **key_json** | mint | mint |
| `github-app` | app_id, **private_key** | mint | mint |
| `hmac-key` | **key** | sign | lease |
| `ssh-key` | **private_key**, public_key | sign | sign |
| `password-login` | url, username, **password**, **totp_seed** | relay | reveal |
| `totp` | **seed** | relay | reveal |
| `database-url` | **url** | lease | lease |
| `smtp-imap` | host, username, **password** | lease | lease |
| `cloud-access-key` | access_key_id, **secret_access_key** | lease | lease |
| `file` | filename, **content** | lease | lease |
| `note` | **text** | reveal | reveal |
| `generic` | **value** | lease | lease |

What machines can do with each kind today: the relay sends any item with an injection (`api-key`, `bearer-token`, `basic-auth`, `custom-headers`, `oauth-connection`, and anything a template gives an injection); `oauth-client` items are used only by the vault itself to connect and refresh; lease-ceiling items reach `mehen run` children. Signing and minting are not built. Service-account, GitHub App and SSH signing uses are unavailable, and the vault refuses to ask for a `google-service-account` or `github-app` at all ([Request a credential](../guides/request-a-credential.md)). An HMAC key cannot be used to sign through Mehen; if a human explicitly sets its ceiling to lease and the machine and run allow it, its key field can be delivered to the child. SSH certificates, client certificates, SSH agent forwarding, SigV4, mTLS and protocol connectors are not built.

## Homes

Every credential belongs somewhere (`home` on every item):

| Home | Who sees its metadata | Who may use it (through a machine, within reach) | Who manages it (rotate, re-bind, delete) |
| --- | --- | --- | --- |
| **workspace** | owners, admins and members; a guest only when a project shared with them references it | any member's machine; a guest's or a team's machine only through a project environment that references it | owners and admins |
| **project** | anyone with `use` on the project | the machines of anyone with `use` on the project | the project's managers |
| **private** | the owning member only | the owning member's own machines enrolled with the private-credentials tick, and never in a protected environment | the owning member (an owner or admin may purge it, without seeing it) |

The home is chosen when the credential is asked for: `mehen request --home private|project|workspace` (and `mehen connect`), private by default, and the human filling in the intake may change it within their rights (a project home needs `edit` on the project; a workspace home an owner or admin; a machine proposing a workspace home must belong to an owner or admin). The passkey that stores the credential signs the home with the rest. A credential can be **re-homed** with a passkey: workspace to project or project to workspace by an owner or admin (not while another project's variables reference it), private to a project by its owner with `edit` there; never shared to private.

**Out of reach means not found.** Someone else's private credential, a project credential of a project not shared with you, a workspace credential from a guest's or a team's machine: every route answers exactly as it does for a name that does not exist, so nothing can be learnt by naming. The one deliberate exception is creation: a name taken by a credential you cannot see, a pending intake or a reserved word is `conflict`, "name not available", with no further detail, and after twenty unavailable-name attempts in an hour from one account or machine, further attempts are rate limited.

No credential is ever shared across workspaces, and Mehen offers no page or command to read a stored value back. A value leaves the vault only in the relay's upstream request, a placeholder swap on the way to a bound host, a [lease](projects.md#leases) into a child process of a machine whose reach allows it, a [fill](#in-web-pages) sealed to `mehen` for one checked field of a web page, a [push](#other-services-secret-stores) the vault sends to a provider's secret store after a person approves it, or a backup export: an owner's `mehen backup export` or Settings download, encrypted inside the vault to an age key that owner registered with a passkey a day before, so it leaves only as ciphertext. An export never holds another member's private credential, a four-eyes credential or an OAuth connection's tokens.

## Fields

Each item has named fields, each public or secret, fixed by its kind. A [reference](#references) can name one: `mehen://github-app-work#private_key`. A kind's **primary** field is the one placeholders and leases deliver by default (for example `key` for `api-key`); kinds without one need the field named. Secret fields are stored encrypted, one data key per field, and are never returned to a machine except as a lease.

## Previous values

When a person's or a machine's rotation replaces a credential's value, or a reviewer chooses **Replace it with this value** for an adopted value ([Values already in the vault](../guides/adopt.md#values-already-in-the-vault)), the vault keeps the value it replaced for 30 days, sealed exactly as it was stored, and never shows it to anyone. The credential's page in the web app says when it was replaced, by whom and which fields, and **Restore it with passkey** puts it back. Restoring needs the same right as rotating the credential, and, where a protected environment uses it, the right to change that environment; a machine can never restore. A restore swaps the two values, so the one it replaces is kept for 30 days in turn and the restore can itself be undone. Only the latest previous value is kept: a second rotation within 30 days replaces it. Deleting the credential deletes its previous value too, and so does removing a member along with their private credentials. A restore is audited with field names only, and if a member who has since left saw the restored value, it is [flagged for review](audit.md#review-flags) at once, as offboarding does.

An OAuth connection keeps no previous value: its old tokens are gone once a refresh, a reconnect or anything else overwrites them, so there is nothing to restore. Reconnect it instead.

## Bindings

A binding is where an item may be used. An item without a binding cannot be used at all. One matcher, the same in the vault and in the local relay of `mehen run`, checks it.

```ts
type Binding = {
  hosts: string[]      // exact names, or "*.example.com" (any depth below, never the apex)
  schemes?: Scheme[]   // default ["https", "wss"]
  ports?: number[]     // default: the scheme's default port only
  paths?: string[]     // globs: "*" one segment, "**" any number including none
  methods?: string[]   // default: any
}
```

How a URL is checked, in order:

1. It is parsed with the WHATWG URL parser. A URL with a username or password is refused. Only `https`, `http`, `wss` and `ws` parse, plain `http` or `ws` match only when the binding lists them, and the vault relay carries `http` and `https` only.
2. The path is canonicalised (RFC 3986 section 6.2.2): escapes of unreserved characters are decoded and every other escape gets upper-case hex. The path is refused outright, never guessed at, when it holds an encoded slash, backslash or dot (`%2f`, `%5c`, `%2e`), a literal backslash, a control character, a malformed escape, an escaped `%` that starts another escape (`%2573`), a `.` or `..` segment, or an empty segment (`//`). A single trailing slash is fine. The canonical path is what the vault forwards.
3. The host, lower-cased and without a trailing dot, must match one pattern. Wildcards need at least two labels after `*.` (`*.com` is invalid). In the vault relay, IP literals, `localhost` names, `*.workers.dev` and the vault's own host are reachable only when bound exactly; a wildcard never opens them. This is not a complete private-network firewall: the vault does not resolve names.
4. The port must be listed, or be the scheme's default when none are listed.
5. Path and method must match when listed.

Matching fails closed both ways. Binding paths and `allow` rules match the canonical path exactly and case-sensitively, so an encoding trick can only narrow what is allowed. `deny` and `approve` rules match a fully decoded, lower-cased path, so `%73end` or `/me/SendMail` still hits a rule written for `send` or `sendMail`.

Only a human can change a binding, with a passkey that signs the change. When an agent asks for a new credential, a provider template's binding wins; without a template the agent proposes one (`mehen request --host`, and `--path`), shown to the human in red with the host spelled out. A rotation keeps the existing binding.

A credential with no template that is asked for or adopted with no host and no injection is lease-only, unless the relay puts its kind into requests: a secret such as `JWT_SECRET`, `SESSION_SECRET` or `DATABASE_URL` that only ever goes into a process. It is stored with the reserved binding `lease-only.mehen.invalid`, which the vault never sends anything to: the relay refuses every destination for it as a host mismatch, and a run never swaps a placeholder for it, so `mehen run` hands it over as a lease. It keeps its kind's ceiling, so a `generic`, `database-url`, `file`, `smtp-imap` or `cloud-access-key` is leased at once, while an `hmac-key` or `note` is stored only until a human sets its ceiling to lease, and an `ssh-key` or `google-service-account` is stored only. The pages say which ("No host: only delivered into a process with `mehen run`", or "No host: stored only") instead of a host. The reserved name is refused beside any other host and as a wildcard. An `api-key`, `bearer-token`, `basic-auth`, `custom-headers` or `oauth-connection`, and a credential proposed with an injection, still need real hosts. A human can give a lease-only credential hosts later by changing its binding with a passkey, which replaces the reserved host.

## Injections

An injection says how a secret goes into a request. It is fixed per item by a human or a template and is never chosen by the caller of the relay:

| `in` | Shape | Example |
| --- | --- | --- |
| `header` | `name`, `format` with `{field}` markers | `Authorization: Bearer {key}`, `x-api-key: {key}` |
| `query` | `name`, `field` | `?key=...` for APIs that insist |
| `basic` | `username`, `password` field names | `Authorization: Basic` built inside the vault |
| `headers` | `field` holding a JSON map | `custom-headers`: two headers at once |

The vault sets the header or parameter, replacing any copy the caller sent. A credential never goes into a reserved header: framing and hop-by-hop headers, `cookie` and `set-cookie`, `forwarded`, `x-forwarded-*`, `proxy-*`, `cf-*`, `mehen-*`, client-IP and URL-rewrite headers, and method overrides. An agent proposing an injection for an intake without a template may name only `header` (never a reserved one), `query` or `basic`. A secret, or a placeholder for one, goes only into the declared surface: a placeholder found anywhere else in a request is refused, never substituted.

## The exposure ladder

Each use of a credential sits on a rung. The vault uses the lowest rung that works.

| Rung | Mode | What the caller receives | Typical use | Built |
| --- | --- | --- | --- | --- |
| 0 | `relay` | The upstream response after vault processing, not the credential value. The upstream service receives the credential. | Every HTTP API. The default. | Yes |
| 1 | `sign` | A signature. | Webhook HMACs, JWT assertions, SSH certificates, AWS SigV4. | No |
| 2 | `mint` | A short-lived derived credential. | GitHub App installation tokens, Google access tokens from a service account. | No |
| 3 | `placeholder` | A per-run placeholder string, swapped for the real value only on the way to a bound host. | `mehen run -- bun dev` with SDKs that read keys from the environment. | Yes |
| 4 | `fill` | One field, sealed to `mehen`, which types it into a page a human allowed after checking the page's address. The agent gets back only what was typed where; the page receives the value. | Signing in to a dashboard in the agent's browser. | Yes, where switched on |
| 5 | `lease` | The value, into one child process only, with its output redacted. | `psql`, SMTP, older command-line tools. | Yes |
| 6 | `reveal` | The value, to a human in the browser after a passkey. Never to a machine. | Copying a password into a phone app. | No: no page shows a value |

An item's **ceiling** is the highest rung it may ever reach. Each kind has a default ceiling and a hard maximum (the [kinds table](#kinds)); raising a ceiling needs a passkey and can never pass the kind's maximum.

**Reveal is for humans only.** A machine never gets `reveal`, and a machine lease needs a ceiling of **exactly** `lease`. A ceiling raised to `reveal` so a human could view a password or a note never widens what a machine gets. A device's `modes` cannot include `reveal`. A machine fills only under a ceiling of `fill` or `lease`.

A device's `modes` scope must also include the rung. A relayed request beyond the item's ceiling is refused with `mode_refused`, one beyond the device's modes with `forbidden`; a lease that is not allowed is refused with `mode_refused`.

## In web pages

Where the vault has switched fill on for the workspace, a credential that `mehen fill` can type has an **In web pages** card on its page. Which fields it types depends on the kind:

| Kind | Fields | Where |
| --- | --- | --- |
| `password-login` | `username`, `password`, `totp` (a one-time code made from its secret) | Its sign-in pages |
| `totp` | `code` | Its sign-in pages |
| `api-key`, `bearer-token`, `generic` | its key, token or value | Only pages of other services a human listed |

For a password login or a one-time code secret, the card offers **How agents may use it**: **Type it into the sign-in page**, which sets the ceiling to `fill`, or **Not at all**, which keeps it at `relay`. Its **sign-in pages** are the origin of its sign-in address, each exact host of its binding, and any a person adds; only an added one can be removed. **May also be typed into** lists pages of other services, such as a dashboard that asks for an API key, which only a person adds; for an API key, a token or a generic secret the ceiling must also allow fill (`fill` or `lease`), and the card says so until it does. Each list holds at most 8 https origins, with no path and no IP address. Saving the card needs a passkey. [Type a credential into a web page](../guides/fill.md) is the whole procedure.

The username of a sign-in is typed without asking. Every other field asks a person first: one approval for a sign-in lets the agent type that credential's fields on that page, up to 6 fields in 10 minutes, and typing into another service's page asks every time. A machine also needs fill among its `modes`, which a person adds on the machine's page once it runs `mehen` 0.3.17 or later. Where fill is off, the card is not shown and the vault refuses fill everywhere.

Fill keeps the value out of the agent's transcript and off lookalike pages. It cannot keep it from the page itself: a script on that page, including one the agent runs in its own browser, can read the field before the form is sent. So fill is opt-in, credential by credential.

## Other services' secret stores

Where the vault has switched push on for the workspace, a credential page has an **Other services' secret stores** card with one tick: **May be put into other services' secret stores**. It is off for every credential until a person who may change the credential ticks it and saves with a passkey; anyone else reads whether it is on. With it on, an agent may ask the vault to put one of the credential's secret fields into a GitHub, Vercel or Cloudflare secret store with `mehen push`. Each push still waits for a person to approve it, and the vault sends the value to the provider itself, so the agent never holds it ([Put a credential into another service](../guides/push.md)).

Only a kind whose ceiling can reach `lease` is offered the tick, and never an OAuth client or connection: a connection refreshes itself, so a copy elsewhere goes stale. Turning it on or off changes the credential's settings, so a push still waiting for a decision goes stale, and a push approved but not yet sent is not sent once it is off. A push is not a rung of the ladder. The vault checks it as a relayed use of the credential by the machine, so the ceiling need not allow `lease`: the tick is what allows it.

Once a credential has been pushed, its page lists under **Pushed to** the latest push to each place, and after a rotation offers to put the new value into the places that still hold an older one, with one passkey for up to 25. Deleting the credential removes it from Mehen only; the delete confirmation lists the places whose copies stay.

## How careful

The **How careful** card on a credential's page sets its posture: ask for every change, let routine building through, or trust the managers' own machines. Only someone who manages the credential's home sets it, with a passkey, and only for a service with a reviewed list. [Policy](policy.md#how-careful-a-credential-is) says what each level lets through.

## References

A reference names an item and optionally a field, and is safe to commit, paste or log:

```
mehen://openai-personal
mehen://github-app-work#private_key
```

The grammar: `mehen://` then a slug, then optionally `#` and a field name of lower case letters, digits and underscores starting with a letter. Repos, configs, prompts and transcripts hold references and placeholders, never values.
