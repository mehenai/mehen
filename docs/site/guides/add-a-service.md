---
title: Add a service
question: How do I add a template for a service Mehen does not know yet, or use that service without one?
section: guides
order: 125
covers: both
---

# Add a service

Mehen knows a service through its **template**: a short, reviewed description of where that service's credential may go, how it goes into a request, and which of its routes need a person. `mehen templates` lists the ones there are ([Providers](../reference/providers.md)). An agent can name a template when it asks for a credential; it can never change one.

There are two ways to use a service that has no template yet. Write a template and send it as a pull request, so everyone gets it. Or add your own credential for it in the vault today, with a destination you check yourself, and no pull request at all ([below](#use-a-service-without-a-template)).

## What a template fixes

- **Where the credential may go.** The exact hosts of the service's API, over https only, and, where the API lives under one prefix such as `/v1/`, only that prefix. A request anywhere else is refused before the credential is touched.
- **How it goes in.** The header the service reads the key from and its format, such as `Authorization: Bearer {key}` or `X-Api-Key: {key}`.
- **What needs a person.** The policy every credential made from the template starts with: which requests go through, which wait for an approval and which are refused ([Policy](../concepts/policy.md)).
- **How far the credential can travel.** Its ceiling, the most a person can let a machine do with it ([Exposure modes](../concepts/credentials.md#the-exposure-ladder)).
- **What the person adding the key sees.** The service's name, a link to the page where the key is made, and the prefix a real key starts with, so a pasted value that does not fit is flagged.

A template is data, never code: nothing in it runs.

## What a reviewer checks

Every template is reviewed against the same rules before it is merged. Check yours against them first.

1. **It comes from the service's own documentation.** Hosts, headers, prefixes and routes are read from the provider's documentation, not copied from another product's catalogue.
2. **The narrowest destination that works.** Exact host names, no wildcards unless the service really answers on many names, and a path prefix where the API has one. Never plain http, and never a host you cannot vouch for.
3. **Hosts that do not move.** If the host depends on the account (a subdomain per customer, an instance URL), it must come from a checked input that matches a pinned pattern. A response from the service never chooses where the credential goes next.
4. **The header the service documents.** A query parameter only when the service accepts nothing else.
5. **Reads pass, everything else waits.** `GET` and `HEAD` go through, except a read that hands back another secret (a database password, a decrypted variable), which needs an approval. Every other method needs an approval by default. A few narrow everyday writes may be allowed, each with a note saying why that is safe enough.
6. **The worst routes are refused or held.** Anything that sends mail or data elsewhere for good, gives someone else access, mints tokens, creates keys, webhooks or app registrations, or moves money needs an approval or is refused. A request an approval card could not show honestly (a batch, or sending something stored by id that could change after the approval) is refused, with a note naming the alternative.
7. **The lowest ceiling that works.** `placeholder` for keys an SDK reads from the environment, `relay` for any other HTTP API. A template never lets a machine read the value by default. Where the service documents the environment variable its SDK or CLI reads the key from, the template names it as `defaultEnvVar`, so `mehen templates --json` shows it; never an invented one.
8. **Public prefixes only.** A prefix is the documented start every key shares, such as `sk_live_`, never characters that would narrow a guess at the rest.
9. **No new kinds.** A template uses one of the existing credential kinds. A new kind is a separate review.

## Start a template

In a checkout of the Mehen repository, from any folder inside it:

```sh
mehen templates new acme --host api.acme.com --category productivity --docs https://acme.com/settings/api-keys
```

`<id>` is lower case letters, digits and hyphens, starting with a letter, 2 to 41 characters. `--host` may be given more than once, one per host the API answers on. The other flags:

| Flag | Default | What it sets |
| --- | --- | --- |
| `--path <prefix>` | every path | Where on the host the credential may go, such as `/v1/**`; repeatable |
| `--header <name>` | `Authorization` | The header the key goes in |
| `--format <format>` | `Bearer {key}` | The header's value, with `{key}` where the key goes, such as `{key}` or `token {key}` |
| `--docs <https url>` | none | The page where a person makes the key |
| `--name <display name>` | the id and `API key` | What the intake page calls it |
| `--category <category>` | none, required | Where `mehen templates` and Connect a service list it: `mail`, `ai`, `code`, `productivity`, `observability`, `infrastructure`, `customers` or `search` |
| `--prefix <prefix>` | none | The public prefix every key starts with; repeatable |

For a service that takes its key in `X-Api-Key` and lives under `/v2/`:

```sh
mehen templates new acme --host api.acme.com --path "/v2/**" --header X-Api-Key --format "{key}" --prefix acme_ --category ai
```

The scaffold writes three things and registers the template, then prints each file it wrote and the test command to run:

- the template, with the safe defaults: an API key, the exact hosts, the header and format you gave, reads allowed, every other method held for approval, and the `placeholder` ceiling;
- a test for it, which proves the destination accepts the real host and refuses a look-alike host, plain http and, with `--path`, another path; that a read passes; and that a write nobody listed needs an approval;
- its entry in the catalogue, so `mehen templates` lists it, and a new `--prefix` in the list of prefixes placeholders keep.

It refuses an id that exists or is reserved, a host that is not a plain lower-case DNS name (no scheme, port, path, wildcard or IP address), a docs link that is not https, a header the vault reserves for itself, and a format without exactly one `{key}`. It writes nothing until every check has passed, and outside a checkout of the repository it refuses and says so.

## Finish it

What the scaffold writes is a safe start, not a finished template. With the service's documentation open:

- add an allow rule, with a note, for each everyday write an agent should make without asking, such as a model call or a search;
- add deny and approve rules for the routes in rule 6;
- add a cheap read that proves a key works, if the service has one;
- add setup steps if making the key is not obvious.

## Test it

Run the command the scaffold printed at the end. It runs the checks every template must pass (a category, https docs, exact hosts, a default of approve, a note on every rule, every rule reachable, prefixes that fit) and your template's own test. Add a case to that test for each rule you added: an allowed write is allowed, and each held or refused route is held or refused, in odd case and with escapes too. Then open a pull request with the files the scaffold wrote and changed.

## Use a service without a template

You do not need a template, or a pull request, to keep a key for a service in the vault. Ask for it with the destination spelled out:

```sh
mehen request api-key --name acme-ci --host api.acme.com --path "/v2/**" --header X-Api-Key --format "{key}" --reason "let the nightly job read Acme's reports"
```

Without `--header` and `--format` an API key goes in `Authorization` as `Bearer {key}`. The intake page shows this destination in red, marked unverified, because no reviewed template vouches for it. Check the host and the header against the service's own documentation before you paste the key and confirm with your passkey; you may narrow the destination there ([Ask a human for a credential](request-a-credential.md)).

A credential without a template is stricter than one with: every request waits for a person, reads included, unless you tick the one box that lets reads through ([Credentials without a template](../concepts/policy.md#credentials-without-a-template)). You can widen its policy later from the credential's page with a passkey, or let a routine request through with a [standing rule](standing-rules.md).
