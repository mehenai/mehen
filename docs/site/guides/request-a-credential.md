---
title: Ask a human for a credential
question: How does an agent get a new key into the vault without seeing it?
section: guides
covers: both
order: 50
---

# Ask a human for a credential

When the credential does not exist, ask for it through the vault. Never ask the human to paste a secret into chat: not "just this once", not "redacted", not "the last four characters are enough". A secret in chat is in your context, the transcript, the provider's logs and possibly a training set. If a human pastes one anyway, do not use it, repeat it, write it to a file or put it in a command; tell them it should be rotated, and send an intake link so the replacement goes into the vault.

## Ask

```sh
mehen request api-key --name openai-personal --provider openai --reason "run the nightly evals against the OpenAI API"
```

That asks for a **private** credential, the default: only the human who fills it in can use it, through their own machines enrolled with the private-credentials tick (on by default for a member's own machine, off for a guest's), and it can never back a shared project variable. For a credential a project will share, say so: `--home project --project prj_3kQ9vXyZ7`.

```
Human needed: add a credential
  open:    https://app.mehen.dev/w/acme/i/int_3kQ9vXyZ7
  what:    Add openai-personal (OpenAI API key, goes to api.openai.com) so the agent can run the nightly evals against the OpenAI API
  check:   the page says it was asked by my-laptop, session pi-4f2a
  expires: in 24 h (tomorrow 17:20)
  then:    mehen wait int_3kQ9vXyZ7   (or add --wait to this command)
```

MCP: `vault_request`.

- `<kind>` is one of the closed list: `api-key`, `bearer-token`, `basic-auth`, `custom-headers`, `oauth-client`, `oauth-connection`, `google-service-account`, `github-app`, `hmac-key`, `ssh-key`, `password-login`, `totp`, `database-url`, `smtp-imap`, `cloud-access-key`, `file`, `note`, `generic`.
- `--name` is the slug of the item to create: lower case letters, digits and single dashes, 2 to 64 characters, starting with a letter and not ending with a dash.
- `--reason` is required (up to 500 characters) and the human reads it. Say plainly what you will do with the credential.
- `--provider` names a template, and the template's kind must match `<kind>`. A template fixes where the key may go, how it is sent and which endpoints need approval, and the human sees its destination marked as verified. [Providers and templates](../reference/providers.md) lists every one; `mehen templates` prints the same list.
- `--home` proposes who the credential belongs to: `private` (the default), `project` (with `--project <prj_id>`, or the checkout's `mehen.toml`) or `workspace`. The human may change it within their rights. A machine may only propose a home within its own reach: a private home needs the private-credentials tick, a workspace home an owner's or admin's machine.
- `--tag` (repeatable) asks for tags on the new item. Tags narrow which machines may use it, so the human sees them and their passkey signs them. Ask only for tags you were told to use.

## Without a template

A new item without a template that the vault sends to a service needs a proposed binding: `--host` (repeatable) and optionally `--path` (MCP `hosts` and `paths`). Without `--host` and `--header`, a kind the relay never puts into a request (such as `generic`, `database-url` or `file`) is lease-only: it has no host, the vault never sends it, and only `mehen run` delivers it into a process, for secrets such as `JWT_SECRET` or `DATABASE_URL` ([lease-only credentials](../concepts/credentials.md#bindings)). A kind the relay injects (`api-key`, `bearer-token`, `basic-auth`, `custom-headers`, `oauth-connection`) without `--host` is refused: "An api-key credential is sent to a service: name the hosts it may go to with --host." For a kind the relay injects, it is sent the kind's usual way (`Bearer {key}` in `Authorization` for an `api-key`) unless you propose another with `--header <name> --format <format>`, for example `--header X-Api-Key --format "{key}"` (MCP `injection`, which may also be `{ "in": "query", "name": "api_key", "field": "key" }`). The human sees both in red, marked unverified, and may narrow the binding. The item is stored with every request held for approval, reads too unless the human allows them ([Policy](../concepts/policy.md#credentials-without-a-template)). A proposed injection is refused with a template, for a rotation, for a kind the relay never sends, and when it names a field the kind does not have or a reserved header.

## Rotate

If `--name` is an item that already exists, is the same kind and is in your reach, the intake **rotates** it: the human replaces its secret fields only, and its binding, provider, tags and home stay. Leave `--provider` out or give the same one, and name the credential's current home (`--home project --project <prj_id>`, `--home workspace`, or the default for a private one): a different home is `conflict`. A slug you cannot see is `not_found` when you name it to use it, and a creation under such a name is the generic `conflict` ("name not available").

For an `oauth-client` intake the `what:` line names the redirect URI the human must register at the provider, and the intake page walks them through the provider's console.

## Relay it, then wait

With `--json` the result is `{ intake, url, expiresAt, kind, name, provider, ask, next }`. Then:

1. Write the human the block from `ask`. For example: "I need an OpenAI API key to run the evals. Please add it here: <link>. It goes straight into the vault; I will never see it."
2. Wait for it:

   ```sh
   mehen wait int_3kQ9vXyZ7
   ```

   MCP: `vault_wait`. It returns the new item's public summary, never the value: `Added openai-personal (OpenAI API key, goes to api.openai.com).` then a `then:` line with a command to use it. Or add `--wait` to the request and it waits in the same process.

An intake is single use and lasts 24 hours. Repeating the same open request from the same machine, with the same home and details, returns the same intake link without extending it (`mehen: already asked 3 min ago; same link` on stderr). A different request under that name, from this machine or anyone else, is `conflict` ("name not available"), which does not say whose request is open; `--new` replaces your own open request, and `mehen pending` lists the newer link. If a link expires, `mehen wait` fails with `expired` (exit 1) and `next.command` is the exact `mehen request ...` that was run. If the human cancels it, `mehen wait` fails with `cancelled` (exit 1): ask them before requesting it again.

## Waiting

`mehen wait <id>` long-polls until the human acts. The first poll answers at once, so an expired or settled ask shows without delay. On a terminal it prints the ask first (when this machine asked), then one line redrawn in place with the time left; off a terminal it prints nothing while waiting. Ctrl-C stops waiting, and the link stays valid.

`--timeout` takes `0` (check once), a number of seconds, or `30s`, `10m`, `2h`, up to 24 hours; the default is 10 minutes. A timeout is `timeout` (exit 4) with the ask handed back so you can relay it again. `--json --events` prints one object per line: `{ event: "waiting", id, kind, ask?, remainingSeconds }` at the start and whenever the remaining time crosses a minute, then `{ event: "settled", ... }` or `{ event: "error", ... }`; an enrolment wait also emits `renewed` when it renews the link in place.
