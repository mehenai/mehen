---
title: Find a credential and call an API
question: How does an agent list, check and use a credential?
section: guides
covers: both
order: 70
---

# Find a credential and call an API

## Find what exists

```sh
mehen ls                         # ITEM, KIND, PROVIDER, ACCOUNT, STATUS, REVIEW, HOSTS
mehen ls --kind api-key --json   # { "items": [ ... ] }
mehen show openai-personal       # public fields, binding, policy, and for each secret field: set, length, prefix, fingerprint
mehen templates                  # every template and OAuth provider; mehen templates <id> for one in full
```

MCP: `vault_list`, `vault_show`, `vault_templates`.

`mehen ls` lists the items this machine may use; an item outside its scope does not appear, and naming it gets `not_found`. When results span more than one workspace, a workspace column appears; a slug is unique only within its workspace, so pass `--workspace` on the commands that follow.

`mehen show` prints every line it has:

```
gmail-personal  (mehen://gmail-personal)
  kind:      oauth-connection, provider google-gmail (Gmail)
  account:   you@example.com (verified)
  status:    active, ceiling relay, version 1
  goes to:   gmail.googleapis.com /gmail/v1/**, /upload/gmail/v1/**
  policy:    approve by default (14 rules; mehen show gmail-personal --json for all of them)
    without a human:  GET/HEAD anywhere; POST on /gmail/v1/users/*/drafts, ...; (1 more)
    needs approval:   POST/PUT on /gmail/v1/users/*/messages/send, ...; (2 more); anything else
    refused:          POST/PUT/PATCH/DELETE on /gmail/v1/users/*/settings/forwardingAddresses, ...; (4 more)
  secret access_token:  set, 253 chars, fingerprint jYYZ_C4NljMe
  last used: 2026-10-24 17:06 (3 min ago)
  try:       mehen check gmail-personal GET https://gmail.googleapis.com/gmail/v1
```

Read `account` and whether it is verified before acting, and say which account you will act as. Name the slug every time: the vault never picks an item for you. If two items could serve (two Gmail connections), ask the human which one they mean. Never try to read a value to "check" it: `mehen show` tells you whether a field is set, its length, a well-known prefix and a fingerprint.

An item a human should look at (for example because an upstream echoed its value back) carries `review: { reason, since }` in `--json`, and `mehen ls` and `mehen show` print `needs review: <reason>`. Tell the human before using it.

## Check before you send

```sh
mehen check gmail-personal POST https://gmail.googleapis.com/gmail/v1/users/me/messages/send
# needs approval: "sends email as you" (approve rule; policy default approve)
#   The vault will answer approval_required with a link when you send it. Keep the body small and uncompressed.
#   Advisory: device scope, a frozen vault or a protected item can still stop it; the vault decides.
# [exit 3]
```

MCP: `vault_check`.

`mehen check` fetches the item's public metadata from the vault and evaluates its binding and policy locally. It sends no request upstream and creates no approval. Its answer is advisory, not permission to send: live scope, protection, policy floors and grants can change the result. The verdict is `allowed` (exit 0), `needs approval` (exit 3), `refused` (exit 5) or `outside the binding` (exit 5), so a script can branch as it would on the real call. Rules that read the body (GraphQL) need `-d`; without it they are taken to match and the output says so.

## Call an API

```sh
mehen fetch openai-personal POST https://api.openai.com/v1/responses -H 'Content-Type: application/json' -d @body.json
```

MCP: `vault_fetch`.

The vault checks the URL against the item's binding and policy, puts the credential where the item says, makes the call from its own servers and returns the response. The vault scrubs credential echoes in raw, URL-encoded, JSON-escaped and supported base64 forms. It cannot catch arbitrary transformations, and values shorter than six characters are not redacted. A detected echo flags the credential for review. A scrubbed echo reads `[redacted:<slug>]`.

- `-d @file` sends a file, `-d -` reads stdin, and `-d text` sends the text. `-H` is repeatable.
- Without a `User-Agent` from `-H`, the vault sends `User-Agent: mehen-relay` upstream, because some APIs (GitHub's) refuse a request without one.
- The response body goes to stdout. It is the body received from the vault: the vault may already have decompressed or scrubbed it and removed response headers, so it is not a byte-for-byte copy of the original upstream response. The status and `Mehen-Item` go to stderr, for example `mehen: 200  Mehen-Item: openai-personal`.
- Any upstream status exits 0. Pass `--fail` to exit 1 on a 4xx or 5xx (`upstream_status`).
- With `--json`: `{ status, statusText, item, headers, body }`, or `bodyBase64` instead of `body` when the body is not UTF-8.
- `-o <file>` (`--output`) writes the body to a file and says on stderr how many bytes it wrote. Use it for large or binary responses.
- `--select <path>` prints one part of a JSON response as JSON: keys and array indexes such as `data.0.id`, `.data[0].id` or `items[2]["display name"]`, and `.` for the whole body. A path that is not there prints `null` and says so on stderr.
- `-i` (`--include`) prints the status and every response header on stderr; stdout stays the body.
- `--max-time <duration>` (`30s`, `2m`, up to `10m`) stops waiting for the answer: `network` (exit 7), and the request may still have reached the upstream, so check before sending it again.
- `--project <prj_id> --env <name>` names the project environment the credential is used for: required for a protected credential, and for a workspace credential a team's or a guest's machine reaches through a shared project ([Projects, environments and runs](../concepts/projects.md#protected-credentials)).

Over MCP, `vault_fetch` returns the body as text cut at 256 KiB; use `select` for one field of a large JSON answer (from the whole response, within the vault's 32 MiB response limit), or `mehen fetch -o <file>` in a shell for the whole body.

## Reading the result

- A response from the upstream carries `Mehen-Upstream: 1` and `Mehen-Item: <slug> (<account>)`, which tells you, and the transcript, which account acted.
- A refusal by the vault carries `Mehen-Error: 1` and the error object ([Errors and exit codes](../reference/errors.md)). An upstream 403 and a vault refusal are never the same thing.
- When the upstream rejects the credential itself, a 401 or a 403 whose `WWW-Authenticate` header says the scope is insufficient, `mehen fetch` prints a `mehen:` line on stderr and `--json` (and `vault_fetch`) carries a `hint`. For a key it names the rotation, `mehen request <kind> --name <slug> --provider <provider> --reason '<why>' --home <home>`; for a connection, the reconnect, `mehen connect <provider> --client <client> --name <slug>` (`--client` names the connection's OAuth client; when you may not see that client, the hint names no command and says to reconnect it from its page in the vault, because without `--client` mehen connect would use the provider's default client), with `--scopes` set to any scope the upstream named and the same `--home`. A connection only its platform reconnects, in a managed workspace or made with a custom provider, gets a hint that says so and names no command. The home is the credential's own (`private`, `workspace`, or `project` with `--project <prj_id>`), because a rotation or reconnect must keep it. Hand that to the human; do not retry in a loop. Other statuses carry no hint, because a 403 alone may be the service's own rule about the request.

You do not set auth headers yourself. Never put a key, token or placeholder in the URL, body or headers: the vault puts the credential where the item's injection says, and replaces any copy of that header you sent.

A request refused before forwarding is not sent upstream. A timeout, or a failure while the vault processes the response, may come after the request took effect; check before retrying. Never guess around a refusal: do not retry it with a different host, a different item, a body-encoded token, an encoded path or a rephrased URL.

`mehen fetch --run <run> <METHOD> <URL>` (or `vault_fetch` with `run`) sends a request that carries a `mehen run`'s placeholders instead of naming an item. The local relay of `mehen run` does this for you; you rarely need it.
