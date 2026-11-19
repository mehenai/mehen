---
title: Connect Gmail, GitHub or Microsoft
question: How do OAuth connections work from the agent's side?
section: guides
covers: both
order: 60
---

# Connect Gmail, GitHub or Microsoft

An OAuth connection is a credential the human signs in to, rather than pastes. The agent asks for it with `mehen connect`, the human signs in from the link, and the tokens stay in the vault.

```sh
mehen connect google-gmail --name gmail-personal --scopes gmail.modify --expect you@example.com --reason "read and draft replies in the inbox"
```

```
Human needed: connect an account
  open:    https://app.mehen.dev/w/acme/c/con_9Kp
  what:    Connect gmail-personal to Gmail as you@example.com so the agent can read and draft replies in the inbox
  check:   the page shows account you@example.com; sign in as that account
  expires: in 15 min (17:05)
  then:    mehen wait con_9Kp   (or add --wait to this command)
```

MCP: `vault_connect`, then `vault_wait`.

## Providers

`<provider>` is one of `google-gmail`, `google-calendar`, `google-drive`, `github-oauth` and `microsoft-graph`. [Providers and templates](../reference/providers.md#oauth-providers) lists each one's client template, default scope and the scopes you may ask for. `--scopes` takes a comma-separated list from the allowed set; Google scopes can be given by their short names.

An agent working for a [platform](../concepts/platforms.md) never runs `mehen connect`: in a managed workspace a machine's connect is refused with `forbidden`, and the platform connects accounts from its own pages, with each user's own OAuth app, which may also be for a provider outside this list ([Build on Mehen](build-on-mehen.md#connecting-an-account)). That is not offered on Mehen's own pages yet.

## The OAuth client

A connection needs an `oauth-client` item made from the provider's client template. Without `--client`, `mehen connect` lists them: exactly one is used (`mehen: using OAuth client google-oauth-client` on stderr); several is a usage error (exit 2) naming them, with `choices` in `--json`; none is `client_missing` (exit 4):

```
mehen: No Google OAuth client is in the vault yet; a Gmail connection needs one (template google-oauth-client).
next: Ask the human for a Google OAuth client first, then run this command again; or repeat it with --request-client to ask for both at once.
  run:  mehen request oauth-client --name google-oauth-client --provider google-oauth-client --reason 'connect Gmail as you@example.com'
  the human will need: a Google OAuth client (web application) with redirect URI https://app.mehen.dev/oauth/callback
  docs: https://console.cloud.google.com/apis/credentials
```

`next.command` runs as printed; `--json` adds `request` (exactly the `mehen request` or `vault_request` arguments) and `setup` (`{ redirectUri, docsUrl }`).

**`--request-client`** does the chain in one process: the vault creates the client intake and the connection together; `mehen connect` prints the client's ask (its `what:` names the redirect URI), waits for it, prints the connection's ask, and with `--wait` waits for that too. `--json` prints one object per step with `step: "client"` or `step: "connect"`. When a client already exists the same command is an ordinary connect that picks it, so it is safe to always pass. `--client-tag` sets the client item's tags. Over MCP, `requestClient: true` returns the client intake's ask; call `vault_wait` for it, then `vault_connect` again with the same arguments.

## Relay, then wait

Write the human the block: the check is the account to sign in as. They sign in to the vault with a passkey first, confirm the connection with it, then sign in to the provider. The link is single use, lasts 15 minutes and completes only in a browser signed in as the member who started it. The same open connect is returned again for the same request; `--new` replaces it.

`mehen wait con_...` reports the connection completed, with the item's public description including its account: `Connected gmail-personal as you@example.com (Gmail; scopes gmail.modify).` with a `then:` line.

**If the human signs in as another account.** The vault refuses the provider's answer when it is not the account in `--expect` (or, for a reconnect, the account the connection already holds) and overwrites nothing; the callback page says so. In this release that refusal is not recorded on the connect link, so `mehen wait` keeps waiting until it times out or the link expires. Ask the human what the callback page said, then start a fresh connection with `--new`, telling them which account to use.

If `--name` is an existing connection for the same provider, this is a reconnect, pinned to the account it already holds. A connection that stops working answers `needs_reauth` with a reconnect link: relay it and wait again ([Errors and exit codes](../reference/errors.md#needs_reauth)).

## Using it

```sh
mehen fetch gmail-personal GET https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10
```

Reads go through; most writes and every send wait for an approval ([When a request needs approval](approvals.md)). Name the slug every time: two Gmail accounts are two connections with two slugs, and the vault never picks one for you. Say which account you will act as before you act.
