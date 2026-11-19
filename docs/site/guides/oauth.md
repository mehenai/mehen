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

`<provider>` is one of `google-gmail`, `google-calendar`, `google-drive`, `github-oauth` and `microsoft-graph`. [Providers and templates](../reference/providers.md#oauth-providers) lists each one's client template, default scope and the scopes you may ask for. `--scopes` takes a comma-separated list from the allowed set (the provider's default when left out; on a reconnect, added to the current scopes); Google scopes can be given by their short names.

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

If `--name` is an existing connection for the same provider, this is a reconnect, pinned to the account it already holds. A reconnect keeps every scope the connection has: `--scopes` (MCP `scopes`) adds to them, and nothing drops one. A connection that stops working answers `needs_reauth` with a reconnect link: relay it and wait again ([Errors and exit codes](../reference/errors.md#needs_reauth)).

## When a refresh fails

The vault renews a connection's sign-in before it expires. What happens when the provider does not renew it depends on why:

- **A network error, a timeout, throttling (429) or the provider's own failure (5xx)**, or any OAuth error that does not say the sign-in or the client is gone: the vault waits and tries again: 30 seconds after the first failure, doubling each time up to an hour, a little earlier or later at random so connections do not retry together, or longer if the provider's `Retry-After` (in seconds or as a date) asks for longer, up to 24 hours: a longer one waits 24 hours and then tries again, so its failures still count towards the four days below. The token it holds is used until it expires; after that the connection answers `refresh_retrying` with `retryAfter`. However long the failures last, on their own they never need a reconnect, on any provider: once refreshing has failed on four different days, the connection's page and a Review row in Needs you say since when and what the last error was (unless it is already flagged for another reason), whoever may reconnect it is told once, and the vault keeps trying. A refresh that works clears it. Reconnecting is offered there but not needed.
- **The provider ended the sign-in** (`invalid_grant` and its kin; for Microsoft also interaction_required, consent_required and login_required, which say a person must sign in again): the connection needs reconnecting. The message says why when the vault can tell: a Google app in Testing ends sign-ins after 7 days (named only when the sign-in is about that old and never renewed past it), a sign-in unused for too long expires, a password change or a removed grant revokes it.
- **The provider rejected the OAuth client** (`invalid_client`, `unauthorized_client`): its secret is wrong, expired or deleted. Every connection that uses the client is paused and sends nothing more. The client itself shows `needs_reauth`, with the reason on its page, until its secret is replaced. `needs_reauth` then carries a `next` that is not a reconnect: it points at the client's page for a machine that may see the client, and at the connection's page, without naming the client, for one that may not. A human replaces the client's secret first, then reconnects the connections. Reconnecting before that would fail the same way. The pause is kept on the client's secret, so it holds even if the connection that found it is deleted or the client's settings are edited, and only replacing or restoring the client's secret, or removing the client, lifts it. A connect that chose that client can neither start nor finish meanwhile, so the client's secret is never sent: Needs you shows the client's row in its place (to a guest too, for their own client), and the connect's page says the client was rejected and keeps Continue off. Such a link is made for the client as it was, so replacing or restoring the client's secret, or removing the client, ends it: its status reads failed with the reason, the agent's wait ends, and a new `mehen connect` (no `--new` needed) makes a new link, or the person reconnects from the credential's page. Asking for a connect through a client while it is rejected is refused at once with the reason. A reconnect through another, working client is not affected.

A GitHub refresh token is replaced on every use. If a refresh's answer is lost (the connection dropped after the request went out), the vault cannot know whether GitHub replaced the token, so it waits until that request can no longer be answered (two minutes) and then sends the same refresh again. If GitHub had replaced the token, it refuses the old one (`bad_refresh_token`) and the connection needs reconnecting. GitHub gives the same answer for a sign-in that was revoked or expired, so the reason says GitHub no longer accepts the sign-in, most likely because the interrupted refresh had already replaced the token, unless the sign-in had gone unused for as long as GitHub keeps one, when it says that instead. If GitHub had not replaced the token, the refresh works. A lost answer alone never needs a reconnect. Meanwhile the vault keeps serving the token it holds until it expires, and an unexpired token does not prove GitHub has not already replaced it: a request in that time may get a 401 from GitHub. That 401 changes nothing in the vault. The token was within a minute of its end when the refresh started, and the vault's own retry, already scheduled, sends the refresh again, so such 401s last about two minutes at most. A connection made with a custom provider is treated the same way. A Google or Microsoft refresh token is not replaced that way, so the same refresh is simply tried again.

Whoever may reconnect a connection (or replace the client) sees it in [Needs you](../concepts/needs-you.md#needs-you), with the reason, and is told once: once per sign-in for a connection (a reconnect is a new one), once per client secret for a client.

## Using it

```sh
mehen fetch gmail-personal GET https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10
```

`mehen show gmail-personal` (MCP `vault_show`) says what the connection may do: its `scopes:` and when its `token:` expires, and `--json` has them as `connection: { scopes, expiresAt, refreshing, client, reconnect }`, where `client` is the OAuth client it signs in through, named only when you may see that client, and `reconnect` is `platform` in a managed workspace, whose platform reconnects it. Read the scopes before you ask for a reconnect with more.

Reads go through; most writes and every send wait for an approval ([When a request needs approval](approvals.md)). Name the slug every time: two Gmail accounts are two connections with two slugs, and the vault never picks one for you. Say which account you will act as before you act.
