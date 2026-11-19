---
title: Intakes and connections
question: How does a credential get into the vault?
section: concepts
covers: both
order: 50
---

# Intakes and connections

A credential gets into the vault one of two ways: a human pastes it into an **intake** page, or signs in to a provider on a **connect** page. Either way the agent asks, gets a link, hands it to the human, and waits. It never sees the value.

## Intakes

An intake is a one-time, expiring form an agent asks for and a human fills in.

1. **The agent asks** with `mehen request` or `vault_request`: the kind, the slug to create, an optional provider template, a reason (required, up to 500 characters), the proposed [home](credentials.md#homes) (private by default), optional tags, an optional proposed binding and injection, and the session label. A template must be of the same kind. A new item needs a template or a proposed binding.
2. **The vault returns a link** (`/w/<slug>/i/<id>`) and `expiresAt`. An intake lasts 24 hours. Repeating the same open request from the same requester, with the same home and details, returns the same intake link without extending it. A different request under that name, from anyone, is the generic `conflict` ("name not available"), which names nothing; `--new` replaces your own open request. Every miss on a name counts against the requester's name budget.
3. **The human opens it**, signs in, and sees who asked (the machine's name; the session label in the details), why, the fields to fill in with hints from the template, where the secret will be allowed to go (a template's binding marked verified, an agent's proposal marked unverified and shown in red), **the tags it will carry**, the home, and a countdown. Tags are one limit on which machines may use the item, so the human sees them; a matching tag alone does not grant access. For a Google OAuth client the page walks through the provider's console step by step, with the vault's redirect URI in a copy box.
4. **The browser seals** each secret field to the vault and submits with a passkey that signs the slug, binding, public fields, sealed fields, tags and home, so the passkey signs exactly what is stored and who may use it.
5. **The agent waits**: `mehen wait <intake>` (or `vault_wait`) returns the item's public summary. Never the value.

If the slug already exists, is the same kind and is in the machine's reach, the intake is a **rotation**: the human replaces the secret fields only, and the item keeps its binding, provider, tags and home. Name the credential's current home when you ask; a different home is `conflict`. A slug the machine cannot see is a creation attempt and answers `conflict`, "name not available". Replacing the secret also clears a review flag. The vault stops using the old value once it is replaced; the old credential may still work at the provider until someone revokes it there.

**Submission is one transaction.** The request must still be open and unexpired, the home and the name must still be permitted and available, and the human must still hold the right to create or rotate there; then the credential is stored, the request completed and the audit event written together. A request cancelled, replaced with `--new`, expired or made invisible meanwhile cannot complete, and nothing is stored on a refusal.

Intake status is `open`, `completed`, `expired` or `cancelled`. A request replaced with `--new` reads `cancelled`, with no field naming its replacement: `mehen pending` lists the newer link.

## Connections

A connection is an item of kind `oauth-connection`, linked to an `oauth-client` item made from the provider's client template. It holds the access and refresh tokens, refresh state and the **verified account**. The providers are `google-gmail`, `google-calendar`, `google-drive` (client template `google-oauth-client`), `github-oauth` (`github-oauth-client`) and `microsoft-graph` (`microsoft-oauth-client`); [Providers and templates](../reference/providers.md#oauth-providers) lists their scopes. Each provider fixes its authorise, token and identity URLs, allowed scopes, the API binding and the sensitive endpoints; nothing in a request can change them.

- A connection's identity is the provider's stable subject (Google's subject id, Microsoft's object and tenant ids, GitHub's user id), never the email.
- Two Gmail accounts are two connections with two slugs, and every request names one.

**The connect flow.** The agent runs `mehen connect` (or `vault_connect`) with the provider, the slug to create or reconnect, optional scopes within the provider's allowed set, an optional expected account and a reason. The OAuth client item is named with `--client`, or picked when exactly one made from the provider's client template exists; with none, `mehen connect` fails locally with `client_missing` and the exact `mehen request oauth-client` command. The vault returns a link (`/w/<slug>/c/<id>`) and `expiresAt`.

The human signs in to the vault with a passkey first and confirms the connection with it, signing the provider, slug, home, tags, expected account and scopes, so nobody else can finish the connection with their own account. The vault then sends them to the provider with a single-use state value (stored hashed, bound to the member) and PKCE. The callback exchanges the code inside the vault, at the template's token URL only, then reads the provider's identity and records the verified account.

**An unexpected account is refused.** If the provider says the human signed in as an account other than the expected one, the callback refuses with `forbidden` and nothing is overwritten. In the current release that refusal is not recorded on the connect request, so `mehen wait` keeps waiting until it times out or the link expires. Ask the human what the callback page said before starting a fresh connection.

Connect links are single use, expire after 15 minutes and complete only in a browser signed in as the member who started them. Reconnect links are pinned to the subject the connection already holds. As for intakes, the same machine asking for the same connect again gets the same link; `--new` replaces it; and the final store re-checks the flow, the session, the request and its home inside one transaction after the token exchange, so a cancelled or replaced link cannot finish. A provider may already have recorded the human's consent when a connection fails or expires in Mehen; they can withdraw it at the provider.

Connect status is `open`, `completed`, `failed` or `expired`, each with `expiresAt`. A completed connection's status carries the public item description, including its account; do not rely on separate top-level account or scope fields in the wait result.

**Chained connect.** `mehen connect --request-client` with no client item makes the vault create the client intake and the connect together: the intake page goes straight on to the connect page once the client is saved. The connect lives as long as its intake and then 15 minutes from the client being saved; it cannot start before the intake completes, and starts only with the client that intake saved. A chained connect never serves as a reconnect link.

## From a platform's pages

In a [managed workspace](platforms.md) there is no Mehen page: the platform opens the intake, its own page draws the fields, the user's browser seals each value to the vault, and the platform submits the sealed boxes, which open only for that intake and field, once. A credential's destination comes from the catalogue template, or from the one host the platform named, and never changes afterwards. Connections use the user's own OAuth app, kept in their workspace like any key, and the platform's own callback. Such an app may carry its own provider definition instead of naming a catalogue provider, so a platform's user can connect any OAuth 2 service; a connection made with one holds every request for a decision unless the platform let reads through. Mehen's own pages do not offer custom providers yet: [Build on Mehen](../guides/build-on-mehen.md#connecting-an-account) walks through both.

## Refresh

Refresh runs inside the workspace's own store, one at a time per connection. It stores a write-ahead attempt before it calls the provider and retries network errors, throttling and the provider's own failures; new tokens are committed before any caller sees them. An unresolved attempt is held for up to 120 seconds and then sent again; a token the provider replaces on every use (GitHub's) that the lost attempt had spent is refused by the provider, and only that refusal makes it need reconnecting. A connection uses the item statuses (`active`, `refresh_retrying`, `needs_reauth`); the refresh bookkeeping is not a public state. A dead grant marks the item `needs_reauth`, and that use and every one after returns `needs_reauth` with a `next` that says why. For a machine that may rotate the connection, sending a single request (not one of a bundle being planned) outside a managed workspace, `next` is a reconnect link pinned to the account, to wait on, unless another open connect already holds the name; otherwise it is the connection's page. When the provider rejected the OAuth client, `next` is the client's page instead ([When a refresh fails](../guides/oauth.md#when-a-refresh-fails)).
