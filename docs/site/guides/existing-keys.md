---
title: Move existing keys in
question: I already have keys and .env files; how do I move them into Mehen?
section: guides
covers: both
order: 95
---

# Move existing keys in

Many keys in `.env` files across your repos and services? [Bring a machine's credentials into Mehen](adopt.md) brings them all in at once, with one passkey for the whole batch. This page is for one key at a time.

Each key goes in once, through a vault page where it is sealed in your browser. Nobody pastes it into chat or a terminal.

## Ask once, not once per machine

A credential lives in the workspace, not on a machine. Every machine you enrol whose scope covers it can use it, so put each key in once, from whichever machine or page is to hand.

Decide first who it belongs to. **Only me** (private, the default for an agent's ask) is for your own keys. **A project** is for a key the project's team shares, and needs `edit` on the project; in a repo with a `mehen.toml`, an agent asks with `--home project`. **Whole workspace** is for owners and admins.

## Two ways in

- **Ask your agent.** It runs `mehen request` (or `vault_request`) and gives you a link; you paste the key on that page. [Ask a human for a credential](request-a-credential.md) shows it from the agent's side.
- **Add it yourself, no agent needed.** In the web app, open **Credentials** and choose **Add a credential**: pick the service (paste a key for a template, or sign in for an OAuth provider), name it, choose where it belongs, and Continue. The next page seals the key in your browser and you confirm with your passkey. A service with no template cannot start there: ask an agent on one of your machines to request it with the service's host (`--host`), and the page asks you to check that destination before anything is saved. A secret that only a program reads, such as `JWT_SECRET` or `DATABASE_URL`, needs no host: requested as a `generic` or `database-url` without `--host`, it is lease-only, and only `mehen run` delivers it.

## Then clear out the `.env`

- In a coding project, declare the variable names in `mehen.toml` and point each at its credential with `mehen env set` ([Project variables with mehen run](projects.md)).
- Delete the value from `.env`, and the file once nothing is left in it. Keep a `.env.example` with the names and no values, so people can see what the project needs.
- Bun, Next.js and Vite load `.env` by themselves. `mehen run` does not stop that, so a leftover `.env` still feeds its old values into the program `mehen run` starts.

## Rotate what was exposed

Moving a key into the vault does not make an exposed key secret again. Rotate at the provider, and put the new value in rather than the old one, for any key an agent could already read (a `.env` in a repo an agent works in, a chat, shell history) and any key that sat in a synced or shared file (a cloud drive, a shared folder, a commit). When the new value replaces one the vault holds, the old value is kept for 30 days and can be restored with a passkey from the credential's page, in case the provider still needs it ([Previous values](../concepts/credentials.md#previous-values)).
