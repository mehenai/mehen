---
title: Providers and templates
question: Which providers can an agent name, and what does each allow, hold and refuse?
section: reference
covers: both
order: 40
generate: providers
---

# Providers and templates

A template is what an agent names with `--provider` when it asks for a credential: it fixes where the key may go, how it is sent and which requests need a human's approval, and the human sees its destination marked as verified. An OAuth provider is what `mehen connect` names. This page is generated from the same catalogue `mehen templates --json` prints, so it matches the `mehen` it was built with; `mehen templates <id>` prints one entry in full. MCP `vault_templates` lists each entry's id, title, category, kind or client template, and hosts, and with `id` returns one entry in full.

Templates fail closed. Reads are allowed, except a read that hands back another secret; every other method needs a human's approval unless the template allows a narrow everyday write by name (model calls, searches, read-only queries); sends and money movements are pinned to an approval; and the worst routes (anything that sends data elsewhere for good, gives someone else access, or mints or revokes tokens) are refused outright. For each entry below, the three policy lines say what goes through without a human, what needs approval, and what is refused; "anything else" sits on the line of the policy's default.

Some templates allow reads by name only, because their providers have reads that hand back tokens, passwords or signing secrets; every other read asks. One exemption is stated rather than hidden: `huggingface` allows `resolve` downloads, which answer with a redirect to a short-lived signed URL. That URL grants a download of exactly the file the allowed read already returns, and nothing more, and downloading model files is the main use of the token. The Xet read and write token routes stay held.

A credential without a template that the vault sends to a service needs a proposed binding (`--host`, and optionally `--path`), and every request it makes needs an approval until a human allows reads. Without `--host`, a kind the relay never sends (such as `generic` or `database-url`) is lease-only: only `mehen run` delivers it, into a process; an `api-key` or another kind the relay injects is refused ([Bindings](../concepts/credentials.md#bindings)). Prefer a template when one exists.
