---
title: Reference
question: Where is each exact fact?
section: reference
covers: both
order: 0
---

# Reference

The exact facts: every command, flag, variable, tool, error code, provider and platform route. The command, error, tool, provider and platform pages are generated from the command line, the protocol and the template catalogue that ship together, so they say what the `mehen` named in the footer does.

- [The mehen command line](reference/cli.md): what does each command do, and what are its flags, variables and exit codes?
- [MCP tools](reference/mcp.md): what are the `vault_*` tools and their inputs?
- [Errors and exit codes](reference/errors.md): what does each error mean, and what do I do?
- [Providers and templates](reference/providers.md): which providers can an agent name, and what does each allow, hold and refuse?
- [The ask object](reference/ask.md): what is the shape a harness draws a card from?
- [mehen.toml](reference/mehen-toml.md): what goes in the project manifest?
- [Platform API](reference/platform.md): what does each platform route take and answer, and how is a call signed?
- [HTTP surfaces](reference/http.md): what does a client see on the wire?

## For agents

- [The short guide](guide.md): what `mehen guide` prints, as markdown at [`/guide.md`](/guide.md).
- [The skill](skill.md): what Claude and pi agents load, at [`/skill.md`](/skill.md).
- [Agent reference](reference/agent-reference.md): the MCP tools, templates, per-agent setup and `AGENTS.md` snippet the skill points to.
- [`/llms.txt`](/llms.txt) lists every page, and [`/llms-full.txt`](/llms-full.txt) is all of them in one file.

Every page is also markdown: add `.md` to its address. The same facts are JSON at [`/reference/cli.json`](/reference/cli.json), [`/reference/errors.json`](/reference/errors.json), [`/reference/mcp.json`](/reference/mcp.json), [`/reference/providers.json`](/reference/providers.json) and [`/reference/platform.json`](/reference/platform.json).
