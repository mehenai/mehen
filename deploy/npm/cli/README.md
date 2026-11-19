# @mehenai/cli

[Mehen](https://mehen.dev) is a credential vault and proxy for AI agents: your agent uses your API keys without ever receiving them.

```sh
npx @mehenai/cli up
```

sets Mehen up on this machine: it starts a local vault, opens a page where you make a passkey, enrols the machine and wires your agents (Claude Code, Codex, Cursor, pi and others).

This package is a small launcher. It runs the signed `mehen` program, and the first time, installs it with the same installer as `curl -fsSL https://mehen.dev/install | sh`, into `~/.local/bin` (or `MEHEN_INSTALL_DIR`). From then on `mehen` updates itself from signed releases, and every `mehen` command works through this package too: `npx @mehenai/cli status`.

macOS and Linux (glibc, WSL included). Docs: https://docs.mehen.dev. Source: https://github.com/mehenai/mehen. Apache 2.0.
