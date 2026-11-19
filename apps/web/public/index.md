# Mehen: use credentials without reading them

Mehen is access for agents: an agent uses API keys without ever receiving them. The agent asks Mehen to make the call; Mehen adds the key on the way out, only to the hosts the key is bound to, and scrubs supported echoes of it from the response, so the agent sees the result and never the key. Or it hands a program a placeholder that becomes the real key only on the way to the right host. A human types each key into the vault's page, never into the chat, and approves held requests with a passkey. Mehen is open source (Apache 2.0) and runs on the human's own machine.

## Set up this machine

The human gives you one prompt:

```text
Follow https://docs.mehen.dev/setup.md to set up Mehen on this machine. I will make the passkey and accept the machine in my browser; never ask me for a key, password or secret.
```

setup.md has you install `mehen` and run `mehen up`, which starts a vault on this machine at `http://localhost:7787`, has the human make a passkey and a workspace in the browser, enrols this machine and wires the agents.

## Join a workspace on Mehen Cloud

Mehen Cloud, for teams, is invite only for now. An invited human gives you a prompt written for them by the workspace's Connect an agent page:

```text
Follow https://docs.mehen.dev/setup.md to connect this machine to Mehen workspace <your-slug> at https://app.mehen.dev. I will approve it in my browser; never ask me for a key, password or secret.
```

You need the workspace slug before you enrol. If the human's prompt does not name it, ask; never guess one.

## Read next

- Setup, the whole procedure: https://docs.mehen.dev/setup.md
- Every page of the docs, for agents: https://docs.mehen.dev/llms.txt
- The source: https://github.com/mehenai/mehen

## Install

setup.md says when to install and how to check for an existing `mehen` first. The installer checks the release manifest's signature against Mehen's release keys, then the binary's SHA-256 against that manifest, and prints a JSON receipt with its absolute path:

```sh
curl -fsSL https://mehen.dev/install | sh
```
