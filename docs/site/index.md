---
title: Mehen docs
question: What is Mehen, and how do I start?
section: start
covers: both
order: 0
---

# Mehen docs

Mehen lets an agent use your API keys without ever receiving them. The agent asks Mehen to make a call; Mehen adds the key on the way out, only to the hosts the key is bound to, and scrubs it from the response, so the agent sees the result and never the key. It is open source under the Apache 2.0 licence, and it runs on your own machine. [Mehen Cloud](start/team.md) runs the same vault for teams.

**Use credentials without reading them.**

## Run it on your machine

```sh
curl -fsSL https://mehen.dev/install | sh && mehen up
```

`mehen up` starts a vault on this machine at `http://localhost:7787`, opens a page where you make a passkey and your workspace, enrols this machine and wires your agents, with guard hooks that stop them reading `.env` files.

[Start here](start.md)

## Paste this to your agent

```prompt
Follow https://docs.mehen.dev/setup.md to set up Mehen on this machine. I will make the passkey and accept the machine in my browser; never ask me for a key, password or secret.
```

To join a workspace on Mehen Cloud instead, its Connect an agent page writes the prompt with your workspace's slug and, when available, a connect code.

[The procedure your agent follows](setup.md)

## How it works

### Ask

An agent that needs a new key never asks for it in chat. It asks the vault for an intake link, the human fills the key in on the vault's page, and the agent gets the credential's name back, never its value. [Intakes and connections](concepts/intakes-and-connections.md)

### Use

The vault makes the HTTP call itself (relay), or gives a program a placeholder that is swapped for the real key only on the way to the credential's bound host. Every credential has a destination, and a request anywhere else is refused. [Credentials](concepts/credentials.md)

### Approve

Requests a credential's policy holds wait for an eligible human, who reads the request on the vault's page and decides with a passkey. The approval is bound to the exact request. [Approvals](concepts/approvals.md)

## Where to go

- [Start here](start.md): How do I set up Mehen on my own machine, in one command?
- [Concepts](concepts.md): What are the pieces, and how do they fit?
- [Guides](guides.md): Which guide do I need?
- [Reference](reference.md): Where is each exact fact?
- [Security](security.md): What is the promise, and where does it stop?
- [Changelog](changelog.md): What changed?

Running the vault somewhere else? [Run it on another machine](start/another-machine.md), [Use it with a team](start/team.md), and [Local or Cloud](start/local-or-cloud.md) to compare. Building a product on Mehen? Start with [Build on Mehen](guides/build-on-mehen.md). The source is at [github.com/mehenai/mehen](https://github.com/mehenai/mehen).

## For agents

Every page is also markdown at `<path>.md`. Start with [`/llms.txt`](/llms.txt), [`/setup.md`](/setup.md) and [`/skill.md`](/skill.md).
