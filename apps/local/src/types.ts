// What the local host exposes, as types only: the CLI typechecks against
// these without entering the vault's Workers source.

import type { Address, LocalConfig } from "./config.ts"
import type { Custody, CustodyHost } from "./custody.ts"
import type { Hardening } from "./harden.ts"

export type { Custody, CustodyHost }

// instance is a random token the server writes to its data directory at
// start, so `mehen up` can tell its own vault from anything else that
// answers on the port. custody says what keeps the vault's root key.
export type LocalState = { origin: string; instance: string; accounts: boolean; bootstrap: boolean; custody: Custody; workspaces: { id: string; slug: string; name: string }[] }

export type LocalOptions = { custody?: CustodyHost }

export type LocalVault = {
  origin: string
  port: number
  address: Address
  hardening: Hardening
  applied: string[]
  state(): LocalState
  stop(): Promise<void>
}

export type LocalHost = {
  BOOTSTRAP_FILE: string
  INSTANCE_FILE: string
  startLocalVault(config: LocalConfig, options?: LocalOptions): Promise<LocalVault>
}
