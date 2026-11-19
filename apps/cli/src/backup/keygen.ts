// mehen backup keygen --out <path>: a new age X25519 backup identity,
// offline, in the file format age-keygen writes, created with O_EXCL and
// mode 0600. Refused under MEHEN_HOME or inside a git work tree. Only the
// recipient (age1...) is printed. Run it on a machine no agent uses;
// the identity belongs in a password manager no agent can read and on
// paper, never on an enrolled machine.

import { dirname } from "node:path"
import { ageRecipientFingerprint } from "@mehen/protocol/backup"
import { utf8 } from "@mehen/protocol/bytes"
import type { Env } from "../config.ts"
import { resolveHome } from "../home.ts"
import { usageError } from "../errors.ts"
import { newAgeIdentity } from "./age.ts"
import { backupFailure, gitWorkTreeAbove, insideDir, realTarget, writeNewFile } from "./files.ts"

export type KeygenResult = { recipient: string; fingerprint: string; identityFile: string }

export async function generateBackupKey(options: { out: string; env: Env; now?: () => Date }): Promise<KeygenResult> {
  if (options.out === "-") throw usageError("--out takes a file path: the identity is written only to a new private file, never to stdout.", "mehen backup --help")
  const path = realTarget(options.out)
  const root = realTarget(resolveHome(options.env).root)
  if (insideDir(path, root)) throw backupFailure(`Refusing to write the backup identity to ${path}: it is under MEHEN_HOME (${root}), where agents on an enrolled machine can read it.`, "Write it somewhere outside MEHEN_HOME on a machine no agent uses, then move it to 1Password and paper.")
  const tree = gitWorkTreeAbove(dirname(path))
  if (tree !== null) throw backupFailure(`Refusing to write the backup identity to ${path}: it is inside the git work tree ${tree}.`, "Write it outside every git work tree, so it can never be committed.")
  const { identity, recipient } = await newAgeIdentity()
  const created = (options.now?.() ?? new Date()).toISOString().replace(/\.\d+Z$/, "Z")
  await writeNewFile(path, utf8(`# created: ${created}\n# public key: ${recipient}\n${identity}\n`))
  return { recipient, fingerprint: ageRecipientFingerprint(recipient), identityFile: path }
}
