// The CLI as the tests spawn it: src/main.ts with the passwd home lookup
// replaced, so no test child reads this user's real managed-host marker
// path. The stand-in passwd home is MEHEN_TEST_PASSWD_HOME when set, else the
// child's HOME, where the tests have always put the marker. Two values are
// not homes: empty means the lookup failed, `none` means it proved this uid
// has no passwd entry. A home is given by its real path: temporary
// directories sit below links such as macOS's /var, and a passwd home must not
// (the resolver refuses a link anywhere in it). Release binaries are built
// from src/main.ts and never contain this file.

import { realpathSync } from "node:fs"
import { type PasswdHomeResult, setPasswdHomeLookupForTests } from "../agent-profiles.ts"

const passwdHome = process.env.MEHEN_TEST_PASSWD_HOME ?? process.env.HOME
delete process.env.MEHEN_TEST_PASSWD_HOME
function real(path: string): string {
  try { return realpathSync(path) } catch { return path }
}
const answer: PasswdHomeResult = !passwdHome ? { kind: "error", reason: "the test stand-in lookup failed" } : passwdHome === "none" ? { kind: "not-found" } : { kind: "found", home: real(passwdHome) }
setPasswdHomeLookupForTests(() => answer)

// MEHEN_TEST_STDERR_TTY=1: stderr reads as a terminal, so a test sees what a
// human at one would (the countdown, the ask block, status lines).
if (process.env.MEHEN_TEST_STDERR_TTY === "1") Object.defineProperty(process.stderr, "isTTY", { value: true, configurable: true })
delete process.env.MEHEN_TEST_STDERR_TTY

await import("../main.ts")
