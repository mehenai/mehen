// Ruling F2: mehen below 0.3.17 reads mode lists with enums that have no
// "fill", and fails on one that holds it: re-running `mehen enrol` (GET
// /v1/me), following an enrolment (GET /v1/enrol/:id, after which it
// revokes the machine), and `mehen workload ls` and `revoke`. So every mode
// list answered to such a CLI, or to one whose version is unknown, leaves
// fill out. Omitted, never mapped to another mode, which could repeat one
// the list already holds.

import type { WorkloadView } from "@mehen/protocol"
import { compareVersions } from "@mehen/protocol/version"
import { VaultError } from "../http.ts"

export const FILL_CLI_VERSION = "0.3.17"

export function cliReadsFill(version: string | null | undefined): boolean {
  if (!version) return false
  try {
    return compareVersions(version, FILL_CLI_VERSION) >= 0
  } catch {
    return false
  }
}

export function scopeForCli<S extends { modes: readonly string[] }>(scope: S, version: string | null | undefined): S {
  return cliReadsFill(version) ? scope : { ...scope, modes: scope.modes.filter((mode) => mode !== "fill") }
}

export function workloadForCli(view: WorkloadView, version: string | null | undefined): WorkloadView {
  return view.scope.modes === undefined ? view : { ...view, scope: scopeForCli({ ...view.scope, modes: view.scope.modes }, version) }
}

// Every released mehen reads a mode list of at least one mode, so a scope
// whose only mode is fill has nothing left once fill is left out.
export function fillOnly(modes: readonly string[] | undefined): boolean {
  return modes !== undefined && modes.length > 0 && modes.every((mode) => mode === "fill")
}

// A machine always keeps another mode besides fill.
export const MACHINE_FILL_ONLY = "A machine needs at least one other way to use credentials besides typing into web pages."
export function refuseFillOnlyMachine(modes: readonly string[]): void {
  if (fillOnly(modes)) throw new VaultError("mode_refused", MACHINE_FILL_ONLY)
}

// A fill-only workload does not exist for a CLI below FILL_CLI_VERSION or
// of unknown version: lists leave it out and its id answers not_found.
export function workloadHiddenFromCli(scope: { modes?: readonly string[] }, version: string | null | undefined): boolean {
  return fillOnly(scope.modes) && !cliReadsFill(version)
}

// GET /v1/me signed by a fill-only workload's own key, from such a CLI.
export function refuseFillOnlyWorkloadStatus(scope: { modes?: readonly string[] }, version: string | null | undefined): void {
  if (workloadHiddenFromCli(scope, version)) throw new VaultError("mode_refused", `This workload only types into web pages, which needs mehen ${FILL_CLI_VERSION} or later.`, { next: { say: "Update mehen on this machine, then try again." } })
}

// Ruling F2(a): fill is never given to a machine whose mehen, as it last
// proved (devices.last_cli_version), is below FILL_CLI_VERSION or unknown,
// since that CLI would fail on the scope it is then answered. Only a change
// that adds fill is refused; one that keeps it is not.
export function refuseFillForOldCli(machine: { name: string; lastCliVersion: string | null }, before: readonly string[], after: readonly string[]): void {
  if (!after.includes("fill") || before.includes("fill") || cliReadsFill(machine.lastCliVersion)) return
  const runs = machine.lastCliVersion ? `runs mehen ${machine.lastCliVersion}` : "runs an unknown version of mehen"
  throw new VaultError("mode_refused", `${machine.name} ${runs}; typing into web pages needs ${FILL_CLI_VERSION} or later.`, { next: { say: "Update mehen on that machine first, then allow it again." } })
}
