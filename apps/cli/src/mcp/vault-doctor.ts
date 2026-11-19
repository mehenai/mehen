import { z } from "zod"
import { type DoctorSpan, doctorAll } from "../commands/doctor.ts"
import { toCliError } from "../errors.ts"
import type { FoundSlot } from "../slots.ts"
import { READS, type ToolDeps, WORKSPACE_ARG, plain, tool } from "./shared.ts"
import { withServerCli } from "./vault-status.ts"

// What this server spans, with its latch as doctor's guard: doctor signs
// only for a slot the latch accepts, never for an identity this server has
// not latched, and reports a refusal as that slot's enrolled check without
// probing or signing for it.
async function doctorSpan(deps: ToolDeps, workspace: string | null): Promise<DoctorSpan> {
  const guard: DoctorSpan["guard"] = async (slot) => {
    try {
      await deps.validate({ dir: slot.dir, config: slot.config, onDisk: true })
      return null
    } catch (error) {
      return toCliError(error)
    }
  }
  if (workspace !== null) {
    const span = await deps.span(workspace)
    return { slots: [...span.active.map((s): FoundSlot => ({ state: "active", dir: s.dir, config: s.config })), ...span.pending], refusal: null, guard }
  }
  try {
    const span = await deps.span(null)
    return { slots: [...span.active.map((s): FoundSlot => ({ state: "active", dir: s.dir, config: s.config })), ...span.pending, ...span.corrupt], refusal: null, guard }
  } catch (error) {
    return { slots: [], refusal: toCliError(error), guard }
  }
}

export const vaultDoctor = tool({
  name: "vault_doctor",
  title: "Diagnose this machine",
  description:
    "One call that says whether this machine can use the vault and, if not, what to do: the config root, each vault and the clock against it, the session label, each workspace this server may use (enrolled, device key, identity, frozen, open asks) and each enrolment still waiting. " +
    "`ok` is false when a check failed; `next` is the step to take. Works before enrolment; creates nothing; never returns a secret.",
  input: z.object({ workspace: WORKSPACE_ARG }),
  annotations: READS,
  async call(args, deps) {
    const report = await doctorAll(deps.env, { span: await doctorSpan(deps, args.workspace ?? null) })
    return plain({ ...report, cli: withServerCli(report.cli, deps) })
  },
})
