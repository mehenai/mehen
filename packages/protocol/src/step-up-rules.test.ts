import { describe, expect, test } from "bun:test"
import { StepUpAction, type StepUpActionInput } from "./api.ts"
import { RESTRICTION_MS, type StepUpActionType, WHILE_RESTRICTED, allowedWhileRestricted } from "./step-up-rules.ts"

// One example of every action type, checked against the schema so the list
// cannot drift from StepUpAction.
const EXAMPLES: { [T in StepUpActionType]: Extract<StepUpActionInput, { type: T }> } = {
  "intake.submit": { type: "intake.submit", intake: "int_x", digest: "d" },
  "enrol.approve": { type: "enrol.approve", enrolment: "ABCD", thumbprint: "t", scope: {} },
  "approval.decide": { type: "approval.decide", approval: "apr_x", digest: "d", decision: "approve", constraints: { uses: 1, ttlSeconds: 600 } },
  "policy.decide": { type: "policy.decide", proposal: "pol_x", digest: "d", decision: "approve", effectDigest: "e" },
  "item.update": { type: "item.update", item: "openai", digest: "d" },
  "item.reveal": { type: "item.reveal", item: "openai", field: "key" },
  "item.delete": { type: "item.delete", item: "openai" },
  "device.revoke": { type: "device.revoke", device: "dev_x" },
  "device.rescope": { type: "device.rescope", device: "dev_x", before: {}, scope: {} },
  "invite.create": { type: "invite.create", role: "member" },
  "tenant.unfreeze": { type: "tenant.unfreeze" },
  "passkey.add": { type: "passkey.add" },
  "passkey.remove": { type: "passkey.remove", passkey: "pk_x" },
  "recovery.generate": { type: "recovery.generate" },
  "recovery.resolve": { type: "recovery.resolve", notice: "ntc_x", outcome: "cancel" },
  "member.reset": { type: "member.reset", member: "mem_x" },
  "member.remove": { type: "member.remove", member: "mem_x" },
  "member.confirm": { type: "member.confirm", member: "mem_x" },
}

// What a member in a cooling-off may sign, as a table.
const EXPECTED: Record<StepUpActionType, boolean> = {
  "approval.decide": false,
  "policy.decide": false,
  "device.revoke": true,
  "recovery.resolve": true,
  "intake.submit": false,
  "enrol.approve": false,
  "device.rescope": false,
  "item.update": false,
  "item.reveal": false,
  "item.delete": false,
  "invite.create": false,
  "tenant.unfreeze": false,
  "passkey.add": false,
  "passkey.remove": false,
  "recovery.generate": false,
  "member.reset": false,
  "member.remove": false,
  "member.confirm": false,
}

function schemaTypes(): string[] {
  return StepUpAction.options.map((option) => option.shape.type.value).sort()
}

describe("allowedWhileRestricted", () => {
  test("the table classifies every StepUpAction option, and nothing else", () => {
    expect(Object.keys(WHILE_RESTRICTED).sort()).toEqual(schemaTypes())
    expect(Object.keys(EXAMPLES).sort()).toEqual(schemaTypes())
    for (const example of Object.values(EXAMPLES)) expect(StepUpAction.parse(example)).toEqual(example)
  })

  test("a restricted member may deny, revoke and resolve, and sign nothing that widens", () => {
    for (const [type, example] of Object.entries(EXAMPLES)) {
      expect({ type, allowed: allowedWhileRestricted(example) }).toEqual({ type, allowed: EXPECTED[type as StepUpActionType] })
    }
  })

  test("deciding an approval is allowed for deny only", () => {
    const decide = EXAMPLES["approval.decide"]
    expect(allowedWhileRestricted({ ...decide, decision: "deny" })).toBe(true)
    expect(allowedWhileRestricted({ ...decide, decision: "approve" })).toBe(false)
  })

  test("the cooling-off is one constant of 24 hours", () => {
    expect(RESTRICTION_MS).toBe(86_400_000)
  })

  test("a table that leaves out an action type does not compile", () => {
    const { "member.confirm": _left, ...partial } = WHILE_RESTRICTED
    // @ts-expect-error member.confirm is missing, so this is not a full table
    const table: typeof WHILE_RESTRICTED = partial
    expect(Object.keys(table)).not.toContain("member.confirm")
  })
})

test("restricted policy approvals and remembered approvals refuse; deny remains allowed", () => {
  const policy = EXAMPLES["policy.decide"]
  expect(allowedWhileRestricted(policy)).toBe(false)
  expect(allowedWhileRestricted({ ...policy, decision: "deny", effectDigest: null })).toBe(true)
  const approval = EXAMPLES["approval.decide"]
  expect(allowedWhileRestricted({ ...approval, remember: { kind: "exact", selector: { device: "dev_x", session: null } } })).toBe(false)
})

import { WORKSPACE_WHILE_RESTRICTED, scopeChangeIsNarrowing, workspaceAllowedWhileRestricted } from "./step-up-rules.ts"
import type { WorkspaceDeviceScope } from "./workspace.ts"
const wsScope: WorkspaceDeviceScope = { tags: ["work", "dev"], projects: ["a", "b"], modes: ["relay", "lease"], maxEnvironment: "protected", privateCredentials: false }
test("workspace narrowing compares every effective set with empty as all", () => {
  for (const patch of [{ tags: [] }, { projects: [] }, { tags: ["work", "extra"] }, { projects: ["a", "extra"] }, { tags: ["work"], projects: ["a", "b", "extra"] }, { privateCredentials: true }]) {
    const after = { ...wsScope, ...patch }
    expect(scopeChangeIsNarrowing(wsScope, after)).toBe(false)
    expect(workspaceAllowedWhileRestricted({ type: "device.rescope", device: "d", thumbprint: "k", before: wsScope, after })).toBe(false)
  }
  expect(scopeChangeIsNarrowing({ ...wsScope, tags: ["last"] }, { ...wsScope, tags: [] })).toBe(false)
  expect(scopeChangeIsNarrowing({ ...wsScope, projects: ["last"] }, { ...wsScope, projects: [] })).toBe(false)
  const after: WorkspaceDeviceScope = { ...wsScope, tags: ["work"], projects: ["a"], modes: ["relay"], maxEnvironment: "unprotected" }
  expect(scopeChangeIsNarrowing(wsScope, after)).toBe(true)
  expect(scopeChangeIsNarrowing({ ...wsScope, tags: [], projects: [] }, after)).toBe(true)
  expect(workspaceAllowedWhileRestricted({ type: "device.rescope", device: "d", thumbprint: "k", before: wsScope, after })).toBe(true)
})

test("approving an adoption batch creates credentials, so a restricted member may not sign it", () => {
  expect(WORKSPACE_WHILE_RESTRICTED["adoption.approve"]).toBe("refused")
  expect(workspaceAllowedWhileRestricted({ type: "adoption.approve", adoption: "adp_x", digest: "d", repoints: 0 })).toBe(false)
})

test("restoring a replaced value puts an older secret back in use, so a restricted member may not sign it", () => {
  expect(WORKSPACE_WHILE_RESTRICTED["item.restore"]).toBe("refused")
  expect(workspaceAllowedWhileRestricted({ type: "item.restore", item: "itm_x", digest: "d" })).toBe(false)
})

import { canonicalJson } from "./api.ts"
import { EnvironmentUpdateSubjectSchema, environmentUpdateDigestInput } from "./workspace.ts"
test("environment digest binds fourEyes", () => {
 const subject = { change: "environment.update" as const, project: "prj_a", env: "prod", protected: true, fences: [], fourEyes: true }
 const { fourEyes, ...missing } = subject
 expect(EnvironmentUpdateSubjectSchema.safeParse(missing).success).toBe(false)
 expect(() => environmentUpdateDigestInput(missing as typeof subject)).toThrow()
 expect(canonicalJson(environmentUpdateDigestInput(subject))).not.toBe(canonicalJson(environmentUpdateDigestInput({ ...subject, fourEyes: false })))
})
test("adding a mode or raising the environment ceiling individually widens", () => {
 const before: WorkspaceDeviceScope = { ...wsScope, modes: ["relay"], maxEnvironment: "unprotected" }
 for (const after of [{ ...before, modes: ["relay", "lease"] as ["relay", "lease"] }, { ...before, maxEnvironment: "protected" as const }]) {
  expect(scopeChangeIsNarrowing(before, after)).toBe(false)
  expect(workspaceAllowedWhileRestricted({ type: "device.rescope", device: "d", thumbprint: "k", before, after })).toBe(false)
 }
})
test("adding fill widens, even beside lease, and dropping it narrows", () => {
 const before: WorkspaceDeviceScope = { ...wsScope, modes: ["relay", "placeholder", "lease"] }
 const after: WorkspaceDeviceScope = { ...before, modes: ["relay", "placeholder", "fill", "lease"] }
 expect(scopeChangeIsNarrowing(before, after)).toBe(false)
 expect(workspaceAllowedWhileRestricted({ type: "device.rescope", device: "d", thumbprint: "k", before, after })).toBe(false)
 expect(scopeChangeIsNarrowing(after, before)).toBe(true)
})
test("rejecting a scope proposal is allowed while restricted, and accepting one is not", () => {
 expect(workspaceAllowedWhileRestricted({ type: "device.rescope_reject", device: "d", thumbprint: "k", proposal: "rsp_x" })).toBe(true)
 expect(workspaceAllowedWhileRestricted({ type: "device.rescope_accept", device: "d", thumbprint: "k", account: "acc_x", before: wsScope, after: { ...wsScope, privateCredentials: true }, admission: false })).toBe(false)
})
test("workloads required is narrower than allowed, and absent means allowed", () => {
 const allowed: WorkspaceDeviceScope = { ...wsScope }
 const required: WorkspaceDeviceScope = { ...wsScope, workloads: "required" }
 expect(scopeChangeIsNarrowing(allowed, required)).toBe(true)
 expect(scopeChangeIsNarrowing({ ...wsScope, workloads: "allowed" }, required)).toBe(true)
 expect(scopeChangeIsNarrowing(required, allowed)).toBe(false)
 expect(scopeChangeIsNarrowing(required, { ...wsScope, workloads: "allowed" })).toBe(false)
 expect(scopeChangeIsNarrowing(required, required)).toBe(true)
 expect(workspaceAllowedWhileRestricted({ type: "device.rescope", device: "d", thumbprint: "k", before: required, after: allowed })).toBe(false)
 expect(workspaceAllowedWhileRestricted({ type: "device.rescope", device: "d", thumbprint: "k", before: allowed, after: required })).toBe(true)
})
test("granting serviceRuns widens, removing it narrows, and absent means false", () => {
 const service: WorkspaceDeviceScope = { ...wsScope, serviceRuns: true }
 expect(scopeChangeIsNarrowing(wsScope, service)).toBe(false)
 expect(scopeChangeIsNarrowing({ ...wsScope, serviceRuns: false }, service)).toBe(false)
 expect(scopeChangeIsNarrowing(service, wsScope)).toBe(true)
 expect(scopeChangeIsNarrowing(service, { ...wsScope, serviceRuns: false })).toBe(true)
 expect(scopeChangeIsNarrowing(service, service)).toBe(true)
 expect(scopeChangeIsNarrowing(wsScope, { ...wsScope, serviceRuns: false })).toBe(true)
 expect(workspaceAllowedWhileRestricted({ type: "device.rescope", device: "d", thumbprint: "k", before: wsScope, after: service })).toBe(false)
 expect(workspaceAllowedWhileRestricted({ type: "device.rescope", device: "d", thumbprint: "k", before: service, after: wsScope })).toBe(true)
})
test("revoking one workload is allowed while restricted", () => {
 expect(workspaceAllowedWhileRestricted({ type: "workload.revoke", device: "dev_x", workload: "wl_task0001" })).toBe(true)
})

import { WorkspaceStepUpActionSchema } from "./workspace.ts"
test("pushing a value to the places it was pushed before sends it out again, so a restricted member may not sign it", () => {
  const action = { type: "item.push" as const, item: "itm_x", field: "key", version: 8, pushes: [{ destination: "fly:my-app/KEY", via: "itm_fly", viaVersion: 2 }, { destination: "github:o/r/KEY", via: "itm_gh", viaVersion: 1 }] }
  expect(WorkspaceStepUpActionSchema.parse(action)).toEqual(action)
  expect(WORKSPACE_WHILE_RESTRICTED["item.push"]).toBe("refused")
  expect(workspaceAllowedWhileRestricted(action)).toBe(false)
})
test("an item.push action names one to 25 destinations, sorted, each once", () => {
  const push = (n: number) => ({ destination: `fly:app-${String(n).padStart(2, "0")}/KEY`, via: "itm_fly", viaVersion: 1 })
  const action = (pushes: unknown[]) => ({ type: "item.push", item: "itm_x", field: "key", version: 1, pushes })
  expect(WorkspaceStepUpActionSchema.safeParse(action(Array.from({ length: 25 }, (_, i) => push(i)))).success).toBe(true)
  expect(WorkspaceStepUpActionSchema.safeParse(action([])).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse(action(Array.from({ length: 26 }, (_, i) => push(i)))).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse(action([push(2), push(1)])).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse(action([push(1), push(1)])).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse(action([{ ...push(1), extra: true }])).success).toBe(false)
  expect(WorkspaceStepUpActionSchema.safeParse({ ...action([push(1)]), version: 1.5 }).success).toBe(false)
})
import { PLATFORM_STEP_UPS } from "./platform.ts"
test("a batch of approval decisions is allowed while restricted only when every entry denies, and never on a platform", () => {
 const entry = (approval: string, decision: "approve" | "deny") => ({ approval, digest: "d", decision, uses: 1, ttlSeconds: 3600 })
 expect(WORKSPACE_WHILE_RESTRICTED["approval.decide_many"]).toBe("decide")
 expect(workspaceAllowedWhileRestricted({ type: "approval.decide_many", entries: [entry("apr_a", "deny"), entry("apr_b", "deny")] })).toBe(true)
 expect(workspaceAllowedWhileRestricted({ type: "approval.decide_many", entries: [entry("apr_a", "deny"), entry("apr_b", "approve")] })).toBe(false)
 expect(workspaceAllowedWhileRestricted({ type: "approval.decide_many", entries: [entry("apr_a", "approve")] })).toBe(false)
 expect(PLATFORM_STEP_UPS as readonly string[]).not.toContain("approval.decide_many")
})
test("setting how careful a credential is may go back to ask while restricted, and never to routine or trust", () => {
 const action = (level: "ask" | "routine" | "trust") => ({ type: "item.posture" as const, item: "itm_x", digest: "d", level })
 for (const level of ["ask", "routine", "trust"] as const) expect(WorkspaceStepUpActionSchema.parse(action(level))).toEqual(action(level))
 expect(WORKSPACE_WHILE_RESTRICTED["item.posture"]).toBe("decide")
 expect(workspaceAllowedWhileRestricted(action("ask"))).toBe(true)
 expect(workspaceAllowedWhileRestricted(action("routine"))).toBe(false)
 expect(workspaceAllowedWhileRestricted(action("trust"))).toBe(false)
 expect(WorkspaceStepUpActionSchema.safeParse({ ...action("ask"), level: "custom" }).success).toBe(false)
 expect(PLATFORM_STEP_UPS as readonly string[]).not.toContain("item.posture")
})
test("the approval dial signs only a change that asks less, never while restricted, and never rides a grace window", () => {
 const action = { type: "workspace.approvals" as const, before: "writes" as const, after: "work" as const }
 expect(WorkspaceStepUpActionSchema.parse(action)).toEqual(action)
 for (const [before, after] of [["work", "writes"], ["writes", "writes"], ["work", "work"], ["every", "work"], ["writes", "every"]]) expect(WorkspaceStepUpActionSchema.safeParse({ ...action, before, after }).success, `${before} to ${after}`).toBe(false)
 expect(WorkspaceStepUpActionSchema.safeParse({ ...action, after: "trust" }).success).toBe(false)
 expect(workspaceAllowedWhileRestricted(action)).toBe(false)
 expect(PLATFORM_STEP_UPS as readonly string[]).not.toContain("workspace.approvals")
})
import { STEP_UP_GRACE_MS, WORKSPACE_STEP_UP_GRACE, workspaceStepUpGraced } from "./step-up-rules.ts"
describe("which confirmations a passkey grace window may cover", () => {
  // Always fresh: everything that can widen, relax a
  // protection or hide either behind a digest.
  const FRESH = ["passkey.add", "passkey.remove", "recovery.generate", "recovery.resolve", "identity.link", "identity.unlink", "account.delete", "workspace.delete", "workspace.delete_cancel", "workspace.identity_rule", "workspace.unfreeze", "member.invite", "member.confirm", "member.role", "member.remove", "member.suspend", "member.reinstate", "team.members", "project.share", "project.configure", "project.delete", "item.update", "item.rehome", "override.set", "backup.recipient_add", "backup.recipient_remove", "enrol.approve", "enrol.accept", "device.rescope_accept", "platform.operate", "platform.administer", "operator.propose", "operator.approve", "operator.accept", "operator.break_glass_link", "mandate.sign", "workspace.approvals"]
  test("the table decides every WorkspaceStepUpAction type, and the always-fresh list is exactly the design's", () => {
    expect(Object.keys(WORKSPACE_STEP_UP_GRACE).sort()).toEqual(WorkspaceStepUpActionSchema.options.map((option) => option.shape.type.value).sort())
    expect(Object.entries(WORKSPACE_STEP_UP_GRACE).filter(([, rule]) => rule === "fresh").map(([type]) => type).sort()).toEqual([...FRESH].sort())
    expect(Object.entries(WORKSPACE_STEP_UP_GRACE).filter(([, rule]) => typeof rule === "function").map(([type]) => type).sort()).toEqual(["adoption.approve", "approval.decide", "device.rescope", "item.posture", "mandate.resume", "policy.decide"])
    expect(STEP_UP_GRACE_MS).toBe(900_000)
  })
  test("a one-off approval rides the window; one that remembers a rule asks for the passkey", () => {
    const decide = { type: "approval.decide" as const, approval: "apr_x", digest: "d", decision: "approve" as const, constraints: { uses: 1, ttlSeconds: 600 } }
    expect(workspaceStepUpGraced(decide)).toBe(true)
    expect(workspaceStepUpGraced({ ...decide, decision: "deny" })).toBe(true)
    expect(workspaceStepUpGraced({ ...decide, remember: { kind: "exact", selector: { device: "dev_x", session: null } } } as typeof decide)).toBe(false)
    expect(workspaceStepUpGraced({ type: "approval.decide_many", entries: [{ approval: "apr_a", digest: "d", decision: "approve", uses: 1, ttlSeconds: 600 }] })).toBe(true)
  })
  test("denying a policy proposal rides the window; approving one, which makes a rule, a grant or a co-signature, asks", () => {
    const decide = { type: "policy.decide" as const, proposal: "pp_x", digest: "d", decision: "deny" as const, effectDigest: null }
    expect(workspaceStepUpGraced(decide)).toBe(true)
    expect(workspaceStepUpGraced({ ...decide, decision: "approve", effectDigest: "e" })).toBe(false)
  })
  test("a posture back to ask rides the window; routine and trust ask", () => {
    const posture = (level: "ask" | "routine" | "trust") => ({ type: "item.posture" as const, item: "it_x", digest: "d", level })
    expect(workspaceStepUpGraced(posture("ask"))).toBe(true)
    expect(workspaceStepUpGraced(posture("routine"))).toBe(false)
    expect(workspaceStepUpGraced(posture("trust"))).toBe(false)
    expect(workspaceStepUpGraced({ type: "workspace.approvals", before: "writes", after: "work" })).toBe(false)
  })
  test("an adoption that repoints no project variable rides the window; one that repoints any asks", () => {
    const approve = { type: "adoption.approve" as const, adoption: "adp_x", digest: "d", repoints: 0 }
    expect(workspaceStepUpGraced(approve)).toBe(true)
    expect(workspaceStepUpGraced({ ...approve, repoints: 1 })).toBe(false)
  })
  test("narrowing a machine's scope rides the window; widening it asks", () => {
    const narrower: WorkspaceDeviceScope = { ...wsScope, tags: ["work"] }
    expect(workspaceStepUpGraced({ type: "device.rescope", device: "d", thumbprint: "k", before: wsScope, after: narrower })).toBe(true)
    expect(workspaceStepUpGraced({ type: "device.rescope", device: "d", thumbprint: "k", before: narrower, after: wsScope })).toBe(false)
  })
  test("signing a mandate asks for the passkey; resuming one from a pause rides the window, from a trip or a lapse asks", () => {
    expect(workspaceStepUpGraced({ type: "mandate.sign", device: "dev_x", digest: "d" })).toBe(false)
    const resume = (from: "paused" | "tripped" | "lapsed") => ({ type: "mandate.resume" as const, mandate: "mdt_x", digest: "d", rev: 2, from })
    expect(workspaceStepUpGraced(resume("paused"))).toBe(true)
    expect(workspaceStepUpGraced(resume("tripped"))).toBe(false)
    expect(workspaceStepUpGraced(resume("lapsed"))).toBe(false)
    expect(WorkspaceStepUpActionSchema.safeParse({ type: "mandate.resume", mandate: "mdt_x", digest: "d", rev: 2 }).success).toBe(false)
  })
  test("a table that leaves out an action type does not compile", () => {
    const { "item.update": _left, ...partial } = WORKSPACE_STEP_UP_GRACE
    // @ts-expect-error item.update is missing, so this is not a full table
    const table: typeof WORKSPACE_STEP_UP_GRACE = partial
    expect(Object.keys(table)).not.toContain("item.update")
  })
})
