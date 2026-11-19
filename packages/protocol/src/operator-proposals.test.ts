import { describe, expect, it } from "bun:test"
import { canonicalJson } from "./canonical-json.ts"
import { sha256B64 } from "./bytes.ts"
import { OPERATOR_PROPOSAL_KINDS, accountDeleteNameHash, operatorBreakGlassLinkStepUpAction, operatorProposalDigest, operatorProposeStepUpAction, parseOperatorProposalTerms } from "./operator-proposals.ts"
import { WorkspaceStepUpActionSchema } from "./workspace.ts"

describe("operator proposals", () => {
  it("binds a proposal by the SHA-256 of the canonical JSON of its kind, target and parameters", async () => {
    const terms = { kind: "operator.grant" as const, target: "acc_kim", params: {} }
    expect(await operatorProposalDigest(terms)).toBe(await sha256B64(canonicalJson({ kind: "operator.grant", params: {}, target: "acc_kim" })))
    expect(await operatorProposalDigest({ ...terms, target: "acc_tom" })).not.toBe(await operatorProposalDigest(terms))
    expect(WorkspaceStepUpActionSchema.parse(await operatorProposeStepUpAction(terms))).toEqual({ type: "operator.propose", digest: await operatorProposalDigest(terms) })
  })

  it("parses a proposal's terms with its kind's own schemas", () => {
    expect(parseOperatorProposalTerms({ kind: "operator.revoke", target: "acc_kim", params: {} })).toEqual({ ok: true, terms: { kind: "operator.revoke", target: "acc_kim", params: {} } })
    expect(parseOperatorProposalTerms({ kind: "operator.revoke", target: "kim@example.com", params: {} })).toEqual({ ok: false, problem: "That is not an account id (acc_...)." })
    expect(parseOperatorProposalTerms({ kind: "operator.grant", target: "acc_kim", params: { extra: 1 } })).toEqual({ ok: false, problem: "Those are not the terms of operator.grant." })
  })

  it("parses a workspace's restore and freeze, naming a workspace id and the restore in the script's own forms", () => {
    const point = "2026-10-31T08:15:00.000Z"
    expect(parseOperatorProposalTerms({ kind: "workspace.restore", target: "tn_Beta1234567", params: { source: "pitr", target: point } })).toEqual({ ok: true, terms: { kind: "workspace.restore", target: "tn_Beta1234567", params: { source: "pitr", target: point } } })
    expect(parseOperatorProposalTerms({ kind: "workspace.restore", target: "tn_Beta1234567", params: { source: "dump", target: "2026-10-30" } })).toMatchObject({ ok: true })
    expect(parseOperatorProposalTerms({ kind: "workspace.freeze", target: "tn_Beta1234567", params: {} })).toMatchObject({ ok: true })
    expect(parseOperatorProposalTerms({ kind: "workspace.freeze", target: "acc_kim", params: {} })).toEqual({ ok: false, problem: "That is not a workspace id (tn_...)." })
    for (const params of [{ source: "pitr", target: "2026-10-31T08:15:00Z" }, { source: "pitr", target: "2026-10-31T09:15:00.000+01:00" }, { source: "pitr", target: "2026-02-30T08:15:00.000Z" }, { source: "dump", target: "2026-02-30" }, { source: "dump", target: point }, { source: "pitr" }, { source: "pitr", target: point, extra: 1 }]) {
      expect(parseOperatorProposalTerms({ kind: "workspace.restore", target: "tn_Beta1234567", params })).toEqual({ ok: false, problem: "Those are not the terms of workspace.restore." })
    }
  })

  it("needs two operators for every kind but resigning, freezing a workspace, the Accounts view's brakes and narrowing a setting; resigning is only ever your own", () => {
    expect(Object.entries(OPERATOR_PROPOSAL_KINDS).map(([kind, rule]) => [kind, rule.operators, rule.target, rule.accept, rule.names])).toEqual([
      ["operator.grant", 2, "other", true, "account"],
      ["operator.revoke", 2, "other", false, "account"],
      ["operator.resign", 1, "self", false, "account"],
      ["workspace.restore", 2, "other", false, "workspace"],
      ["workspace.freeze", 1, "other", false, "workspace"],
      ["account.workspace_creation", 1, "other", false, "account"],
      ["account.suspend", 1, "other", false, "account"],
      ["account.lift_suspension", 1, "other", false, "account"],
      ["account.break_glass", 2, "other", false, "account"],
      ["account.delete", 2, "other", false, "account"],
      ["settings.narrow", 1, "other", false, "setting"],
      ["settings.widen", 2, "other", false, "setting"],
    ])
  })

  it("targets a deployment setting by its key, with the value it sets and, for a widening, the value in force when proposed", () => {
    expect(parseOperatorProposalTerms({ kind: "settings.widen", target: "signup_mode", params: { value: "open", from: "invite" } })).toEqual({ ok: true, terms: { kind: "settings.widen", target: "signup_mode", params: { value: "open", from: "invite" } } })
    expect(parseOperatorProposalTerms({ kind: "settings.widen", target: "signup_mode", params: { value: "open" } })).toEqual({ ok: false, problem: "Those are not the terms of settings.widen." })
    expect(parseOperatorProposalTerms({ kind: "settings.narrow", target: "signup_mode", params: { value: "invite", from: "open" } })).toEqual({ ok: false, problem: "Those are not the terms of settings.narrow." })
    expect(parseOperatorProposalTerms({ kind: "settings.narrow", target: "acc_kim", params: { value: "operator" } })).toEqual({ ok: false, problem: "That is not a deployment setting (workspace_creation or signup_mode)." })
    expect(parseOperatorProposalTerms({ kind: "settings.narrow", target: "workspace_creation", params: { value: "everyone" } })).toEqual({ ok: false, problem: "Those are not the terms of settings.narrow." })
  })

  it("parses the Accounts view's terms: a workspace creation choice, plain words for how a person was verified, the hash of a name typed back", async () => {
    expect(parseOperatorProposalTerms({ kind: "account.workspace_creation", target: "acc_kim", params: { creation: "default" } })).toMatchObject({ ok: true })
    expect(parseOperatorProposalTerms({ kind: "account.workspace_creation", target: "acc_kim", params: { creation: "maybe" } })).toMatchObject({ ok: false })
    expect(parseOperatorProposalTerms({ kind: "account.break_glass", target: "acc_kim", params: { verified: "Video call" } })).toMatchObject({ ok: true })
    for (const verified of ["", " Video call", "Video\ncall", "x".repeat(501)]) expect(parseOperatorProposalTerms({ kind: "account.break_glass", target: "acc_kim", params: { verified } }), verified).toMatchObject({ ok: false })
    expect(parseOperatorProposalTerms({ kind: "account.delete", target: "acc_kim", params: { nameHash: await accountDeleteNameHash("acc_kim", "Kim") } })).toMatchObject({ ok: true })
    for (const params of [{}, { name: "Kim" }, { nameHash: "Kim" }]) expect(parseOperatorProposalTerms({ kind: "account.delete", target: "acc_kim", params }), JSON.stringify(params)).toMatchObject({ ok: false })
  })

  it("keeps a hash of the name typed back for deleting, bound to the account, never the name", async () => {
    const kim = await accountDeleteNameHash("acc_kim", "Kim")
    expect(kim).toBe(await sha256B64(canonicalJson({ purpose: "mehen-account-delete-name/v1", target: "acc_kim", name: "Kim" })))
    expect(kim).not.toContain("Kim")
    expect(await accountDeleteNameHash("acc_lee", "Kim")).not.toBe(kim)
    expect(await accountDeleteNameHash("acc_kim", "kim")).not.toBe(kim)
  })

  it("binds taking a recovery link to that intent", () => {
    expect(WorkspaceStepUpActionSchema.parse(operatorBreakGlassLinkStepUpAction("bgi_1"))).toEqual({ type: "operator.break_glass_link", intent: "bgi_1" })
  })
})
