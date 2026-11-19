// Several operators and the changes that need two of them
// (routes/console-operators.ts, directory/operator-proposals.ts) through the
// real Worker, with real web sessions and the real passkey step-up.

import { describe, expect, it } from "vitest"
import { type OperatorCandidate, type OperatorInvitationRead, type OperatorProposalAnswer, type OperatorProposalKind, type OperatorProposalView, type OperatorRequirement, type OperatorsView, operatorAcceptStepUpAction, operatorApproveStepUpAction, operatorProposalDigest, operatorProposeStepUpAction, operatorRequirementsRefusal } from "@mehen/protocol"
import { accountBatch } from "../src/directory/account-store.ts"
import { LAST_OPERATOR, OPERATOR_KIND_HANDLERS } from "../src/directory/operator-proposal-kinds.ts"
import { NEEDS_SECOND_OPERATOR, NO_INVITATION, expireOperatorProposals } from "../src/directory/operator-proposals.ts"
import { maintainWorkspaceDirectory } from "../src/directory/workspace-maintenance.ts"
import { type ConsoleFixture, type Person, answer, consoleFixture } from "./console-support.ts"

const HIDDEN = { error: "not_found", message: "No such operation." }
const OPERATOR_START = "/api/operator/stepup/start"
const ACCOUNT_START = "/api/account/stepup/start"

type Setup = ConsoleFixture & { alex: Person; tom: Person; ravi: Person; kim: Person }

// Alex, Tom and Ravi are operators; Kim is not.
async function setup(): Promise<Setup> {
  const f = await consoleFixture()
  for (const account of ["acc_owner", "acc_admin", "acc_member"]) await f.grantOperator(account)
  return { ...f, alex: await f.person("acc_owner"), tom: await f.person("acc_admin"), ravi: await f.person("acc_member"), kim: await f.person("acc_kim") }
}

async function propose(f: ConsoleFixture, who: Person, kind: OperatorProposalKind, target: string): Promise<Response> {
  const stepUp = await f.proof(who, OPERATOR_START, await operatorProposeStepUpAction({ kind, target, params: {} }))
  return f.request("/api/operator/proposals", who, { kind, target, params: {}, stepUp })
}

async function proposed(f: ConsoleFixture, who: Person, kind: OperatorProposalKind, target: string): Promise<OperatorProposalView> {
  return (await answer<OperatorProposalAnswer>(await propose(f, who, kind, target), 201)).proposal!
}

async function approve(f: ConsoleFixture, who: Person, proposal: { id: string; digest: string }, digest = proposal.digest): Promise<Response> {
  const stepUp = await f.proof(who, OPERATOR_START, operatorApproveStepUpAction(proposal.id, digest))
  return f.request(`/api/operator/proposals/${proposal.id}`, who, { decision: "approve", digest, stepUp })
}

async function accept(f: ConsoleFixture, who: Person, proposal: { id: string; digest: string }): Promise<Response> {
  const stepUp = await f.proof(who, ACCOUNT_START, operatorAcceptStepUpAction(proposal.id, proposal.digest))
  return f.request("/api/account/operator-invitation", who, { proposal: proposal.id, digest: proposal.digest, stepUp })
}

async function refusal(response: Response, status: number, body: unknown): Promise<void> {
  expect({ status: response.status, body: await response.json() }).toEqual({ status, body })
}

async function refused(response: Response, status: number, message: string): Promise<void> {
  expect({ status: response.status, message: ((await response.json()) as { message: string }).message }).toEqual({ status, message })
}

function notReady(f: ConsoleFixture, missing: OperatorRequirement[]): unknown {
  return { error: "forbidden", message: operatorRequirementsRefusal(missing), next: { url: `${f.env.VAULT_ORIGIN}/account`, say: "Your account page shows your passkeys, your recovery and any cooling-off; come back once nothing is missing." } }
}

async function isOperator(f: ConsoleFixture, account: string): Promise<boolean> {
  return (await f.env.DB.prepare("SELECT is_operator FROM accounts WHERE id=?").bind(account).first<{ is_operator: number }>())?.is_operator === 1
}

async function events(f: ConsoleFixture): Promise<{ kind: string; actor: string; approver: string | null; target: string; details: Record<string, unknown> }[]> {
  const rows = await f.env.DB.prepare("SELECT kind,actor,approver,target,details FROM deployment_events WHERE actor!='operator:test' ORDER BY at,rowid").all<{ kind: string; actor: string; approver: string | null; target: string; details: string }>()
  return rows.results.map((row) => ({ ...row, details: JSON.parse(row.details) as Record<string, unknown> }))
}

// The accounts given a notice of a proposal's event, sorted.
async function noticed(f: ConsoleFixture, event: string): Promise<string[]> {
  const rows = await f.env.DB.prepare("SELECT account FROM account_notices WHERE json_extract(payload,'$.change')='operator_proposal' AND json_extract(payload,'$.event')=? ORDER BY account").bind(event).all<{ account: string }>()
  return rows.results.map((row) => row.account)
}

describe("who sees the Operators view", () => {
  it("gives every new operator route not_found to an account without the role, and to anyone signed out", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.grant", "acc_kim")
    for (const who of [f.kim, undefined]) {
      await refusal(await f.request("/api/operator/operators", who), 404, HIDDEN)
      await refusal(await f.request("/api/operator/operators/lookup?q=acc_owner", who), 404, HIDDEN)
      await refusal(await f.request("/api/operator/proposals", who, { kind: "operator.grant", target: "acc_guest", params: {} }), 404, HIDDEN)
      await refusal(await f.request(`/api/operator/proposals/${open.id}`, who, { decision: "decline" }), 404, HIDDEN)
      await refusal(await f.request(OPERATOR_START, who, { action: { type: "operator.approve", proposal: open.id, digest: open.digest } }), 404, HIDDEN)
    }
  })

  it("refuses the operator step-ups on the account route, and accepting there to an account no approved grant names", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.grant", "acc_kim")
    const digest = await operatorProposalDigest({ kind: "operator.resign", target: "acc_owner", params: {} })
    await refusal(await f.request(ACCOUNT_START, f.alex, { action: { type: "operator.propose", digest } }), 404, HIDDEN)
    await refusal(await f.request(ACCOUNT_START, f.tom, { action: { type: "operator.approve", proposal: open.id, digest: open.digest } }), 404, HIDDEN)
    // Not approved yet, so Kim has nothing to accept; nor does anyone else.
    await refusal(await f.request(ACCOUNT_START, f.kim, { action: operatorAcceptStepUpAction(open.id, open.digest) }), 404, { error: "not_found", message: NO_INVITATION })
    await answer(await approve(f, f.tom, open))
    await refusal(await f.request(ACCOUNT_START, f.ravi, { action: operatorAcceptStepUpAction(open.id, open.digest) }), 404, { error: "not_found", message: NO_INVITATION })
    expect((await f.request(ACCOUNT_START, f.kim, { action: operatorAcceptStepUpAction(open.id, open.digest) })).status).toBe(200)
    // And the operator start refuses the acceptance.
    await refused(await f.request(OPERATOR_START, f.alex, { action: operatorAcceptStepUpAction(open.id, open.digest) }), 400, "That action does not belong to this scope.")
  })
})

describe("granting the operator role", () => {
  it("is proposed by one operator, approved by another, accepted by the target with their own passkey, and only then set", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.grant", "acc_kim")
    expect(open).toMatchObject({ kind: "operator.grant", target: "acc_kim", targetName: "Kim", proposedBy: { account: "acc_owner" }, state: "open", awaiting: "approval", approvedBy: null })
    expect(open.digest).toBe(await operatorProposalDigest({ kind: "operator.grant", target: "acc_kim", params: {} }))
    expect(await noticed(f, "proposed")).toEqual(["acc_admin", "acc_member", "acc_owner"])

    const approved = await answer<OperatorProposalAnswer>(await approve(f, f.tom, open))
    expect(approved.done).toBe("Approved. Kim accepts it with their own passkey on Your account, before it expires.")
    expect(approved.proposal).toMatchObject({ state: "open", awaiting: "acceptance", approvedBy: { account: "acc_admin" } })
    expect(await isOperator(f, "acc_kim")).toBe(false)
    expect(await noticed(f, "approved")).toEqual(["acc_admin", "acc_kim", "acc_member", "acc_owner"])

    const invitation = await answer<OperatorInvitationRead>(await f.request("/api/account/operator-invitation", f.kim))
    expect(invitation.invitation).toMatchObject({ proposal: open.id, digest: open.digest, proposedBy: { account: "acc_owner" }, approvedBy: { account: "acc_admin" }, missing: [] })
    expect((await answer<OperatorInvitationRead>(await f.request("/api/account/operator-invitation", f.ravi))).invitation).toBeNull()

    expect(await answer(await accept(f, f.kim, open))).toEqual({ done: "Accepted. You are an operator: the Operator area is in your menu." })
    expect(await isOperator(f, "acc_kim")).toBe(true)
    expect(await f.env.DB.prepare("SELECT is_operator_by FROM accounts WHERE id='acc_kim'").first()).toEqual({ is_operator_by: "operator:acc_owner" })
    const applied = (await events(f)).filter((event) => event.kind === "operator.grant")
    expect(applied).toEqual([{ kind: "operator.grant", actor: "operator:acc_owner", approver: "operator:acc_admin", target: "acc_kim", details: { proposal: open.id, digest: open.digest, acceptedAt: expect.any(String) } }])
    expect(await noticed(f, "applied")).toEqual(["acc_admin", "acc_member", "acc_owner"])
    expect((await events(f)).map((event) => event.kind)).toEqual(["proposal.open", "proposal.approve", "operator.grant"])
    // It applies once.
    await refusal(await f.request("/api/account/operator-invitation", f.kim, { proposal: open.id, digest: open.digest }), 404, { error: "not_found", message: NO_INVITATION })
    await refused(await approve(f, f.ravi, open), 409, "This proposal is applied already.")
  })

  it("re-checks what an operator account must have at proposal, approval and acceptance", async () => {
    const f = await setup()
    await f.person("acc_guest", "device")
    const name = (await f.env.DB.prepare("SELECT name FROM accounts WHERE id='acc_guest'").first<{ name: string }>())!.name
    await refused(await propose(f, f.alex, "operator.grant", "acc_guest"), 403, operatorRequirementsRefusal(["security-key"], `${name}'s account`))
    expect(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM operator_proposals").first()).toEqual({ n: 0 })

    const open = await proposed(f, f.alex, "operator.grant", "acc_kim")
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"internal\"]' WHERE account='acc_kim'").run()
    await refused(await approve(f, f.tom, open), 403, operatorRequirementsRefusal(["security-key"], "Kim's account"))
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"usb\"]' WHERE account='acc_kim' AND credential_id LIKE 'second-%'").run()
    await answer(await approve(f, f.tom, open))
    // Kim loses the security key before accepting: refused, saying so, and nothing set.
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"internal\"]' WHERE account='acc_kim'").run()
    expect((await answer<OperatorInvitationRead>(await f.request("/api/account/operator-invitation", f.kim))).invitation?.missing).toEqual(["security-key"])
    await refusal(await f.request("/api/account/operator-invitation", f.kim, { proposal: open.id, digest: open.digest }), 403, notReady(f, ["security-key"]))
    expect(await isOperator(f, "acc_kim")).toBe(false)
  })

  it("the proposer cannot approve their own proposal, in the code and by the table's CHECK", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.grant", "acc_kim")
    await refused(await approve(f, f.alex, open), 403, "You proposed this; a different operator approves it.")
    await expect(f.env.DB.prepare("UPDATE operator_proposals SET approved_by=proposed_by,approved_at=1 WHERE id=?").bind(open.id).run()).rejects.toThrow("CHECK constraint failed")
    expect(await f.env.DB.prepare("SELECT state,approved_by FROM operator_proposals WHERE id=?").bind(open.id).first()).toEqual({ state: "open", approved_by: null })
  })

  it("nobody proposes or approves a change to their own account", async () => {
    const f = await setup()
    await refused(await propose(f, f.alex, "operator.revoke", "acc_owner"), 403, "Nobody may propose a change to their own account.")
    const open = await proposed(f, f.alex, "operator.revoke", "acc_admin")
    await refused(await approve(f, f.tom, open), 403, "Nobody may approve a change to their own account.")
    expect(await isOperator(f, "acc_admin")).toBe(true)
  })

  it("refuses an approval whose digest is not the proposal's, and one past its 24 hours", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.grant", "acc_kim")
    const other = await operatorProposalDigest({ kind: "operator.grant", target: "acc_guest", params: {} })
    await refused(await approve(f, f.tom, open, other), 409, "This proposal is not the one you read. Read it again.")
    await f.env.DB.prepare("UPDATE operator_proposals SET proposed_at=proposed_at-86400001,expires_at=expires_at-86400001 WHERE id=?").bind(open.id).run()
    await refused(await approve(f, f.tom, open), 409, "This proposal expired; propose it again.")
    expect(await f.env.DB.prepare("SELECT state FROM operator_proposals WHERE id=?").bind(open.id).first()).toEqual({ state: "expired" })
    expect((await events(f)).map((event) => [event.kind, event.actor])).toEqual([["proposal.open", "operator:acc_owner"], ["proposal.expire", "system"]])
    expect(await noticed(f, "expired")).toEqual(["acc_admin", "acc_member", "acc_owner"])
    expect(await isOperator(f, "acc_kim")).toBe(false)
    // A new proposal of the same change may open once the old one closed.
    await proposed(f, f.tom, "operator.grant", "acc_kim")
  })

  it("refuses to approve or accept a proposal whose stored terms no longer give its digest", async () => {
    const f = await setup()
    const tampered = "This proposal's stored terms are not the ones proposed; propose it again."
    const first = await proposed(f, f.alex, "operator.grant", "acc_kim")
    await f.env.DB.prepare("UPDATE operator_proposals SET params='{\"edited\":true}' WHERE id=?").bind(first.id).run()
    await refused(await approve(f, f.tom, first), 409, tampered)
    await f.env.DB.prepare("UPDATE operator_proposals SET params='{}' WHERE id=?").bind(first.id).run()
    await answer(await approve(f, f.tom, first))
    await f.env.DB.prepare("UPDATE operator_proposals SET params='{\"edited\":true}' WHERE id=?").bind(first.id).run()
    await refused(await f.request(ACCOUNT_START, f.kim, { action: operatorAcceptStepUpAction(first.id, first.digest) }), 409, tampered)
    await refused(await f.request("/api/account/operator-invitation", f.kim, { proposal: first.id, digest: first.digest }), 409, tampered)
    expect(await isOperator(f, "acc_kim")).toBe(false)
    expect((await events(f)).map((event) => event.kind)).toEqual(["proposal.open", "proposal.approve"])
  })

  it("refuses an acceptance once the approved grant is past its 24 hours, telling its target as well as every operator", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.grant", "acc_kim")
    await answer(await approve(f, f.tom, open))
    await f.env.DB.prepare("UPDATE operator_proposals SET proposed_at=proposed_at-86400001,expires_at=expires_at-86400001 WHERE id=?").bind(open.id).run()
    await refusal(await f.request(ACCOUNT_START, f.kim, { action: operatorAcceptStepUpAction(open.id, open.digest) }), 404, { error: "not_found", message: NO_INVITATION })
    await refusal(await f.request("/api/account/operator-invitation", f.kim, { proposal: open.id, digest: open.digest }), 404, { error: "not_found", message: NO_INVITATION })
    expect(await f.env.DB.prepare("SELECT state FROM operator_proposals WHERE id=?").bind(open.id).first()).toEqual({ state: "expired" })
    expect(await isOperator(f, "acc_kim")).toBe(false)
    expect((await events(f)).map((event) => event.kind)).toEqual(["proposal.open", "proposal.approve", "proposal.expire"])
    expect(await noticed(f, "expired")).toEqual(["acc_admin", "acc_kim", "acc_member", "acc_owner"])
  })

  it("the cron expires an open proposal past its 24 hours", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.grant", "acc_kim")
    await maintainWorkspaceDirectory(f.env, Date.now() + 86_400_001)
    expect(await f.env.DB.prepare("SELECT state FROM operator_proposals WHERE id=?").bind(open.id).first()).toEqual({ state: "expired" })
    await expireOperatorProposals(f.env, Date.now() + 86_400_002)
    expect((await events(f)).filter((event) => event.kind === "proposal.expire")).toHaveLength(1)
  })

  it("one open proposal per kind and target", async () => {
    const f = await setup()
    await proposed(f, f.alex, "operator.grant", "acc_kim")
    await refused(await propose(f, f.tom, "operator.grant", "acc_kim"), 409, "There is already an open proposal for that; approve, decline or cancel it first.")
  })
})

describe("the brakes", () => {
  it("another operator declines and the proposer cancels, each without a passkey, and nothing changes", async () => {
    const f = await setup()
    const first = await proposed(f, f.alex, "operator.revoke", "acc_member")
    await refused(await f.request(`/api/operator/proposals/${first.id}`, f.alex, { decision: "decline" }), 403, "You proposed this; cancel it instead.")
    await refused(await f.request(`/api/operator/proposals/${first.id}`, f.tom, { decision: "cancel" }), 403, "Only the operator who proposed it cancels it; decline it instead.")
    expect(await answer<OperatorProposalAnswer>(await f.request(`/api/operator/proposals/${first.id}`, f.tom, { decision: "decline" }))).toMatchObject({ done: "Declined. Nothing changed.", proposal: { state: "declined", declinedBy: { account: "acc_admin" } } })
    const second = await proposed(f, f.alex, "operator.revoke", "acc_member")
    expect(await answer<OperatorProposalAnswer>(await f.request(`/api/operator/proposals/${second.id}`, f.alex, { decision: "cancel" }))).toMatchObject({ done: "Cancelled. Nothing changed.", proposal: { state: "cancelled" } })
    expect(await isOperator(f, "acc_member")).toBe(true)
    expect(await noticed(f, "declined")).toEqual(["acc_admin", "acc_member", "acc_owner"])
    expect(await noticed(f, "cancelled")).toEqual(["acc_admin", "acc_member", "acc_owner"])
    expect((await events(f)).map((event) => [event.kind, event.actor])).toEqual([["proposal.open", "operator:acc_owner"], ["proposal.decline", "operator:acc_admin"], ["proposal.open", "operator:acc_owner"], ["proposal.cancel", "operator:acc_owner"]])
    await refused(await approve(f, f.tom, second), 409, "This proposal is cancelled already.")
  })

  it("the operator a revoke names cannot decline it, in the code and by the table's CHECK", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.revoke", "acc_member")
    await refused(await f.request(`/api/operator/proposals/${open.id}`, f.ravi, { decision: "decline" }), 403, "Nobody may decline a change to their own account.")
    await expect(f.env.DB.prepare("UPDATE operator_proposals SET state='declined',closed_at=1,declined_by=target WHERE id=?").bind(open.id).run()).rejects.toThrow("CHECK constraint failed")
    expect(await f.env.DB.prepare("SELECT state,declined_by FROM operator_proposals WHERE id=?").bind(open.id).first()).toEqual({ state: "open", declined_by: null })
    await answer(await approve(f, f.tom, open))
    expect(await isOperator(f, "acc_member")).toBe(false)
  })
})

describe("revoking and resigning", () => {
  it("revokes another operator's role once a second operator approves, with the event and a notice to every operator", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.revoke", "acc_member")
    expect(await isOperator(f, "acc_member")).toBe(true)
    expect(await answer<OperatorProposalAnswer>(await approve(f, f.tom, open))).toMatchObject({ done: expect.stringMatching(/ is no longer an operator\.$/), proposal: { state: "applied", awaiting: null } })
    expect(await isOperator(f, "acc_member")).toBe(false)
    expect((await events(f)).at(-1)).toEqual({ kind: "operator.revoke", actor: "operator:acc_owner", approver: "operator:acc_admin", target: "acc_member", details: { proposal: open.id, digest: open.digest } })
    expect(await noticed(f, "applied")).toEqual(["acc_admin", "acc_member", "acc_owner"])
    // Ravi is no operator now: every operator route is hidden from him.
    await refusal(await f.request("/api/operator/operators", f.ravi), 404, HIDDEN)
  })

  it("when two operators approve at the same time, one approval lands: a revoke applies once and a grant is approved once", async () => {
    const f = await setup()
    await f.grantOperator("acc_kim")
    await f.person("acc_guest")
    const both = async (open: OperatorProposalView): Promise<number[]> => {
      const proofs = await Promise.all([f.tom, f.kim].map(async (who) => ({ who, stepUp: await f.proof(who, OPERATOR_START, operatorApproveStepUpAction(open.id, open.digest)) })))
      const responses = await Promise.all(proofs.map(({ who, stepUp }) => f.request(`/api/operator/proposals/${open.id}`, who, { decision: "approve", digest: open.digest, stepUp })))
      return responses.map((response) => response.status).sort()
    }
    const count = async (kind: string): Promise<unknown> => f.env.DB.prepare("SELECT COUNT(*) AS n FROM deployment_events WHERE kind=?").bind(kind).first()
    const revoke = await proposed(f, f.alex, "operator.revoke", "acc_member")
    expect(await both(revoke)).toEqual([200, 409])
    expect(await isOperator(f, "acc_member")).toBe(false)
    expect(await count("operator.revoke")).toEqual({ n: 1 })
    const grant = await proposed(f, f.alex, "operator.grant", "acc_guest")
    expect(await both(grant)).toEqual([200, 409])
    expect(await count("proposal.approve")).toEqual({ n: 1 })
    expect(await f.env.DB.prepare("SELECT state FROM operator_proposals WHERE id=?").bind(grant.id).first()).toEqual({ state: "open" })
  })

  it("resigns your own role with one passkey and no second operator, even without a security key, telling every operator", async () => {
    const f = await setup()
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"internal\"]' WHERE account='acc_member'").run()
    expect(await answer<OperatorProposalAnswer>(await propose(f, f.ravi, "operator.resign", "acc_member"))).toEqual({ done: "You are no longer an operator.", proposal: null })
    expect(await isOperator(f, "acc_member")).toBe(false)
    expect(await events(f)).toEqual([{ kind: "operator.resign", actor: "operator:acc_member", approver: null, target: "acc_member", details: { digest: await operatorProposalDigest({ kind: "operator.resign", target: "acc_member", params: {} }) } }])
    expect(await noticed(f, "applied")).toEqual(["acc_admin", "acc_member", "acc_owner"])
    await refused(await propose(f, f.alex, "operator.resign", "acc_admin"), 403, "This change is only ever to your own account.")
  })

  it("never leaves Mehen without an operator: the last one cannot resign or be revoked", async () => {
    const f = await setup()
    await answer(await propose(f, f.ravi, "operator.resign", "acc_member"))
    await answer(await propose(f, f.alex, "operator.resign", "acc_owner"))
    await refused(await propose(f, f.tom, "operator.resign", "acc_admin"), 409, LAST_OPERATOR)
    expect(await isOperator(f, "acc_admin")).toBe(true)
    // Through the app a revoke always leaves its proposer and approver, so
    // its check and its batch guard are what stop any other way of applying
    // one to the last operator.
    const revoke = { kind: "operator.revoke" as const, target: "acc_admin", params: {} }
    const handler = OPERATOR_KIND_HANDLERS["operator.revoke"]
    await expect(handler.check(f.env, revoke, Date.now())).rejects.toThrow(LAST_OPERATOR)
    await expect(accountBatch(f.env, [...handler.guards(f.env, revoke, Date.now()), ...(await handler.apply(f.env, revoke, "acc_owner", Date.now())).statements])).rejects.toThrow("Account state changed. Try again.")
    expect(await isOperator(f, "acc_admin")).toBe(true)
  })

  it("until two operators exist, a two-operator change says it needs a second operator; the script still works", async () => {
    const f = await consoleFixture()
    await f.grantOperator("acc_owner")
    const alex = await f.person("acc_owner")
    await f.person("acc_kim")
    await refused(await propose(f, alex, "operator.grant", "acc_kim"), 403, NEEDS_SECOND_OPERATOR)
    await refused(await propose(f, alex, "operator.resign", "acc_owner"), 409, LAST_OPERATOR)
    await f.grantOperator("acc_kim")
    expect(await isOperator(f, "acc_kim")).toBe(true)
  })
})

describe("what an operator account must have, for proposals", () => {
  it("refuses an operator without a security key, saying so before any passkey, at the step-up and the proposal", async () => {
    const f = await setup()
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"internal\"]' WHERE account='acc_owner'").run()
    const open = await proposed(f, f.tom, "operator.grant", "acc_kim")
    await refusal(await f.request(OPERATOR_START, f.alex, { action: operatorApproveStepUpAction(open.id, open.digest) }), 403, notReady(f, ["security-key"]))
    await refusal(await f.request(`/api/operator/proposals/${open.id}`, f.alex, { decision: "approve", digest: open.digest }), 403, notReady(f, ["security-key"]))
    await refusal(await f.request("/api/operator/proposals", f.alex, { kind: "operator.revoke", target: "acc_member", params: {} }), 403, notReady(f, ["security-key"]))
    await refusal(await f.request(OPERATOR_START, f.alex, { action: await operatorProposeStepUpAction({ kind: "operator.revoke", target: "acc_member", params: {} }) }), 403, notReady(f, ["security-key"]))
    // Resigning only removes power: its passkey may still be asked for.
    expect((await f.request(OPERATOR_START, f.alex, { action: await operatorProposeStepUpAction({ kind: "operator.resign", target: "acc_owner", params: {} }) })).status).toBe(200)
    // Tom's proposal waits; it cannot apply with Alex as its second operator.
    expect(await f.env.DB.prepare("SELECT state FROM operator_proposals WHERE id=?").bind(open.id).first()).toEqual({ state: "open" })
  })

  it("a proposer who lost their security key since stops their proposal applying", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.revoke", "acc_member")
    await f.env.DB.prepare("UPDATE passkeys SET transports='[\"internal\"]' WHERE account='acc_owner'").run()
    const name = (await f.env.DB.prepare("SELECT name FROM accounts WHERE id='acc_owner'").first<{ name: string }>())!.name
    await refused(await approve(f, f.tom, open), 409, operatorRequirementsRefusal(["security-key"], `${name}'s account`))
    expect(await isOperator(f, "acc_member")).toBe(true)
  })
})

describe("the Operators view", () => {
  it("lists every operator with their passkeys, recovery and last sign-in, the open and recent proposals, and the events", async () => {
    const f = await setup()
    const open = await proposed(f, f.alex, "operator.grant", "acc_kim")
    const view = await answer<OperatorsView>(await f.request("/api/operator/operators", f.tom))
    expect(view.you).toBe("acc_admin")
    // Grants made in the same millisecond fall back to id order, so compare as a set.
    expect(view.operators.map((o) => [o.account, o.passkeys, o.securityKeys, o.recoveryReady, o.missing, o.grantedBy]).sort()).toEqual([
      ["acc_admin", 2, 1, true, [], "operator:test"],
      ["acc_member", 2, 1, true, [], "operator:test"],
      ["acc_owner", 2, 1, true, [], "operator:test"],
    ])
    expect(view.operators.every((o) => o.since !== null && o.lastSeenAt !== null)).toBe(true)
    expect(view.open.map((p) => p.id)).toEqual([open.id])
    expect(view.recent).toEqual([])
    expect(view.events.map((e) => e.kind)).toEqual(["proposal.open", "operator.grant", "operator.grant", "operator.grant"])
  })

  it("looks an account up by its id or a linked Google email, answering its name, id and what it lacks, never the email", async () => {
    const f = await setup()
    const now = Date.now()
    await f.env.DB.prepare("INSERT INTO oidc_identities(id,account,provider,issuer,subject,email,domain,name,email_verified,linked_at,last_verified_at) VALUES ('oid_kim','acc_kim','google','https://accounts.google.com','sub-kim','kim@example.com','example.com','Kim',1,?,?)").bind(now, now).run()
    const byEmail = await answer<OperatorCandidate>(await f.request("/api/operator/operators/lookup?q=Kim%40Example.com", f.alex))
    expect(byEmail).toEqual({ account: "acc_kim", name: "Kim", operator: false, missing: [] })
    expect(await answer<OperatorCandidate>(await f.request("/api/operator/operators/lookup?q=acc_admin", f.alex))).toMatchObject({ account: "acc_admin", operator: true })
    await refused(await f.request("/api/operator/operators/lookup?q=nobody%40example.com", f.alex), 404, "No active account has that id or sign-in email.")
    await refused(await f.request("/api/operator/operators/lookup", f.alex), 400, "Type an account id (acc_...) or the email of a Google sign-in.")
  })

  it("rate-limits the account lookup per operator account", async () => {
    const f = await setup()
    const counts = new Map<string, number>()
    const limiter = f.env.AUTH_RATE_LIMITER
    f.env.AUTH_RATE_LIMITER = { limit: async ({ key }: { key: string }) => { const n = (counts.get(key) ?? 0) + 1; counts.set(key, n); return { success: n <= 1 } } } as unknown as RateLimit
    try {
      await answer(await f.request("/api/operator/operators/lookup?q=acc_kim", f.alex))
      await refusal(await f.request("/api/operator/operators/lookup?q=acc_kim", f.alex), 429, { error: "rate_limited", message: "Too many account lookups. Try again shortly.", retryAfter: 60 })
      await answer(await f.request("/api/operator/operators/lookup?q=acc_kim", f.tom))
      expect([...counts.keys()]).toEqual(["operator-lookup:acc_owner", "operator-lookup:acc_admin"])
    } finally {
      f.env.AUTH_RATE_LIMITER = limiter
    }
  })
})
