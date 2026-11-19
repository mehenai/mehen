// The Operators view's routes (CONSOLE_ROUTES in the protocol package):
// every operator, the two-operator proposals and the operator events, on a
// web session, not_found to an account without the role like every other
// operator route. The one exception is the account's own invitation: the
// operator role an approved proposal grants it, which it accepts with its
// own passkey.
//
// Each write checks everything first (directory/operator-proposals.ts) and
// only then asks for the passkey: a write sent without one gets its plain
// refusal, or the step-up's own once nothing else stops it, so the page
// can ask first and spend a passkey only on a change the vault would take.
// Declining and cancelling are brakes, and need no passkey.

import { CONSOLE_ROUTES, OperatorAcceptAnswerSchema, OperatorAcceptRequestSchema, OperatorAccountLookupQuerySchema, OperatorCandidateSchema, OperatorInvitationReadSchema, OperatorProposalAnswerSchema, OperatorProposalDecisionSchema, OperatorProposeRequestSchema, OperatorsViewSchema, operatorAcceptStepUpAction, operatorApproveStepUpAction, operatorProposalDigest, parseOperatorProposalTerms } from "@mehen/protocol"
import { z } from "zod"
import { acceptOperatorProposal, approveOperatorProposal, closeOperatorProposal, operatorCandidate, operatorInvitation, operatorsView, proposeOperatorChange, readOperatorProposal } from "../directory/operator-proposals.ts"
import { requireAccountStepUp } from "../directory/workspace-stepup.ts"
import { VaultError, json } from "../http.ts"
import type { Route } from "../router.ts"
import { accountBody, accountBrowser, requireAccount } from "./account.ts"
import type { Handler, RequestContext } from "./context.ts"
import { operatorAccount } from "./console.ts"

const ProposalId = z.string().regex(/^opp_[A-Za-z0-9_-]{1,124}$/)

function proposalInPath(rc: RequestContext): string {
  const id = ProposalId.safeParse(rc.params.id)
  if (!id.success) throw new VaultError("not_found", "No such proposal.")
  return id.data
}

export const consoleOperatorRoutes: Route<Handler>[] = [
  accountBrowser("GET", CONSOLE_ROUTES.operatorOperators, async (rc) => {
    const account = await operatorAccount(rc)
    return json(OperatorsViewSchema.parse(await operatorsView(rc.env, account.account)))
  }),
  // An account by its id or a linked Google email: its name, its id,
  // whether it is an operator already and what it lacks to be one; never
  // its email. Rate-limited per operator account.
  accountBrowser("GET", CONSOLE_ROUTES.operatorAccountLookup, async (rc) => {
    const account = await operatorAccount(rc)
    const limited = await rc.env.AUTH_RATE_LIMITER?.limit({ key: `operator-lookup:${account.account}` })
    if (!limited?.success) throw new VaultError("rate_limited", "Too many account lookups. Try again shortly.", { retryAfter: 60 })
    const query = OperatorAccountLookupQuerySchema.safeParse(Object.fromEntries(rc.url.searchParams))
    if (!query.success) throw new VaultError("bad_request", "Type an account id (acc_...) or the email of a Google sign-in.")
    const candidate = await operatorCandidate(rc.env, query.data.q)
    if (!candidate) throw new VaultError("not_found", "No active account has that id or sign-in email.")
    return json(OperatorCandidateSchema.parse(candidate))
  }),
  accountBrowser("POST", CONSOLE_ROUTES.operatorProposals, async (rc) => {
    const account = await operatorAccount(rc)
    const { kind, target, params, stepUp } = await accountBody(rc, OperatorProposeRequestSchema)
    const parsed = parseOperatorProposalTerms({ kind, target, params })
    if (!parsed.ok) throw new VaultError("bad_request", parsed.problem)
    const digest = await operatorProposalDigest(parsed.terms)
    const result = await proposeOperatorChange(rc.env, account.account, parsed.terms, digest, () => requireAccountStepUp(rc, account, "-", { type: "operator.propose", digest }, stepUp))
    return json(OperatorProposalAnswerSchema.parse({ done: result.done, proposal: result.proposal === null ? null : await readOperatorProposal(rc.env, result.proposal) }), result.proposal === null ? 200 : 201)
  }),
  accountBrowser("POST", CONSOLE_ROUTES.operatorProposal, async (rc) => {
    const account = await operatorAccount(rc)
    const id = proposalInPath(rc)
    const decision = await accountBody(rc, OperatorProposalDecisionSchema)
    const result = decision.decision === "approve"
      ? await approveOperatorProposal(rc.env, account.account, id, decision.digest, () => requireAccountStepUp(rc, account, "-", operatorApproveStepUpAction(id, decision.digest), decision.stepUp))
      : await closeOperatorProposal(rc.env, account.account, id, decision.decision)
    return json(OperatorProposalAnswerSchema.parse({ done: result.done, proposal: await readOperatorProposal(rc.env, id) }))
  }),

  // ---------------------------------------------------------------- every account

  accountBrowser("GET", CONSOLE_ROUTES.operatorInvitation, async (rc) => {
    const account = await requireAccount(rc)
    return json(OperatorInvitationReadSchema.parse({ invitation: await operatorInvitation(rc.env, account.account) }))
  }),
  accountBrowser("POST", CONSOLE_ROUTES.operatorInvitation, async (rc) => {
    const account = await requireAccount(rc)
    const { proposal, digest, stepUp } = await accountBody(rc, OperatorAcceptRequestSchema)
    const result = await acceptOperatorProposal(rc.env, account.account, proposal, digest, () => requireAccountStepUp(rc, account, "-", operatorAcceptStepUpAction(proposal, digest), stepUp))
    return json(OperatorAcceptAnswerSchema.parse(result))
  }),
]
