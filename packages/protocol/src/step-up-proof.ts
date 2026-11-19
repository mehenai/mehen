import { z } from "zod"

// The one step-up proof every grace-enabled route parses: a passkey
// assertion over the challenge the start answered, or `grace: true` when the
// start answered `grace`. Strict, so no proof carries both.
// A route whose actions are all fresh parses the assertion branch alone, so
// a grace proof there is a bad request rather than a refusal at the
// verifier. The console and operator routes keep assertion-only schemas of
// their own.
const Nonce = z.string().min(1).max(200)
export type StepUpAssertionProof = { nonce: string; assertion: unknown; grace?: never }
export type StepUpProof = StepUpAssertionProof | { nonce: string; grace: true }
export const StepUpAssertionProofSchema: z.ZodType<StepUpAssertionProof> = z.strictObject({ nonce: Nonce, assertion: z.unknown().refine((v) => v !== undefined) })
export const StepUpProofSchema: z.ZodType<StepUpProof> = z.union([
  StepUpAssertionProofSchema,
  z.strictObject({ nonce: Nonce, grace: z.literal(true) }),
])
