import { z } from "zod"

// A sealed box as an intake submission or an adoption upload carries it, one
// secret field per box. The context it was sealed under is the vault's to
// check when it opens the box. Kept out of seal.ts so the browser seal entry
// stays free of zod; the platform's stricter shape is platform.ts's
// SealedBoxSchema.
export const IntakeSealedBoxSchema = z.object({
  v: z.literal(1),
  epk: z.object({ kty: z.literal("EC"), crv: z.literal("P-256"), x: z.string().max(100), y: z.string().max(100) }),
  iv: z.string().max(100),
  ct: z.string().max(200_000),
})
