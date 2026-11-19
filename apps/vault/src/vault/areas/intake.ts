// Pieces the workspace intakes (intake-workspace.ts) and adoptions share:
// the reason a member's ask records, the proposed
// injection check and the sealed submission with its digest. Its area
// carries the workspace requests' migrations.

import { z } from "zod"
import { BindingSchema, type Injection, Slug, Tag } from "@mehen/protocol/api"
import { KINDS, type ItemKind, IntakeSealedBoxSchema, isReservedHeader } from "@mehen/protocol"
import { VaultError } from "../../http.ts"
import type { Area } from "../core.ts"
import "./credentials-pending.ts"
import { credentialOps } from "./items-workspace.ts"
import { workspaceIntakeOps, workspaceRequestMigration, workspaceRequestWorkloadMigration } from "./intake-workspace.ts"
import { stepUpDigest } from "./items.ts"

// The reason recorded on an ask a member starts from Connect a service:
// fixed, since the member types no reason and a page quotes this line.
export const MEMBER_REASON = "Started from Connect a service in the vault."

// The first four made the table of single-tenant intakes, which no
// workspace ever wrote; they stay so every workspace's migration count
// holds, and the last drops it.
const INTAKE_MIGRATIONS = [
  `CREATE TABLE intakes (
       id TEXT PRIMARY KEY,
       kind TEXT NOT NULL,
       slug TEXT NOT NULL,
       provider TEXT,
       reason TEXT NOT NULL,
       tags TEXT NOT NULL,
       proposed_binding TEXT,
       rotation INTEGER NOT NULL,
       device TEXT NOT NULL,
       device_name TEXT NOT NULL,
       session TEXT,
       status TEXT NOT NULL,
       item TEXT,
       created_at INTEGER NOT NULL,
       expires_at INTEGER NOT NULL,
       completed_at INTEGER
     );
     CREATE INDEX intakes_device ON intakes (device, created_at);`,
  `ALTER TABLE intakes ADD COLUMN proposed_injection TEXT;`,
  `ALTER TABLE intakes ADD COLUMN connect TEXT;
   ALTER TABLE intakes ADD COLUMN cancel_reason TEXT;`,
  `ALTER TABLE intakes ADD COLUMN claimed_at INTEGER;`,
]

const DROP_SINGLE_TENANT_INTAKES = "DROP TABLE IF EXISTS intakes;"

const INJECTION_HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/

// An agent's proposed injection may only name this kind's fields, must put
// a secret field into the request, and may only be one header (never a
// reserved one), one query parameter or basic credentials: a header map
// would let the human's entry name any header at all.
export function assertProposedInjection(kind: ItemKind, injection: Injection): void {
  const spec = KINDS[kind]
  const fields = new Map(spec.fields.map((f) => [f.name, f]))
  const secretNames = spec.fields.filter((f) => f.secret).map((f) => f.name).join(", ")
  const bad = (why: string): never => {
    throw new VaultError("bad_request", `The proposed injection ${why}. A ${spec.label} has the secret field(s) ${secretNames}; use for example { "in": "header", "name": "Authorization", "format": "Bearer {${spec.fields.find((f) => f.secret)?.name ?? "key"}}" }.`)
  }
  const secret = (name: string): boolean => fields.get(name)?.secret === true
  switch (injection.in) {
    case "header": {
      if (!INJECTION_HEADER_NAME.test(injection.name) || isReservedHeader(injection.name)) bad(`cannot use the header "${injection.name}"`)
      if (/[\r\n\0]/.test(injection.format)) bad("has a line break in its format")
      const markers = [...injection.format.matchAll(/\{([a-z][a-z0-9_]*)\}/g)].map((m) => m[1] as string)
      const unknown = markers.filter((m) => !fields.has(m))
      if (unknown.length > 0) bad(`names ${unknown.map((m) => `{${m}}`).join(", ")}, which a ${spec.label} does not have`)
      if (!markers.some(secret)) bad("puts no secret field into the header")
      break
    }
    case "query":
      if (!INJECTION_HEADER_NAME.test(injection.name)) bad(`cannot use the query parameter "${injection.name}"`)
      if (!secret(injection.field)) bad(`names "${injection.field}", which is not a secret field of a ${spec.label}`)
      break
    case "basic":
      if (!fields.has(injection.username)) bad(`names "${injection.username}", which a ${spec.label} does not have`)
      if (!secret(injection.password)) bad(`names "${injection.password}", which is not a secret field of a ${spec.label}`)
      break
    case "headers":
      bad("is a header map, which an agent may not propose; propose one header, a query parameter or basic credentials")
  }
}

// The browser seals each secret field with seal(sealKey, value, `intake/<intake>/<field>`).
// The body the passkey signs over: stepUpDigest(canonical fields below).
// `tags` echoes the IntakeView's tags so the Worker can rebuild the action;
// the DO signs over the intake's stored tags instead, so a body that names
// other tags fails the step-up check. `allowReads` is the human's tick on a
// credential without a template (IntakeView.customPolicy); it is signed
// only when true, so a submission without it keeps the digest it had.
// `ceiling: "fill"` is the person's "Type it into the sign-in page" on a new
// password-login (submitWorkspaceIntake, intake-workspace.ts); absent, the
// body and its digest are what they were before it existed.
export const IntakeSubmission = z.object({
  slug: Slug,
  binding: BindingSchema,
  publicFields: z.record(z.string().max(64), z.string().max(4096)),
  sealed: z.record(z.string().max(64), IntakeSealedBoxSchema),
  tags: z.array(Tag).max(16),
  allowReads: z.boolean().optional(),
  ceiling: z.literal("fill").optional(),
})
export type IntakeSubmissionInput = z.infer<typeof IntakeSubmission>

export function intakeSubmitDigest(submission: IntakeSubmissionInput): Promise<string> {
  return stepUpDigest({
    slug: submission.slug,
    binding: submission.binding,
    publicFields: submission.publicFields,
    sealed: submission.sealed,
    tags: [...submission.tags].sort(),
    ...(submission.allowReads === true ? { allowReads: true } : {}),
    ...(submission.ceiling !== undefined ? { ceiling: submission.ceiling } : {}),
  })
}

export const intakeArea: Area = {
  name: "intake",
  get migrations() { return [...INTAKE_MIGRATIONS, workspaceRequestMigration, workspaceRequestWorkloadMigration, DROP_SINGLE_TENANT_INTAKES] },
  get workspaceOps() { return credentialOps(workspaceIntakeOps) },
}
