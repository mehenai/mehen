// The Operator area's Settings view (CONSOLE_ROUTES.operatorSettings): each
// deployment setting (deployment-settings.ts) with the value in force, what
// is stored and by whom, and the deploy's ceiling; the open proposals that
// would change one; and every change to them, newest first. A change is a
// settings.narrow or settings.widen proposal (operator-proposals.ts).

import { z } from "zod"
import { DeploymentSettingKeySchema, DeploymentSettingValueSchema } from "./deployment-settings.ts"
import { OperatorEventViewSchema, OperatorProposalViewSchema } from "./operator-proposals.ts"
import { AccountIdSchema, OperatorRequirementSchema } from "./platform-console.ts"

const Iso = z.iso.datetime()
const Count = z.number().int().nonnegative()

export const OPERATOR_SETTINGS_HISTORY = 50

// `value` is in force; `stored` is what the operators set (null: nothing,
// so the deployment does what it did before settings); `ceiling` is the
// deploy's. `updatedBy` is the actor (operator:<who>) and `updatedByName`
// that account's name when it is one.
export const DeploymentSettingViewSchema = z.strictObject({
  key: DeploymentSettingKeySchema,
  value: DeploymentSettingValueSchema,
  stored: DeploymentSettingValueSchema.nullable(),
  ceiling: DeploymentSettingValueSchema,
  updatedAt: Iso.nullable(),
  updatedBy: z.string().nullable(),
  updatedByName: z.string().nullable(),
})
export type DeploymentSettingView = z.infer<typeof DeploymentSettingViewSchema>

// `operators` counts the accounts holding the role, so the page can say a
// widening needs a second; `missing` is what the reader's own account lacks.
export const OperatorSettingsViewSchema = z.strictObject({
  you: AccountIdSchema,
  operators: Count,
  missing: z.array(OperatorRequirementSchema),
  settings: z.array(DeploymentSettingViewSchema),
  open: z.array(OperatorProposalViewSchema),
  history: z.array(OperatorEventViewSchema).max(OPERATOR_SETTINGS_HISTORY),
})
export type OperatorSettingsView = z.infer<typeof OperatorSettingsViewSchema>
