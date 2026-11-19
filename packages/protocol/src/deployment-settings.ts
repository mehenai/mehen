// What a deployment decides for every account, set by its operators in the
// Operator area's Settings view and capped by a ceiling the deploy sets.
//
// Each setting's values run from narrowest to widest. The value in force is
// the one the operators stored, capped by the deploy's ceiling (a variable
// in wrangler.jsonc); with nothing stored it is what the deployment did
// before there were settings. Narrowing is one operator's call with a
// passkey; widening is a two-operator proposal (settings.narrow and
// settings.widen in operator-proposals.ts), and never past the ceiling, so
// even two stolen operator sessions cannot widen what the deploy does not
// allow.

import { z } from "zod"

export type DeploymentSettingRule = {
  // Narrowest first.
  values: readonly [string, ...string[]]
  // The deploy variable that caps it; missing or not one of `values`
  // means the narrowest.
  ceilingVar: string
  // What holds while nothing is stored: "ceiling" is the deploy variable
  // itself.
  unset: string
  // Values the vault does not do yet: shown, never offered.
  notBuilt: readonly string[]
}

export const DEPLOYMENT_SETTINGS = {
  // Whether an account no operator decided on may create workspaces:
  // "operator" only once an operator allowed it, "accounts" every account.
  workspace_creation: { values: ["operator", "accounts"], ceilingVar: "WORKSPACE_CREATION", unset: "ceiling", notBuilt: [] },
  // Who may sign up: by invitation only, by asking for access, or anyone.
  // Stored and shown only: sign-up is by invitation whatever this says.
  signup_mode: { values: ["invite", "request", "open"], ceilingVar: "SIGNUP_MODE_MAX", unset: "invite", notBuilt: ["request", "open"] },
} as const satisfies Record<string, DeploymentSettingRule>

export type DeploymentSettingKey = keyof typeof DEPLOYMENT_SETTINGS
export const DEPLOYMENT_SETTING_KEYS = Object.keys(DEPLOYMENT_SETTINGS) as [DeploymentSettingKey, ...DeploymentSettingKey[]]
export const DeploymentSettingKeySchema = z.enum(DEPLOYMENT_SETTING_KEYS)

type AnySettingValue = (typeof DEPLOYMENT_SETTINGS)[DeploymentSettingKey]["values"][number]
const ALL_VALUES = [...new Set(Object.values(DEPLOYMENT_SETTINGS).flatMap((rule) => rule.values))] as [AnySettingValue, ...AnySettingValue[]]
export const DeploymentSettingValueSchema = z.enum(ALL_VALUES)
export type DeploymentSettingValue = z.infer<typeof DeploymentSettingValueSchema>

export const SignupModeSchema = z.enum(DEPLOYMENT_SETTINGS.signup_mode.values)
export type SignupMode = z.infer<typeof SignupModeSchema>

export function deploymentSettingValues(key: DeploymentSettingKey): readonly DeploymentSettingValue[] {
  return DEPLOYMENT_SETTINGS[key].values
}

export function isDeploymentSettingValue(key: DeploymentSettingKey, value: string): value is DeploymentSettingValue {
  return (deploymentSettingValues(key) as readonly string[]).includes(value)
}

export function deploymentSettingRank(key: DeploymentSettingKey, value: DeploymentSettingValue): number {
  return deploymentSettingValues(key).indexOf(value)
}

export function deploymentSettingNotBuilt(key: DeploymentSettingKey, value: DeploymentSettingValue): boolean {
  return (DEPLOYMENT_SETTINGS[key].notBuilt as readonly string[]).includes(value)
}

// The deploy's ceiling from its variable's raw value.
export function deploymentSettingCeiling(key: DeploymentSettingKey, raw: string | undefined): DeploymentSettingValue {
  return raw !== undefined && isDeploymentSettingValue(key, raw) ? raw : DEPLOYMENT_SETTINGS[key].values[0]
}

// What holds while nothing is stored.
export function deploymentSettingUnset(key: DeploymentSettingKey, ceiling: DeploymentSettingValue): DeploymentSettingValue {
  const unset: string = DEPLOYMENT_SETTINGS[key].unset
  return unset === "ceiling" ? ceiling : (unset as DeploymentSettingValue)
}

// The value in force: the stored one (or, with none, the unset one) capped
// by the ceiling. A stored value that is not one of the setting's counts
// as none.
export function effectiveDeploymentSetting(key: DeploymentSettingKey, stored: string | null, ceiling: DeploymentSettingValue): DeploymentSettingValue {
  const chosen = stored !== null && isDeploymentSettingValue(key, stored) ? stored : deploymentSettingUnset(key, ceiling)
  return deploymentSettingRank(key, chosen) <= deploymentSettingRank(key, ceiling) ? chosen : ceiling
}

export type DeploymentSettingChange = "narrow" | "widen" | "same"

export function deploymentSettingChange(key: DeploymentSettingKey, from: DeploymentSettingValue, to: DeploymentSettingValue): DeploymentSettingChange {
  const delta = deploymentSettingRank(key, to) - deploymentSettingRank(key, from)
  return delta < 0 ? "narrow" : delta > 0 ? "widen" : "same"
}

// ---------------------------------------------------------------- words

export const DEPLOYMENT_SETTING_WORDS: Readonly<Record<DeploymentSettingKey, { title: string; values: Readonly<Record<string, string>> }>> = {
  workspace_creation: { title: "Workspace creation", values: { operator: "Only accounts an operator allows", accounts: "Every account" } },
  signup_mode: { title: "Sign-up", values: { invite: "Invitation only", request: "Request access", open: "Open" } },
}

export const DEPLOYMENT_SETTING_NOT_BUILT = "Not available yet."

export function deploymentSettingValueWords(key: DeploymentSettingKey, value: DeploymentSettingValue): string {
  return DEPLOYMENT_SETTING_WORDS[key].values[value] ?? value
}

// Why a wider value than the ceiling cannot be chosen, naming the deploy
// variable and what it says.
export function deploymentSettingCeilingWords(key: DeploymentSettingKey, ceiling: DeploymentSettingValue): string {
  return `This deploy allows at most ${deploymentSettingValueWords(key, ceiling)} (${DEPLOYMENT_SETTINGS[key].ceilingVar} is ${ceiling}); the deploy must allow more first.`
}
