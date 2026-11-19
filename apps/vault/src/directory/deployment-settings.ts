// The deployment settings (DEPLOYMENT_SETTINGS in the protocol): each
// deploy ceiling from its variable, the stored value, the value in force,
// and the two proposal kinds that change one (operator-proposal-kinds.ts
// runs them like every other kind).
//
// - settings.narrow applies at once, one operator with a passkey, only to
//   a value narrower than the one in force.
// - settings.widen is proposed and approved by two operators, only to a
//   value wider than the one in force and never past the deploy's ceiling.
// - Neither sets a value the vault does not do yet (deploymentSettingNotBuilt).
//   It names the value in force when proposed and applies only while that
//   is still the value in force.
// - A narrowing is a brake: it cancels every open widening of the same
//   setting, so an approval already on its way cannot undo it.
// Both are checked before any passkey and again in the batch, so a change
// made meanwhile (another operator narrowing first) never turns a narrowing
// into a widening or the other way round.
// Their deployment_events rows (proposal.open and applied) keep the terms'
// parameters, so the Audit view alone says what changed.

import { type DeploymentSettingKey, type DeploymentSettingValue, DEPLOYMENT_SETTING_NOT_BUILT, DEPLOYMENT_SETTING_WORDS, DeploymentSettingKeySchema, deploymentSettingCeiling, deploymentSettingCeilingWords, deploymentSettingChange, deploymentSettingNotBuilt, deploymentSettingRank, deploymentSettingUnset, deploymentSettingValues, deploymentSettingValueWords, effectiveDeploymentSetting, isDeploymentSettingValue, type OperatorProposalKind, type OperatorProposalTerms } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { accountGuard } from "./account-store.ts"
import type { OperatorKindHandler } from "./operator-proposal-kinds.ts"

const CEILING_VARS: Readonly<Record<DeploymentSettingKey, (env: Env) => string | undefined>> = {
  workspace_creation: (env) => env.WORKSPACE_CREATION,
  signup_mode: (env) => env.SIGNUP_MODE_MAX,
}

export function deploymentCeiling(env: Env, key: DeploymentSettingKey): DeploymentSettingValue {
  return deploymentSettingCeiling(key, CEILING_VARS[key](env))
}

export type StoredDeploymentSetting = { value: string; updated_at: number; updated_by: string }

export async function storedDeploymentSetting(env: Env, key: DeploymentSettingKey): Promise<StoredDeploymentSetting | null> {
  return env.DB.prepare("SELECT value,updated_at,updated_by FROM deployment_settings WHERE key=?").bind(key).first<StoredDeploymentSetting>()
}

export async function deploymentSetting(env: Env, key: DeploymentSettingKey): Promise<DeploymentSettingValue> {
  return effectiveDeploymentSetting(key, (await storedDeploymentSetting(env, key))?.value ?? null, deploymentCeiling(env, key))
}

// What a narrowing moves away from: the value in force, or the stored value
// when it is above a ceiling a later deploy lowered, so that value can be
// cleared before a deploy raises the ceiling again.
async function narrowingFrom(env: Env, key: DeploymentSettingKey): Promise<DeploymentSettingValue> {
  const ceiling = deploymentCeiling(env, key)
  const stored = (await storedDeploymentSetting(env, key))?.value ?? null
  if (stored !== null && isDeploymentSettingValue(key, stored) && deploymentSettingRank(key, stored) > deploymentSettingRank(key, ceiling)) return stored
  return effectiveDeploymentSetting(key, stored, ceiling)
}

// ---------------------------------------------------------------- the proposal kinds

// `from` is a widening's value in force when proposed; null for a narrowing.
type SettingTerms = { key: DeploymentSettingKey; value: DeploymentSettingValue; from: DeploymentSettingValue | null }

function settingValue(key: DeploymentSettingKey, raw: unknown): DeploymentSettingValue {
  const value = String(raw)
  if (!isDeploymentSettingValue(key, value)) throw new VaultError("bad_request", `${value} is not a value of ${key}: it is one of ${deploymentSettingValues(key).join(", ")}.`)
  return value
}

function settingTerms(terms: OperatorProposalTerms): SettingTerms {
  const key = DeploymentSettingKeySchema.parse(terms.target)
  return { key, value: settingValue(key, terms.params.value), from: terms.kind === "settings.widen" ? settingValue(key, terms.params.from) : null }
}

function title(key: DeploymentSettingKey): string {
  return DEPLOYMENT_SETTING_WORDS[key].title
}

function words(setting: SettingTerms): string {
  return `${title(setting.key)} is ${deploymentSettingValueWords(setting.key, setting.value)}`
}

// The stored value (or, with none, the unset one) still on the side of
// `value` this change moves away from, in the batch. The ceiling is the
// deploy's and cannot move within it.
function stillMoves(env: Env, setting: SettingTerms, direction: "narrow" | "widen"): D1PreparedStatement {
  const rank = deploymentSettingRank(setting.key, setting.value)
  const from = deploymentSettingValues(setting.key).filter((value) => (direction === "narrow" ? deploymentSettingRank(setting.key, value) > rank : deploymentSettingRank(setting.key, value) < rank))
  const unset = deploymentSettingUnset(setting.key, deploymentCeiling(env, setting.key))
  return accountGuard(env, `COALESCE((SELECT value FROM deployment_settings WHERE key=?),?) IN (${from.map(() => "?").join(",") || "NULL"})`, [setting.key, unset, ...from])
}

// The value in force still `inForce`, in the batch: the stored value (or
// the unset one) is `inForce`, or, when that is the ceiling, anything the
// ceiling caps to it.
function stillInForce(env: Env, key: DeploymentSettingKey, inForce: DeploymentSettingValue): D1PreparedStatement {
  const ceiling = deploymentCeiling(env, key)
  const stored = inForce === ceiling ? deploymentSettingValues(key).filter((value) => deploymentSettingRank(key, value) >= deploymentSettingRank(key, ceiling)) : [inForce]
  return accountGuard(env, `COALESCE((SELECT value FROM deployment_settings WHERE key=?),?) IN (${stored.map(() => "?").join(",")})`, [key, deploymentSettingUnset(key, ceiling), ...stored])
}

export const WIDENING_CANCELLED_REASON = "the setting was narrowed"

// Every open widening of `key` cancelled by `operator`'s narrowing: the
// proposal.cancel event and a notice to its proposer, then the row.
function cancelOpenWidenings(env: Env, key: DeploymentSettingKey, operator: string, now: number): D1PreparedStatement[] {
  const open = "FROM operator_proposals WHERE kind='settings.widen' AND target=? AND state='open'"
  return [
    env.DB.prepare(`INSERT INTO deployment_events(id,at,kind,actor,approver,target,details) SELECT 'dpe_' || lower(hex(randomblob(16))),?,'proposal.cancel',?,NULL,target,json_object('proposal',id,'kind',kind,'proposedBy','operator:' || proposed_by,'reason',?) ${open}`).bind(now, `operator:${operator}`, WIDENING_CANCELLED_REASON, key),
    env.DB.prepare(`INSERT INTO account_notices(id,account,kind,payload,at) SELECT 'ntc_' || lower(hex(randomblob(16))),proposed_by,'workspace',json_object('change','operator_proposal','event','cancelled','kind',kind,'target',target,'proposal',id,'by',?,'reason',?),? ${open}`).bind(`operator:${operator}`, WIDENING_CANCELLED_REASON, now, key),
    env.DB.prepare(`UPDATE operator_proposals SET state='cancelled',closed_at=? WHERE kind='settings.widen' AND target=? AND state='open'`).bind(now, key),
  ]
}

function settingHandler(direction: "narrow" | "widen"): OperatorKindHandler {
  return {
    async check(env, terms) {
      const setting = settingTerms(terms)
      const ceiling = deploymentCeiling(env, setting.key)
      const current = await deploymentSetting(env, setting.key)
      if (setting.from !== null && setting.from !== current) throw new VaultError("conflict", `${title(setting.key)} is ${deploymentSettingValueWords(setting.key, current)} now, not ${deploymentSettingValueWords(setting.key, setting.from)} as this widening says: read it again.`)
      const change = deploymentSettingChange(setting.key, direction === "narrow" ? await narrowingFrom(env, setting.key) : current, setting.value)
      if (change === "same") throw new VaultError("conflict", `${words(setting)} already.`)
      if (direction === "narrow" && change === "widen") throw new VaultError("forbidden", `That widens ${title(setting.key).toLowerCase()}, which needs a second operator: propose it instead.`)
      if (direction === "widen" && change === "narrow") throw new VaultError("bad_request", `That narrows ${title(setting.key).toLowerCase()}, which you do on your own with your passkey.`)
      if (deploymentSettingRank(setting.key, setting.value) > deploymentSettingRank(setting.key, ceiling)) throw new VaultError("forbidden", deploymentSettingCeilingWords(setting.key, ceiling))
      if (deploymentSettingNotBuilt(setting.key, setting.value)) throw new VaultError("forbidden", DEPLOYMENT_SETTING_NOT_BUILT)
    },
    guards(env, terms) {
      const setting = settingTerms(terms)
      return [stillMoves(env, setting, direction), ...(setting.from !== null ? [stillInForce(env, setting.key, setting.from)] : [])]
    },
    apply(env, terms, proposer, now) {
      const setting = settingTerms(terms)
      return {
        statements: [...(direction === "narrow" ? cancelOpenWidenings(env, setting.key, proposer, now) : []), env.DB.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES (?,?,CAST(unixepoch('subsec')*1000 AS INTEGER),?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at,updated_by=excluded.updated_by").bind(setting.key, setting.value, `operator:${proposer}`)],
        details: { params: terms.params },
      }
    },
    done: (_name, terms) => `Saved. ${words(settingTerms(terms))} now.`,
    proposed: (terms) => ({ params: terms.params }),
  }
}

export const DEPLOYMENT_SETTING_KIND_HANDLERS: Readonly<Record<Extract<OperatorProposalKind, `settings.${string}`>, OperatorKindHandler>> = {
  "settings.narrow": settingHandler("narrow"),
  "settings.widen": settingHandler("widen"),
}
