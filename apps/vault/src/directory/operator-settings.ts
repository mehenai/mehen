// The Settings view's read (OperatorSettingsView in the protocol): each
// deployment setting as it stands, the open proposals to change one and
// every change to them. Changes go through operator-proposals.ts.

import { ACCOUNT_ID, DEPLOYMENT_SETTING_KEYS, OPERATOR_SETTINGS_HISTORY, type OperatorProposalView, type OperatorSettingsView, effectiveDeploymentSetting, isDeploymentSettingValue } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { deploymentCeiling, storedDeploymentSetting } from "./deployment-settings.ts"
import { expireOperatorProposals, operatorCount, readOperatorProposal } from "./operator-proposals.ts"
import { operatorRequirementsMissing } from "./operator-requirements.ts"

function iso(ms: number): string {
  return new Date(ms).toISOString()
}

async function accountName(env: Env, actor: string | null): Promise<string | null> {
  const account = actor?.startsWith("operator:") ? actor.slice("operator:".length) : null
  if (account === null || !ACCOUNT_ID.test(account)) return null
  return (await env.DB.prepare("SELECT name FROM accounts WHERE id=?").bind(account).first<{ name: string }>())?.name ?? null
}

// The settings' own events: their changes, by the app or the script, and
// the proposals to change them.
const SETTINGS_EVENTS = "kind GLOB 'settings.*' OR (kind GLOB 'proposal.*' AND json_extract(details,'$.kind') GLOB 'settings.*')"

export async function operatorSettingsView(env: Env, you: string, now = Date.now()): Promise<OperatorSettingsView> {
  await expireOperatorProposals(env, now)
  const [operators, missing, open, history] = await Promise.all([
    operatorCount(env),
    operatorRequirementsMissing(env, you, now),
    env.DB.prepare("SELECT id FROM operator_proposals WHERE state='open' AND kind GLOB 'settings.*' ORDER BY proposed_at,id").all<{ id: string }>(),
    env.DB.prepare(`SELECT id,at,kind,actor,approver,target,details FROM deployment_events WHERE ${SETTINGS_EVENTS} ORDER BY at DESC,id DESC LIMIT ?`).bind(OPERATOR_SETTINGS_HISTORY).all<{ id: string; at: number; kind: string; actor: string; approver: string | null; target: string; details: string }>(),
  ])
  const settings = await Promise.all(DEPLOYMENT_SETTING_KEYS.map(async (key) => {
    const stored = await storedDeploymentSetting(env, key)
    const ceiling = deploymentCeiling(env, key)
    const value = stored !== null && isDeploymentSettingValue(key, stored.value) ? stored.value : null
    return { key, value: effectiveDeploymentSetting(key, value, ceiling), stored: value, ceiling, updatedAt: stored ? iso(stored.updated_at) : null, updatedBy: stored?.updated_by ?? null, updatedByName: await accountName(env, stored?.updated_by ?? null) }
  }))
  const proposals = (await Promise.all(open.results.map((row) => readOperatorProposal(env, row.id)))).filter((p): p is OperatorProposalView => p !== null)
  return {
    you,
    operators,
    missing,
    settings,
    open: proposals,
    history: history.results.map((row) => ({ id: row.id, at: iso(row.at), kind: row.kind, actor: row.actor, approver: row.approver, target: row.target, details: JSON.parse(row.details) as Record<string, unknown> })),
  }
}
