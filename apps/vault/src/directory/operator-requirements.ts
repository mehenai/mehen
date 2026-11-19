// What an operator account must have (OPERATOR_REQUIREMENTS in the
// protocol): recovery set up, at least two passkeys with one of them a
// security key, no cooling-off and no security change pending. Read for the
// pages and the plain refusal, and as one SQL predicate for the guard every
// operator batch starts with, so an account that lost one meanwhile writes
// nothing.

import { type OperatorRequirement, operatorRequirementsRefusal } from "@mehen/protocol"
import type { Env } from "../env.ts"
import { VaultError } from "../http.ts"
import { accountRecoveryReadySql } from "./account-recovery-setup.ts"

// Only source-owned SQL column references enter these expressions.
function livePasskeySql(passkey: string): string {
  return `NOT EXISTS (SELECT 1 FROM account_security_transitions t,json_each(t.removed_factors) f WHERE t.account=${passkey}.account AND t.state='pending' AND f.value=${passkey}.handle)`
}

// A security key as authenticatorWords (passkey-admin.ts) names one: USB,
// NFC or Bluetooth, and neither built into a device nor a phone by QR code.
export function securityKeySql(passkey: string): string {
  return `(EXISTS (SELECT 1 FROM json_each(COALESCE(${passkey}.transports,'[]')) t WHERE t.value IN ('usb','nfc','ble'))
    AND NOT EXISTS (SELECT 1 FROM json_each(COALESCE(${passkey}.transports,'[]')) t WHERE t.value IN ('internal','hybrid')))`
}

function passkeyCountSql(account: string, securityKeysOnly: boolean): string {
  return `(SELECT COUNT(*) FROM passkeys p WHERE p.account=${account} AND ${livePasskeySql("p")}${securityKeysOnly ? ` AND ${securityKeySql("p")}` : ""})`
}

// The predicate on the accounts row `a` that holds while it meets every
// requirement; binds one value, the time now.
export function operatorReadySql(a: string): string {
  return `(${accountRecoveryReadySql(`${a}.id`)} AND ${passkeyCountSql(`${a}.id`, false)}>=2 AND ${passkeyCountSql(`${a}.id`, true)}>=1
    AND ${a}.security_transition IS NULL AND (${a}.restricted_until IS NULL OR ${a}.restricted_until<=?))`
}

export type OperatorAccountFacts = { passkeys: number; securityKeys: number; recoveryReady: boolean; missing: OperatorRequirement[] }

export function missingOf(row: { recovery_ready: number; passkeys: number; security_keys: number; restricted_until: number | null; security_transition: string | null }, now: number): OperatorRequirement[] {
  const missing: OperatorRequirement[] = []
  if (row.recovery_ready !== 1) missing.push("recovery")
  if (row.passkeys < 2) missing.push("two-passkeys")
  if (row.security_keys < 1) missing.push("security-key")
  if (row.restricted_until !== null && row.restricted_until > now) missing.push("cooling-off")
  if (row.security_transition !== null) missing.push("security-change")
  return missing
}

// The columns missingOf reads, for the accounts row `a`.
export function operatorFactsColumns(a: string): string {
  return `${accountRecoveryReadySql(`${a}.id`)} AS recovery_ready,${passkeyCountSql(`${a}.id`, false)} AS passkeys,${passkeyCountSql(`${a}.id`, true)} AS security_keys,${a}.restricted_until,${a}.security_transition`
}

// An active account's facts, or null for one that is not active.
export async function operatorAccountFacts(env: Env, account: string, now = Date.now()): Promise<OperatorAccountFacts | null> {
  const row = await env.DB.prepare(`SELECT ${operatorFactsColumns("a")} FROM accounts a WHERE a.id=? AND a.status='active'`).bind(account).first<{ recovery_ready: number; passkeys: number; security_keys: number; restricted_until: number | null; security_transition: string | null }>()
  if (!row) return null
  return { passkeys: row.passkeys, securityKeys: row.security_keys, recoveryReady: row.recovery_ready === 1, missing: missingOf(row, now) }
}

export async function operatorRequirementsMissing(env: Env, account: string, now = Date.now()): Promise<OperatorRequirement[]> {
  return (await operatorAccountFacts(env, account, now))?.missing ?? []
}

// Refuses an operator write, before any passkey, from an account that lacks
// something, saying exactly what.
export async function requireOperatorReady(env: Env, account: string, now = Date.now()): Promise<void> {
  const missing = await operatorRequirementsMissing(env, account, now)
  if (missing.length > 0) throw new VaultError("forbidden", operatorRequirementsRefusal(missing), { next: { url: `${env.VAULT_ORIGIN}/account`, say: "Your account page shows your passkeys, your recovery and any cooling-off; come back once nothing is missing." } })
}
