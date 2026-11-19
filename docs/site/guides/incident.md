---
title: A machine or a key is compromised
question: What do I do, in what order?
section: guides
covers: both
order: 110
---

# A machine or a key is compromised

"Compromised" means a `software` key file was copied, or a machine (Secure Enclave or not) ran hostile code as the user, so someone else can sign as that machine. The numbered steps are for a workspace owner or admin; the machine's owner can do the first two for their own machine. A lost or stolen laptop or phone comes first, and is usually narrower.

## A lost or stolen device

End what was on that device, and only that:

1. **End its sign-in.** On your account page, under **Sessions**, press **End** on the browser or app that was on it. It is signed out at once. Your other sign-ins, and every mandate you signed, stay as they were.
2. **Remove its passkey.** If a passkey lived only on that device, remove it under **Passkeys** (a fresh passkey from another device). Like any security change, this lapses every mandate you signed until you resume each with your passkey.
3. **Revoke that machine**, if Mehen was enrolled on it: on each workspace's Machines page, with a passkey (it has one key per workspace). Its requests then fail with `device_revoked`, and its mandate lapses with it, so nothing goes through on trust from it again.
4. **Pause your other mandates** if you are worried: **Pause** on each one's page, or **Pause all** on the mandates page, which pauses every active mandate there you may pause. No passkey is needed. Resuming a mandate you signed and paused yourself needs none either, while nothing else has changed since you signed it.

If the device's key may have been used before you revoked it, carry on from [2. Scope](#2-scope). Keep **Sign out everywhere** for an account that may be stolen ([below](#if-your-account-may-be-stolen)).

## 1. Contain

If you are not sure which machine or how far it went, **freeze the workspace first**: "Freeze everything" on the workspace's home page, or `mehen freeze` from any other enrolled machine in it. No passkey is needed to freeze.

If the machine has a [mandate](../concepts/mandates.md), **pause it** on the mandates page or the machine's page, or **Pause all**: no passkey either. A pause stops it letting work through at once.

Then **revoke the machine** on the workspace's Machines page with a passkey. Its owner, an owner or an admin can; for a team's machine, an owner or admin. A key belongs to one workspace, so a leaked key reaches one workspace; a machine enrolled in several has one key per workspace, each to be revoked in its own.

From the machine itself, `mehen revoke --workspace <slug>` revokes it and removes that workspace's slot once the vault confirms. When the vault cannot be reached, `mehen workspace forget --slot <path>` retires the slot on the machine only, and the machine stays listed until someone revokes it on the Machines page.

A revoked machine's requests fail with `device_revoked`, and grants, [standing rules](standing-rules.md) and the mandate it held become unusable. Revocation and freeze stop subsequent uses through Mehen. They cannot recall an upstream request already sent, undo what happened at a provider, erase a value already leased, or revoke a credential at its provider; that is the next steps' work.

## 2. Scope

Read the audit chain ([Audit, review and freeze](../concepts/audit.md)) for the actor `device:<id>` from the earliest time the key could have leaked, as an owner or admin so nothing is filtered. Note every credential it used, in which mode, against which hosts, and any intakes, connects, runs, leases and approvals it asked for. A private credential's events carry no hosts or paths: ask its owner to check the provider's own logs. Local relay refusals are not in the chain.

## 3. Rotate what was exposed

- **Credentials the machine leased** (`run.lease` events): the value reached that machine. Rotate each at its provider, then replace it in the vault through an intake: from its credential page (an owner or admin, or a manager of its project), or `mehen request <kind> --name <slug> --home workspace --reason 'Rotate this credential after a machine compromise'` (or `mehen request <kind> --name <slug> --home project --project <prj_id> --reason 'Rotate this credential after a machine compromise'`) from another machine that may use it. Use the credential's actual kind and its current home.
- **Credentials it used in relay or placeholder mode**: the value never reached the machine. Rotation is not needed for the secret itself, but review what was done with it (the requests are in the audit) and undo what you can at the provider.

## 4. Review approvals, grants and rules

Deny anything pending that the machine asked for and you do not recognise, including a rule proposal. In the audit, `rule.use` events are the requests a standing rule let through without asking; read them with the rest. A mandate's page lists under **Went through on trust** every request it let through in the last 30 days, and on a shared credential each is also a `mandate.use` event. A mandate proposal has no deny: leave one you do not recognise unsigned, and it closes after 7 days. Stop the mandate if you will not resume it.

## 5. Look for persistence at the providers

New deploy keys, webhooks, OAuth apps, mail forwarding rules, API tokens. Templates deny or hold many of these, but check.

## 6. Clean the machine, or retire it

Then enrol a new key with `mehen enrol --workspace <slug>`. Never re-enable the old key.

## 7. Unfreeze

As an owner, with a passkey, once you are satisfied.

## 8. Write it down

What leaked, how, and what was rotated.

## If your account may be stolen

When someone may be able to act as you, not just hold one device, **Sign out everywhere** on the account page ends every browser and app session, this one included, and every 15-minute passkey window. It also lapses every mandate you signed: each covers nothing until you resume it with a fresh passkey. Your machines stay enrolled. Then check the passkeys, recovery codes and linked identities on the same page.

## Removing a person

Removing someone from a workspace (People, an owner or admin; an owner for an owner) revokes all their machines, deletes their private credentials, voids every approval they decided and records which credentials they had been exposed to, so the rotation list is in the audit. Suspending them stops their machines at once and keeps everything for reinstatement.

## If the vault itself may be compromised

If whoever can deploy the vault, or its root key, may be hostile, every secret should be assumed exposed: the [threat model](../security/threat-model.md#whoever-can-deploy-the-vault) explains why. That is your operator's incident, not a workspace's; rotate every credential at its provider.
