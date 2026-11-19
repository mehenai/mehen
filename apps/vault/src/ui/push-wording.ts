// The words for pushes (design push-providers 3.3 and 4), shared by the
// approval card, the credential page and the browser code: where a value
// goes, what the provider said about the place before anyone decided, how
// far a push got, and the credential page's allowance, Pushed to list,
// push again and delete lines. No DOM and no Worker APIs.

import type { PushApprovalView, PushDestination, PushPreview, PushProvider, PushRecordView } from "@mehen/protocol/push"
import { PUSH_PROVIDER_NAMES, formatTime } from "./wording.ts"

// "GitHub repository example/mehen, owned by the user example": the
// place, with its owner as the provider answered, never as the agent said.
export function pushWhereWords(d: PushDestination, preview: PushPreview | null): string {
  switch (d.provider) {
    case "github": {
      const repo = `GitHub repository ${d.owner}/${d.repo}`
      if (preview?.provider !== "github" || preview.owner === null) return repo
      const kind = preview.ownerType === "Organization" ? "the organisation " : preview.ownerType === "User" ? "the user " : ""
      return `${repo}, owned by ${kind}${preview.owner}`
    }
    case "vercel": {
      const name = preview?.provider === "vercel" ? preview.projectName : null
      return `Vercel project ${name ?? d.project}${d.team === null ? "" : ` in team ${d.team}`}`
    }
    case "cloudflare": {
      const account = preview?.provider === "cloudflare" ? preview.accountName : null
      return `Cloudflare Worker ${d.script} in account ${account ?? d.account}`
    }
    case "fly":
      return `Fly app ${d.app}`
  }
}

// Which store in that place, and what writing to it does there.
export function pushStoreWords(d: PushDestination): string {
  switch (d.provider) {
    case "github":
      return d.store === "environment" ? `Environment ${d.environment}, secret` : d.store === "dependabot" ? "Dependabot secret" : "Actions secret"
    case "vercel": {
      const target = d.target.charAt(0).toUpperCase() + d.target.slice(1)
      return `${target} variable (sensitive)`
    }
    case "cloudflare":
      return `Worker secret: Cloudflare deploys ${d.script} again`
    case "fly":
      return "App secret: staged until the next deploy"
  }
}

// Whether the name is already there, as the provider said before anyone
// decided.
export function pushExistsWords(preview: PushPreview | null): string {
  if (preview === null || preview.exists === null) return "Mehen could not check whether it exists."
  if (!preview.exists) return "Not there yet: this creates it."
  return preview.updatedAt !== null ? `Already there, updated ${formatTime(preview.updatedAt)}: this replaces it.` : "Already there: this replaces it."
}

// Who can read the value once it is there.
export function pushReadersWords(d: PushDestination): string {
  switch (d.provider) {
    case "github": {
      const repo = `${d.owner}/${d.repo}`
      if (d.store === "environment") return `Anyone who can run or change workflows in ${repo} that deploy to ${d.environment}.`
      if (d.store === "dependabot") return `Workflows Dependabot runs in ${repo}, and anyone who can change them.`
      return `Anyone who can run or change workflows in ${repo}.`
    }
    case "vercel":
      return `Anyone who can change or deploy the Vercel project ${d.project}, and its ${d.target} builds and functions.`
    case "cloudflare":
      return `The Worker ${d.script}, and anyone who can change or deploy it in this Cloudflare account.`
    case "fly":
      return `The app ${d.app}, and anyone who can deploy it or run commands on its machines.`
  }
}

export const PUSH_NEXT_WORDS = "Approving puts the value there now; the agent is told either way and never sees the value. Declining tells the agent no, and nothing is sent."

// How far an approved push got, after the decision. The vault keeps no
// reason a push was not sent on the approval, so that line is the same
// for every case.
export function pushOutcomeWords(push: Pick<PushApprovalView, "state" | "outcome" | "providerStatus">, provider: PushProvider): string | null {
  const name = PUSH_PROVIDER_NAMES[provider]
  switch (push.state) {
    case "pending":
      return null
    case "queued":
    case "sending":
      return `Sending: Mehen is putting it into ${name}.`
    case "done":
      return push.outcome === "created" || push.outcome === "replaced" ? `Put into ${name}: ${push.outcome}.` : `Put into ${name}.`
    case "failed":
      return push.providerStatus !== undefined ? `${name} refused it (${push.providerStatus}).` : `${name} refused it.`
    case "not_sent":
      return "Not sent: nothing was sent."
    case "unknown":
      return `Mehen could not confirm this push. Check ${name}.`
  }
}

// ---------------------------------------------------------------- the exact request

export const PUSH_HASH_HEADING = "What the hash covers"
export const PUSH_HASH_WORDS = "The body SHA-256 is the hash of these, with both credentials' ids and settings revisions, and the version of the one carrying it. The page does not show the exact JSON, because it names a credential's id."

// ---------------------------------------------------------------- the credential page

export const PUSH_ALLOWANCE_TITLE = "Other services' secret stores"
export const PUSH_ALLOWANCE_LABEL = "May be put into other services' secret stores"
export const PUSH_ALLOWANCE_WORDS = "An agent may then ask to put it into GitHub, Vercel or Cloudflare. Each push still waits for a person to approve it, and the agent never holds the value."
export const PUSH_ALLOWANCE_ON = "Allowed"
export const PUSH_ALLOWANCE_OFF = "Not allowed"
export const PUSH_ALLOWANCE_SAVE = "Save with passkey"

export const PUSHED_TO_TITLE = "Pushed to"
export const PUSH_AGAIN_TITLE = "Push the new value to the same places"
export const PUSH_AGAIN_WORDS = "These places still hold an older value. Tick each one to put the current value there; one passkey sends them all."
export const PUSH_AGAIN_BUTTON = "Push with passkey"
export const PUSH_AGAIN_CHOOSE_WORDS = "Tick at least one place."
export const PUSH_AGAIN_TOO_MANY_WORDS = "Tick at most 25 places; push the rest after."
export const PUSH_AGAIN_FOUR_EYES_WORDS = "Push this from a machine's ask, so a second person decides."
export const PUSH_AGAIN_ALLOWANCE_WORDS = "Allow it under Other services' secret stores first to push it again."
export const PUSH_AGAIN_VIA_UNSEEN_WORDS = "The credential that carried it is not one you can see, so it cannot be pushed again from here."
export const PUSH_AGAIN_CHANGED_WORDS = "This changed since the page loaded; review and try again."
export const PUSH_AGAIN_MAX = 25
export const PUSH_DELETE_WORDS = "Deleting removes it from Mehen only. The copies in these places stay where they are."
export const PUSH_OLDER_WORDS = "older than the current value"

// One record's outcome on the Pushed to list.
export function pushRecordStateWords(r: Pick<PushRecordView, "state" | "outcome" | "providerStatus">): string {
  switch (r.state) {
    case "done":
      return r.outcome === "created" ? "Created" : r.outcome === "replaced" ? "Replaced" : "Put there"
    case "failed":
      return r.providerStatus !== null ? `Refused (${r.providerStatus})` : "Refused"
    case "not_sent":
      return "Not sent"
    case "unknown":
      return "Not confirmed"
  }
}

// "version 7, older than the current value": the record's version, and
// whether the credential has moved on since.
export function pushRecordVersionWords(r: Pick<PushRecordView, "version" | "current">): string {
  return `version ${r.version}${r.current ? "" : `, ${PUSH_OLDER_WORDS}`}`
}

// The places a value may still be: a record that was put there, or that
// may have been.
export function pushHeldThere(r: Pick<PushRecordView, "state">): boolean {
  return r.state === "done" || r.state === "unknown"
}

// The places push again offers: the latest push there was done and holds
// an older version.
export function pushBehind(r: Pick<PushRecordView, "state" | "current">): boolean {
  return r.state === "done" && !r.current
}
