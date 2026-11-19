import type { ErrorCode, NextStep } from "@mehen/protocol/api"
import type { WorkspaceEnrolStatus } from "@mehen/protocol/workspace"

export type RefusalFields = {
  // internal also when the vault answered a code this client does not know.
  code: ErrorCode
  // The vault's own code when this client does not know it (a newer vault).
  rawCode?: string
  status: number
  message: string
  next?: NextStep
  // next.url, resolved against the vault's origin and checked to be on it:
  // the absolute URL of the page a person opens.
  link?: string
  approval?: string
  bindingCode?: string
  expiresAt?: string
  retryAfter?: number
  deciders?: string[]
  choices?: { slug: string; account: string | null }[]
  // Only on the enrolment renew route's settled 409.
  enrolment?: WorkspaceEnrolStatus
}

// The vault answered with its own refusal (Mehen-Error: 1). Retrying the
// same request will not help unless `next` or `retryAfter` says otherwise.
export class MehenRefusal extends Error {
  override readonly name = "MehenRefusal"
  readonly code: ErrorCode
  readonly rawCode?: string
  readonly status: number
  readonly next?: NextStep
  readonly link?: string
  readonly approval?: string
  readonly bindingCode?: string
  readonly expiresAt?: string
  readonly retryAfter?: number
  readonly deciders?: string[]
  readonly choices?: { slug: string; account: string | null }[]
  readonly enrolment?: WorkspaceEnrolStatus

  constructor(fields: RefusalFields) {
    super(fields.message)
    this.code = fields.code
    if (fields.rawCode !== undefined) this.rawCode = fields.rawCode
    this.status = fields.status
    if (fields.next !== undefined) this.next = fields.next
    if (fields.link !== undefined) this.link = fields.link
    if (fields.approval !== undefined) this.approval = fields.approval
    if (fields.bindingCode !== undefined) this.bindingCode = fields.bindingCode
    if (fields.expiresAt !== undefined) this.expiresAt = fields.expiresAt
    if (fields.retryAfter !== undefined) this.retryAfter = fields.retryAfter
    if (fields.deciders !== undefined) this.deciders = fields.deciders
    if (fields.choices !== undefined) this.choices = fields.choices
    if (fields.enrolment !== undefined) this.enrolment = fields.enrolment
  }
}

// network: the request never got an answer (DNS, TLS, reset, refused).
// timeout: no complete answer within the client's timeout.
// unexpected: an answer arrived that is not the vault's: a non-Mehen error
// page, a body that does not parse, or a link off the vault's origin.
export type TransportReason = "network" | "timeout" | "unexpected"

// No usable answer from the vault. Whether the vault acted on the request is
// unknown: a relayed request may have reached its upstream.
export class MehenTransport extends Error {
  override readonly name = "MehenTransport"
  readonly reason: TransportReason
  readonly status?: number

  constructor(reason: TransportReason, message: string, status?: number) {
    super(message)
    this.reason = reason
    if (status !== undefined) this.status = status
  }
}
