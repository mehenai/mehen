// The browser side of joining from an invitation, recovery setup and
// creating a workspace, with workspaces on. The invitation code is read once
// from the address's fragment, taken out of the address bar and kept in this
// tab's sessionStorage (mehen.oidc.invite), with the Google proof's result id
// (mehen.oidc.result) beside it, so a reload or the return from Google
// resumes at the same step. Account actions are signed through
// /api/account/stepup/start (step-up.ts), never the legacy /api/stepup.

import type { RecoveryCodesIssued } from "@mehen/protocol/api"
import type { AccountSession, WorkspaceRef, WorkspaceRole } from "@mehen/protocol/workspace"
import { type PublicKeyCredentialCreationOptionsJSON, startRegistration } from "@simplewebauthn/browser"
import { normaliseRecoveryCode } from "@mehen/protocol/recovery-code"
import { VaultFailure, api } from "../api.ts"
import { type Boot, all, el, find, inputValue, must, showError, withBusy } from "../dom.ts"
import { accountStepUp } from "../step-up.ts"
import { RECOVERY_POLL_MS, nextRecoveryPoll, sameOriginHref, waitForConfirmation } from "../confirmation-poll.ts"
import { formatTime } from "../../wording.ts"
import { type EmailCodeOffer, isEmailProof, proofBody, wireEmailCode } from "../email-code.ts"
import { INVITE_KEY } from "../oidc-logic.ts"
import { COPIED_FOR_MS } from "../wires.ts"

// ---------------------------------------------------------------- recovery

export const RECOVERY_CODES_FILE = "mehen-recovery-codes.txt"

// What Copy and Download hand over: the codes in the page's order, one a line.
export function recoveryCodesLines(codes: readonly string[]): string {
  return `${codes.join("\n")}\n`
}

function saveText(name: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }))
  const link = document.createElement("a")
  link.href = url
  link.download = name
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 60_000)
}

// Codes made and one typed back, or a second passkey: then `done`.
// `afterSignup`: /signup, where the vault makes an account's first codes
// without a passkey prompt for 15 minutes; when it says no, the step-up.
export function wireRecoveryStep(root: ParentNode, done: () => void, afterSignup = false): void {
  const make = must<HTMLButtonElement>('[data-action="make-codes"]', root)
  const second = must<HTMLButtonElement>('[data-action="add-second-passkey"]', root)
  const issued = must('[data-region="codes-issued"]', root)
  const list = must('[data-region="codes-list"]', root)
  const input = must<HTMLInputElement>('[data-input="codes-confirm"]', root)
  const error = must('[data-region="codes-error"]', root)
  const confirm = must<HTMLButtonElement>('[data-action="confirm-codes"]', root)
  const copy = must<HTMLButtonElement>('[data-action="copy-codes"]', root)
  const download = must<HTMLButtonElement>('[data-action="download-codes"]', root)
  let codes: readonly string[] = []
  const finished = () => {
    issued.hidden = true
    list.replaceChildren()
    codes = []
    must('[data-region="recovery-done"]', root).hidden = false
    done()
  }
  let batch: string | null = null
  const generate = async (): Promise<RecoveryCodesIssued> => {
    if (afterSignup) {
      try {
        return await api<RecoveryCodesIssued>("/api/account/recovery/generate", {})
      } catch (failure) {
        if (!(failure instanceof VaultFailure) || failure.body.error !== "forbidden") throw failure
      }
    }
    return api<RecoveryCodesIssued>("/api/account/recovery/generate", { stepUp: await accountStepUp({ type: "recovery.generate" }) })
  }
  make.addEventListener("click", () => {
    void withBusy(make, afterSignup ? "Making your codes..." : "Waiting for your passkey...", async () => {
      const reply = await generate()
      batch = reply.batch
      codes = reply.codes
      list.replaceChildren(...reply.codes.map((code) => el("li", null, code)))
      must('[data-region="codes-position"]', root).textContent = String(reply.confirmPosition)
      issued.hidden = false
      // Pressed again, it would replace the codes just written down.
      make.hidden = true
    })
  })
  copy.addEventListener("click", () => {
    if (codes.length === 0) return
    void navigator.clipboard.writeText(recoveryCodesLines(codes)).then(() => {
      const label = copy.querySelector("span") ?? copy
      const before = label.textContent
      label.textContent = "Copied"
      setTimeout(() => {
        label.textContent = before
      }, COPIED_FOR_MS)
    })
  })
  download.addEventListener("click", () => {
    if (codes.length > 0) saveText(RECOVERY_CODES_FILE, recoveryCodesLines(codes))
  })
  confirm.addEventListener("click", () => {
    const current = batch
    if (current === null) return
    const parsed = normaliseRecoveryCode(input.value)
    if (!parsed.ok) {
      error.textContent = parsed.reason === "typo" ? "That code has a typo. Check each group." : "Type the code in four groups of four."
      error.hidden = false
      return
    }
    error.hidden = true
    void withBusy(confirm, "Checking...", async () => {
      try {
        await api("/api/account/recovery/confirm", { batch: current, code: input.value })
        finished()
      } catch (failure) {
        if (!(failure instanceof VaultFailure) || failure.status === 0) throw failure
        error.textContent = failure.body.message
        error.hidden = false
      }
    })
  })
  second.addEventListener("click", () => {
    void withBusy(second, "Waiting for your passkey...", async () => {
      const stepUp = await accountStepUp({ type: "passkey.add" })
      const { options } = await api<{ options: PublicKeyCredentialCreationOptionsJSON }>("/api/account/passkeys/options", { stepUp, kind: "device" })
      const response = await startRegistration({ optionsJSON: options })
      await api("/api/account/passkeys/verify", { response, name: "Second passkey" })
      finished()
    })
  })
}

// ---------------------------------------------------------------- joining

// The cards a person goes through, in the vault's order. Only one shows.
const STEPS = ["signup-verify", "signup-passkey", "signup-recovery", "signup-join", "signup-waiting", "signup-invite-unknown", "signup-no-invite"] as const
type Step = (typeof STEPS)[number]

function showStep(step: Step): void {
  for (const s of STEPS) {
    const region = find(`[data-region="${s}"]`)
    if (region) region.hidden = s !== step
  }
  // The invitation's end date and "not expecting it" only before anything is created.
  const terms = find('[data-region="invite-terms"]')
  if (terms) terms.hidden = step !== "signup-verify" && step !== "signup-passkey"
  // The step list: the steps before this one done, this one current.
  const at = ["signup-verify", "signup-passkey", "signup-recovery", "signup-join"].indexOf(step === "signup-waiting" ? "signup-join" : step)
  all('[data-region="signup-invite"] .step').forEach((item, i) => {
    item.classList.toggle("done", at >= 0 && (i < at || step === "signup-waiting"))
    item.classList.toggle("current", at >= 0 && i === at && step !== "signup-waiting")
  })
}

export { INVITE_KEY }
export const RESULT_KEY = "mehen.oidc.result"
// The account id the vault returned for a bootstrap signup in this tab, so a
// reload before recovery is done resumes it. It only steers this page: the
// grant and recovery readiness are the vault's, and the marker is honoured
// only while /api/account names the same account.
export const BOOTSTRAP_KEY = "mehen.signup.bootstrap"

// POST /api/auth/invite/peek: the workspace and role, and whether the
// invitation is bound to one email (so needs the Google step or the emailed
// code, as emailCode says). No email.
type InvitePeek = { workspace: { name: string; slug: string }; role: WorkspaceRole; bound: boolean; emailCode: EmailCodeOffer; expiresAt: string }

type SignupStore = { invite: string | null; result: string | null; bootstrap: string | null; set(key: string, value: string): void; drop(key: string): void }

// The tab's sessionStorage, or this page's memory when storage is refused.
function signupStore(): SignupStore {
  const memory = new Map<string, string>()
  const read = (key: string): string | null => {
    try {
      return sessionStorage.getItem(key)
    } catch {
      return memory.get(key) ?? null
    }
  }
  const store: SignupStore = {
    invite: null,
    result: null,
    bootstrap: null,
    set(key, value) {
      memory.set(key, value)
      try {
        sessionStorage.setItem(key, value)
      } catch {
        // Kept in memory for this page only.
      }
      if (key === INVITE_KEY) store.invite = value
      if (key === RESULT_KEY) store.result = value
      if (key === BOOTSTRAP_KEY) store.bootstrap = value
    },
    drop(key) {
      memory.delete(key)
      try {
        sessionStorage.removeItem(key)
      } catch {
        // Nothing stored.
      }
      if (key === INVITE_KEY) store.invite = null
      if (key === RESULT_KEY) store.result = null
      if (key === BOOTSTRAP_KEY) store.bootstrap = null
    },
  }
  store.invite = read(INVITE_KEY)
  store.result = read(RESULT_KEY)
  store.bootstrap = read(BOOTSTRAP_KEY)
  return store
}

// The fragment once, then out of the address bar: #<code> is an invitation
// (a different one replaces the stored code and drops its proof); #oidc=<id>
// is the Google step's result for the stored invitation, and is dropped when
// no invitation is stored, so a proof is never sent without its invitation.
function readSignupFragment(store: SignupStore): void {
  let fragment = ""
  try {
    fragment = decodeURIComponent(location.hash.slice(1)).trim()
  } catch {
    fragment = ""
  }
  if (location.hash) history.replaceState(null, "", location.pathname + location.search)
  if (fragment.startsWith("oidc=")) {
    const result = fragment.slice("oidc=".length)
    if (store.invite !== null && result !== "") store.set(RESULT_KEY, result)
    return
  }
  if (fragment === "" || fragment === store.invite) return
  store.drop(RESULT_KEY)
  store.set(INVITE_KEY, fragment)
}

// The deployment's first account is created: the plain card stops saying
// the link may have expired and says what comes next.
function showBootstrapLead(): void {
  must('[data-region="signup-plain"]').hidden = false
  must('[data-region="signup-plain-lead"]').hidden = true
  must('[data-region="signup-first-lead"]').hidden = true
  must('[data-region="signup-bootstrap-lead"]').hidden = false
}

function forget(store: SignupStore): void {
  store.drop(RESULT_KEY)
  store.drop(INVITE_KEY)
  store.drop(BOOTSTRAP_KEY)
}

function fill(name: string, text: string): void {
  for (const node of all(`[data-fill="${name}"]`)) node.textContent = text
}

function roleWords(role: WorkspaceRole): string {
  return role === "owner" ? "an owner" : role === "admin" ? "an admin" : role === "guest" ? "a guest" : "a member"
}

const lapsed = (failure: unknown): failure is VaultFailure => failure instanceof VaultFailure && failure.body.error === "identity_required"

// Where the vault sends a membership just confirmed (Connect an agent, or
// the home while an identity check is due), only on this vault; the home
// when the vault cannot say.
async function onboardingPlace(workspace: WorkspaceRef): Promise<string> {
  const home = `/w/${encodeURIComponent(workspace.slug)}/`
  try {
    const { next } = await api<{ next: string }>(`/api/account/onboarding/${encodeURIComponent(workspace.id)}`)
    return sameOriginHref(next) ?? home
  } catch {
    return home
  }
}

// A reload after a bootstrap signup in this tab: only while the vault's
// /api/account names the account the signup returned does the page take it
// up again, at recovery while that is missing, else on to the workspaces.
// Signed out, or another account, the marker is dropped and nothing resumes.
async function resumeBootstrap(boot: Boot, store: SignupStore): Promise<void> {
  const marked = store.bootstrap
  const session = boot.signedIn === true ? await api<AccountSession>("/api/account") : null
  if (session === null || session.account !== marked) {
    store.drop(BOOTSTRAP_KEY)
    showStep("signup-no-invite")
    return
  }
  if (!session.recoverySetupRequired) {
    forget(store)
    location.assign("/workspaces")
    return
  }
  wireRecoveryStep(must('[data-region="signup-recovery"]'), () => {
    forget(store)
    location.assign("/workspaces")
  }, true)
  showBootstrapLead()
  showStep("signup-recovery")
}

export function initWorkspaceSignup(boot: Boot): void {
  const store = signupStore()
  readSignupFragment(store)
  const invite = store.invite
  if (invite === null || invite === "") {
    store.drop(RESULT_KEY)
    if (store.bootstrap !== null) {
      void resumeBootstrap(boot, store).catch(showError)
      return
    }
    showStep("signup-no-invite")
    return
  }
  // An invitation opened in this tab replaces an earlier bootstrap's marker.
  store.drop(BOOTSTRAP_KEY)
  const signedIn = boot.signedIn === true
  // A vault with no account yet has no invitation to peek at: the code can
  // only be its bootstrap code, which only the signup answers for.
  const firstAccount = boot.firstAccount === true
  let recoveryReady = boot.recoveryReady === true
  let peek: InvitePeek | null = null
  let bootstrap = false

  // Step 1: the Google proof of the invited email, before any passkey for a
  // new account and before joining for a signed-in one. `again`: a proof
  // the vault no longer accepts (lapsed after ten minutes, or the wrong one).
  const verify = (again: boolean) => {
    store.drop(RESULT_KEY)
    must('[data-region="verified"]').hidden = true
    must('[data-region="verify-lead"]').hidden = again
    must('[data-region="verify-lapsed"]').hidden = !again
    emailCode.show(peek?.emailCode ?? "off")
    showStep("signup-verify")
  }
  const verifyButton = must<HTMLButtonElement>('[data-action="verify-google"]')
  verifyButton.addEventListener("click", () => {
    void withBusy(verifyButton, "Opening Google...", async () => {
      const { url } = await api<{ url: string }>("/api/auth/oidc/google/start", { purpose: "invite", invite, next: "/signup" })
      location.assign(url)
    })
  })
  // The emailed code's proof is kept where Google's result is; the address
  // it proved is only known in this page view.
  let emailProved: string | null = null
  const emailCode = wireEmailCode(invite, (handle, address) => {
    store.set(RESULT_KEY, handle)
    emailProved = address
    void resume().catch(showError)
  })
  const proof = () => proofBody(store.result)

  // Step 4, automatic once recovery is ready; then the wait, unless the
  // invitation let the member straight in.
  const joinButton = must<HTMLButtonElement>('[data-action="join"]')
  const wait = () => {
    showStep("signup-waiting")
    const slug = peek?.workspace.slug
    if (slug !== undefined) waitForConfirmation(slug, must('[data-region="signup-waiting"]'), () => forget(store))
  }
  const enter = async (workspace: WorkspaceRef) => {
    const place = await onboardingPlace(workspace)
    forget(store)
    location.assign(place)
  }
  // An active membership enters at once; one that is not yet listed as
  // active waits as any joined membership does.
  const enterWhenActive = async () => {
    const session = await api<AccountSession>("/api/account")
    const member = session.memberships.find((m) => m.workspace.slug === peek?.workspace.slug)
    if (member?.status === "active") await enter(member.workspace)
    else wait()
  }
  const join = async () => {
    joinButton.hidden = true
    must('[data-region="join-working"]').hidden = false
    showStep("signup-join")
    let joined: { member: string; state: string }
    try {
      joined = await api<{ member: string; state: string }>("/api/account/invites/join", { code: invite, ...proof() })
    } catch (failure) {
      if (lapsed(failure)) {
        verify(true)
        if (failure.body.next?.url !== "/signup") showError(failure)
        return
      }
      must('[data-region="join-working"]').hidden = true
      joinButton.hidden = false
      throw failure
    }
    // The proof is spent; the code stays until the confirmation, so a reload
    // finds the membership and waits again.
    store.drop(RESULT_KEY)
    if (joined.state === "active") await enterWhenActive()
    else wait()
  }
  joinButton.addEventListener("click", () => {
    void withBusy(joinButton, "Joining...", join)
  })
  const afterRecovery = () => {
    if (bootstrap) {
      forget(store)
      location.assign("/workspaces")
      return
    }
    recoveryReady = true
    void join().catch(showError)
  }
  wireRecoveryStep(must('[data-region="signup-recovery"]'), afterRecovery, true)

  // Step 2: the passkey, for a new account.
  const form = must<HTMLFormElement>('[data-form="workspace-signup"]')
  const button = must<HTMLButtonElement>('[data-action="signup"]', form)
  const name = must<HTMLInputElement>('[data-input="name"]', form)
  const refresh = () => {
    button.disabled = name.value.trim() === ""
  }
  name.addEventListener("input", refresh)
  refresh()
  form.addEventListener("submit", (event) => {
    event.preventDefault()
    const chosen = name.value.trim()
    if (chosen === "") return
    void withBusy(button, "Creating your passkey...", async () => {
      try {
        const { options } = await api<{ options: PublicKeyCredentialCreationOptionsJSON }>("/api/auth/signup/options", { invite, name: chosen, ...proof() })
        const response = await startRegistration({ optionsJSON: options })
        const created = await api<{ account: string; onboarding: "bootstrap" | "join" | "break-glass"; recoveryReady: boolean }>("/api/auth/signup/verify", { invite, name: chosen, ...proof(), response })
        if (created.onboarding === "break-glass") {
          forget(store)
          location.assign("/account")
          return
        }
        // The deployment's first account (the operator's bootstrap code) has
        // no invitation to join: after recovery it goes to its workspaces.
        // Only the server's reply says which; the code is never inspected.
        // The code is spent, so it goes; the account id stays so a reload
        // comes back to recovery (resumeBootstrap).
        bootstrap = created.onboarding === "bootstrap"
        if (bootstrap) {
          forget(store)
          store.set(BOOTSTRAP_KEY, created.account)
          showBootstrapLead()
        }
        // A passkey that syncs is already a way back in: no recovery step.
        if (created.recoveryReady) afterRecovery()
        else showStep("signup-recovery")
      } catch (failure) {
        if (peek?.bound === true && lapsed(failure)) {
          verify(true)
          if (failure.body.next?.url !== "/signup") showError(failure)
          return
        }
        throw failure
      }
    })
  })

  // Where this browser is in the steps, worked out afresh on every load.
  const resume = async () => {
    if (firstAccount) peek = null
    else try {
      peek = await api<InvitePeek>("/api/auth/invite/peek", { code: invite })
    } catch (failure) {
      if (!(failure instanceof VaultFailure) || failure.body.error !== "not_found") throw failure
      peek = null
    }
    if (peek === null) {
      // Not a live invitation this account may use. Signed out it may be the
      // deployment's bootstrap code, which only the signup answers for.
      store.drop(RESULT_KEY)
      if (signedIn) {
        forget(store)
        showStep("signup-invite-unknown")
        return
      }
      must('[data-region="signup-plain"]').hidden = false
      showStep("signup-passkey")
      return
    }
    const invited = peek
    fill("workspace-name", invited.workspace.name)
    fill("invite-role", roleWords(invited.role))
    fill("invite-expiry", formatTime(invited.expiresAt))
    const first = find('[data-region="signup-invite"] .step')
    if (first) first.hidden = !invited.bound
    must('[data-region="signup-invite"]').hidden = false
    if (signedIn) {
      const session = await api<AccountSession>("/api/account")
      const member = session.memberships.find((m) => m.workspace.slug === invited.workspace.slug)
      if (member?.status === "active") {
        await enter(member.workspace)
        return
      }
      if (member !== undefined) {
        store.drop(RESULT_KEY)
        wait()
        return
      }
    }
    if (invited.bound) {
      const result = store.result
      if (result === null) {
        verify(false)
        return
      }
      if (isEmailProof(result)) {
        if (emailProved !== null) {
          fill("verified-email", emailProved)
          must('[data-region="verified"]').hidden = false
        }
      } else try {
        const checked = await api<{ identity: { email: string; name: string | null } }>("/api/auth/oidc/google/result", { result, purpose: "invite" })
        fill("verified-email", checked.identity.email)
        must('[data-region="verified"]').hidden = false
        // "Your name" starts as the name Google gave with the proof just
        // read, when it fits the field (64); the person can still change it.
        const google = typeof checked.identity.name === "string" ? checked.identity.name.trim() : ""
        if (name.value === "" && google !== "" && google.length <= 64) {
          name.value = google
          refresh()
        }
      } catch (failure) {
        if (!lapsed(failure)) throw failure
        verify(true)
        return
      }
    } else store.drop(RESULT_KEY)
    if (!signedIn) showStep("signup-passkey")
    else if (!recoveryReady) showStep("signup-recovery")
    else await join()
  }
  void resume().catch(showError)
}

// ---------------------------------------------------------------- account pages

export function initAccountRecovery(): void {
  const step = find('[data-region="recovery-step"]')
  if (step) wireRecoveryStep(step, () => undefined)
}

// The short name the workspace's name suggests: lower case, spaces to
// dashes, only letters, digits and single dashes, starting with a letter,
// at most 40; null when that leaves fewer than three characters.
export function suggestWorkspaceSlug(name: string): string | null {
  const slug = name
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9-]/g, "")
    .replace(/-+/g, "-")
    .replace(/^[^a-z]+/, "")
    .slice(0, 40)
    .replace(/-+$/, "")
  return slug.length >= 3 && !slug.startsWith("legacy-") ? slug : null
}

export function initWorkspaceCreate(): void {
  const form = find<HTMLFormElement>('[data-form="workspace-create"]')
  if (!form) return
  // Filled from the name as it is typed, until the person edits it.
  const nameInput = must<HTMLInputElement>('[data-input="workspace-name"]', form)
  const slugInput = must<HTMLInputElement>('[data-input="workspace-slug"]', form)
  let edited = slugInput.value !== ""
  slugInput.addEventListener("input", () => {
    edited = true
  })
  nameInput.addEventListener("input", () => {
    if (!edited) slugInput.value = suggestWorkspaceSlug(nameInput.value) ?? ""
  })
  form.addEventListener("submit", (event) => {
    event.preventDefault()
    const name = inputValue('[data-input="workspace-name"]', form).trim()
    const slug = inputValue('[data-input="workspace-slug"]', form).trim().toLowerCase()
    void withBusy(must<HTMLButtonElement>('button[type="submit"]', form), "Waiting for your passkey...", async () => {
      const stepUp = await accountStepUp({ type: "workspace.create", name, slug })
      const created = await api<WorkspaceRef>("/api/workspaces", { name, slug, stepUp })
      location.assign(`/w/${encodeURIComponent(created.slug)}/`)
    })
  })
}

// /recover/passkey while pending: ask the ceremony's own status until it
// commits (or ends), then reload so the server shows the passkey form or
// the ran-out page. The status grants nothing; the cookie stays the same and
// the code is never sent again. The status read shares the sign-in limiter
// (20 a minute per address), so a tab asks at most four times a minute; a
// failed read (rate limited, the vault or the network down) is shown, then
// retried later, after the vault's retryAfter when it gives one, with the
// wait doubling up to a few minutes. One timer at a time; only a definite
// "live" or "ended" reloads.
export function initRecoverPending(): void {
  let timer: ReturnType<typeof setTimeout> | undefined
  let failures = 0
  const schedule = (ms: number) => {
    clearTimeout(timer)
    timer = setTimeout(() => void poll(), ms)
  }
  const poll = async (): Promise<void> => {
    timer = undefined
    let state: string
    try {
      state = (await api<{ state: "live" | "pending" | "ended" }>("/api/auth/recovery/status")).state
    } catch (failure) {
      showError(failure)
      const retryAfter = failure instanceof VaultFailure ? failure.body.retryAfter : undefined
      schedule(nextRecoveryPoll(failures, retryAfter))
      failures += 1
      return
    }
    failures = 0
    if (state === "live" || state === "ended") {
      location.reload()
      return
    }
    schedule(RECOVERY_POLL_MS)
  }
  schedule(RECOVERY_POLL_MS)
}
