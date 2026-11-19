// The one client bundle: reads the page's boot payload and wires that page.

import { initOidc } from "./pages/oidc-verify.ts"
import { readBoot, showError } from "./dom.ts"
import { initAccount, initRecover, initRecoverPasskey, initSignin, initSignout } from "./pages/account.ts"
import { initConnect, initConnectWaiting } from "./pages/requests-connect.ts"
import { initIntake } from "./pages/requests-intake.ts"
import { initConnectAgent, initMachine, initPeople, initTeams } from "./pages/people.ts"
import { initAccountRecovery, initRecoverPending, initWorkspaceCreate, initWorkspaceSignup } from "./pages/account-setup.ts"
import { waitForConfirmation } from "./confirmation-poll.ts"
import { initNeedsBadge, initNeedsYou } from "./pages/needs-you.ts"
import { initWorkspaceCredential, initWorkspaceCredentials, initWorkspacePending, initWorkspaceProject, initWorkspaceProjects, needShell } from "./pages/workspace.ts"
import { initPolicyRules } from "./pages/policy-rules.ts"
import { initWorkspaceApproval, initWorkspaceConnect, initWorkspaceEnrol, initWorkspaceEnrolClosed, initWorkspaceIntake, initWorkspacePolicy, initWorkspaceRuleProposal } from "./pages/workspace-asks.ts"
import { initWorkspaceAreaProposal } from "./pages/workspace-asks.ts"
import { initWorkspaceSettings } from "./pages/workspace-settings.ts"
import { initWorkspaceAdoption } from "./pages/workspace-adopt.ts"
import { initWorkspaceReview } from "./pages/workspace-review.ts"
import { initOperatorPlatform, initOperatorRegister, initPlatformAdmin } from "./pages/console.ts"
import { initOperatorAcceptance, initOperatorOperators } from "./pages/operators.ts"
import { initOperatorWorkspace } from "./pages/operator-workspaces.ts"
import { initOperatorAccount } from "./pages/operator-accounts.ts"
import { initOperatorSettings } from "./pages/operator-settings.ts"
import { initPalette } from "./palette.ts"
import { initGetStarted, initMoreSheet, initShell } from "./shell.ts"
import { workspaceGoPlaces } from "./shortcut-keys.ts"
import { initShortcuts } from "./shortcuts.ts"
import { wireCopy, wireRings, wireTimes } from "./wires.ts"
import type { Boot } from "./dom.ts"
import type { ShellState } from "./shell-logic.ts"
import { initNudges } from "./pages/nudges.ts"
import { initMandate, initMandateControls, initMandateSign, initMandates } from "./pages/mandates.ts"

const PAGES: Record<string, (boot: Boot, shell: ShellState | null) => void> = {
  oidc: initOidc,
  account: () => {
    initAccount()
    initOperatorAcceptance()
  },
  signin: initSignin,
  recover: initRecover,
  "recover-passkey": initRecoverPasskey,
  intake: initIntake,
  connect: initConnect,
  "connect-waiting": initConnectWaiting,
  people: initPeople,
  teams: initTeams,
  machine: (boot, shell) => {
    initMachine(boot, shell)
    if (shell !== null) initMandateControls(shell)
  },
  mandate: initMandate,
  mandates: initMandates,
  "mandate-sign": initMandateSign,
  "connect-agent": initConnectAgent,
  "workspace-enrol": initWorkspaceEnrol,
  "enrol-closed": initWorkspaceEnrolClosed,
  "workspace-signup": initWorkspaceSignup,
  "account-recovery": initAccountRecovery,
  "workspace-create": initWorkspaceCreate,
  "recover-pending": initRecoverPending,
  "ws-projects": initWorkspaceProjects,
  "ws-project": initWorkspaceProject,
  "ws-credentials": initWorkspaceCredentials,
  "ws-credential": initWorkspaceCredential,
  "ws-my-rules": (_boot, shell) => initPolicyRules(needShell(shell)),
  "ws-approval": initWorkspaceApproval,
  "ws-pending": initWorkspacePending,
  "workspace-home": (boot, shell) => {
    initGetStarted()
    if (shell !== null) initWorkspacePending(boot, shell)
    if (shell !== null) initNudges(shell)
  },
  "needs-you": initNeedsYou,
  // The picker: the inline first workspace form, or the wait for an owner
  // or admin to confirm the account's one membership.
  workspaces: (boot) => {
    initWorkspaceCreate()
    const region = document.querySelector('[data-region="signup-waiting"]')
    if (typeof boot.waiting === "string" && region !== null) waitForConfirmation(boot.waiting, region)
  },
  "ws-intake": initWorkspaceIntake,
  "ws-connect": initWorkspaceConnect,
  "ws-adoption": initWorkspaceAdoption,
  "ws-review": initWorkspaceReview,
  "ws-policy": initWorkspacePolicy,
  "ws-rule-proposal": initWorkspaceRuleProposal,
  "ws-area-proposal": initWorkspaceAreaProposal,
  "workspace-settings": initWorkspaceSettings,
  "operator-register": initOperatorRegister,
  "operator-platform": initOperatorPlatform,
  "operator-operators": initOperatorOperators,
  "operator-workspace": initOperatorWorkspace,
  "operator-account": initOperatorAccount,
  "operator-settings": initOperatorSettings,
  "platform-admin": initPlatformAdmin,
}

function start(): void {
  const boot = readBoot()
  try {
    // First, so a stale tab refuses every call the page's wiring makes.
    const shell = initShell(boot)
    initSignout()
    wireCopy()
    const palette = initPalette(shell)
    initShortcuts(() => palette?.isOpen() ?? false, shell === null ? undefined : workspaceGoPlaces(shell.identity.workspace.slug, shell.identity.pages))
    initMoreSheet()
    PAGES[boot.page]?.(boot, shell)
    if (boot.page !== "needs-you") initNeedsBadge(boot, shell)
    wireTimes()
    // After the page's own wiring, so a ring already at zero on load reaches
    // the page's expiry listener.
    wireRings()
  } catch (error) {
    showError(error)
  }
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start)
else start()
