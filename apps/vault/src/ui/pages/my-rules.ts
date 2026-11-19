// The My rules page (/w/<slug>/rules), served only with POLICY_RULES on for
// the workspace: the live standing rules that touch the signed-in person
// (GET /policy/rules naming neither credential nor machine), with the Stop
// and Extend the credential and machine cards offer, which
// client/pages/policy-rules.ts wires.

import { pageHead } from "../components.ts"
import { html } from "../html.ts"
import type { PageInput } from "../layout.ts"
import { type PolicyRulesCardData, type RuleProjects, myRulesList } from "../policy-rules-list.ts"
import type { WorkspaceShell } from "../shell.ts"
import { MY_RULES_LEAD, MY_RULES_TITLE } from "../wording.ts"

export function myRulesPage(shell: WorkspaceShell, data: PolicyRulesCardData, projects: RuleProjects): PageInput {
  return {
    title: MY_RULES_TITLE,
    viewer: null,
    workspace: shell,
    current: "rules",
    boot: { page: "ws-my-rules" },
    body: html`${pageHead({ title: MY_RULES_TITLE, lead: MY_RULES_LEAD })}
      ${myRulesList(shell.identity.workspace.slug, data, projects)}`,
  }
}
