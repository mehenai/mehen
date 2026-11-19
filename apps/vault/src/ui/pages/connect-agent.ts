// /w/:ws/connect-agent: where an invited person lands once they are
// active, and where anyone goes to add an agent. One line to give any
// agent, and the three commands to run by hand.
// What can be copied carries only the workspace's checked slug, the vault's
// origin and a connect code in the issuer's alphabet (agentSetup): the
// display name is someone's free text (quotes, newlines, a command, a URL)
// and appears only in the page around them, never in what is copied.
//
// The page is a GET and writes nothing. Its client asks the connect-code
// issuer (POST /api/w/:ws/connect-code) on load; until it answers, the two
// boxes a code would change are disabled with "Getting your connect code".
// Any refusal, including a vault that does not issue codes yet, leaves the
// boxes as served: without --connect, which works through the owner and
// admin path. So the code is offered only by a vault that issues one
// (MANIFEST section 7 step 6), and every box parses as printed either way.

import { agentSetup } from "../client/people-logic.ts"
import { cardText, notice, pageHead, timeTag } from "../components.ts"
import { type Html, html } from "../html.ts"
import { icon } from "../icons.ts"
import type { PageInput } from "../layout.ts"
import type { WorkspaceShell } from "../shell.ts"
import { identityLine, workspaceHref } from "../shell.ts"

// What the client found out about a connect code. The route always serves
// "waiting"; the gallery renders the other two as the client leaves them.
export type ConnectCodeState = { state: "waiting" } | { state: "issued"; code: string; expiresAt: string } | { state: "refused"; say: string | null }

export const CONNECT_CODE_WAITING = "Getting your connect code"
export const CONNECT_CODE_WORDS = "The code sends this machine's approval to your own Needs you; it approves nothing by itself."

// A copy box as copyBox() draws it, inside a wrapper the client finds it by,
// with its Copy button disabled while the code is outstanding.
function connectBox(name: string, value: string, waiting: boolean, caption?: Html): Html {
  return html`<div class="connect-box" data-box="${name}"><div class="copybox"><code>${value}</code><button type="button" class="btn secondary sm" data-copy${waiting ? html` disabled` : ""}>${icon("copy")}<span>Copy</span></button></div>${caption !== undefined ? html`<p class="copybox-caption">${caption}</p>` : ""}</div>`
}

export function connectAgentPage(shell: WorkspaceShell, code: ConnectCodeState = { state: "waiting" }): PageInput {
  const identity = shell.identity
  const issued = code.state === "issued" ? code : null
  const setup = agentSetup(identity.origin, identity.workspace.slug, issued?.code ?? null)
  const base = { title: "Connect an agent", viewer: null, workspace: shell, current: "connect-agent" as const, boot: { page: "connect-agent" } }
  if (setup === null) {
    return { ...base, body: html`${pageHead({ title: "Connect an agent" })}<section class="card">${notice("warn", "Nothing to copy", "This workspace's address cannot be put into a command safely, so nothing is offered to copy. Ask an owner to check the workspace's short name.")}</section>` }
  }
  const waiting = code.state === "waiting"
  const name = cardText(identity.workspace.name)
  return {
    ...base,
    body: html`${pageHead({
      title: "Connect an agent",
      lead: html`Paste the line below into any agent: Claude Code, Codex, Cursor, pi or another MCP client. It installs or updates Mehen, enrols this machine in ${identityLine(identity)} and asks you to approve it here. It never needs your passkey, your invitation or a secret.`,
    })}
      <section class="card" data-region="agent-prompt"><h2>Tell your agent</h2>
        ${connectBox("prompt", setup.prompt, waiting)}
        <p class="small muted" data-region="connect-code-waiting" role="status"${waiting ? "" : html` hidden`}>${CONNECT_CODE_WAITING}</p>
        <p class="small" data-region="connect-code-note"${issued === null ? html` hidden` : ""}>${CONNECT_CODE_WORDS} It lasts a day, until <span data-region="connect-code-expiry">${issued !== null ? timeTag(issued.expiresAt) : ""}</span>.</p>
        <p class="small muted" data-region="connect-code-refused"${code.state === "refused" && code.say !== null ? "" : html` hidden`}>${code.state === "refused" && code.say !== null ? cardText(code.say) : ""}</p>
      </section>
      <section class="card" data-region="agent-next"><h2>What happens next</h2>
        <p>Your agent gives you a link and a fingerprint of four groups. Open the link (with your connect code in the line, it also waits under your Needs you), type the group the page hides from your agent's message, check what the machine may use, and approve with your passkey. Then restart the agent once so its Mehen tools load; the command line works straight away.</p>
      </section>
      <section class="card" data-region="agent-another"><h2>Already connected to another workspace?</h2>
        <p>Give the agent the same line. This machine joins ${name} as well and keeps the other.</p>
      </section>
      <details class="card fold" data-region="agent-commands"><summary>${icon("chevronRight")}<span>Or run it yourself</span></summary>
        ${connectBox("install", setup.install, false, html`First time on this machine only; an installed Mehen keeps itself current.`)}
        ${connectBox("setup", setup.setup, false, html`Registers Mehen in the supported agents it finds for this user. For another MCP client, add <code>--mcp-file</code> with the path of its JSON configuration, then check the workspace it serves.`)}
        ${connectBox("enrol", setup.enrol, waiting, html`To name the machine, add <code>--name my-laptop</code>. It prints a link, the fingerprint and an <code>enr_</code> id. Approve here, then run <code>mehen wait enr_...</code> to finish.`)}
        <p class="small muted">A guest's machine also needs an owner, an admin or a manager of the shared project to admit it.</p>
      </details>
      <p><a class="btn secondary" href="${workspaceHref(identity.workspace.slug, "/devices")}">${icon("cpu")}<span>Machines</span></a></p>`,
  }
}
