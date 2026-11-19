// Preview pages for the MCP Apps cards, for design work (not CI):
//
//   bun apps/cli/scripts/mcp-ui-preview.ts <out-dir>
//
// Writes one page per state and theme. Each page plays the host: the card in
// an <iframe sandbox="allow-scripts" srcdoc=...>, ui/initialize answered with
// openLinks and serverTools, the tool's input and result sent from a
// fixture, vault_ask_state answered from a script, ui/open-link and
// ui/update-model-context logged, and the frame sized from size-changed.
// With Google Chrome installed each page is also screenshotted to a PNG.

import { existsSync } from "node:fs"
import { mkdir, writeFile } from "node:fs/promises"
import { join, resolve } from "node:path"
import { type Ask, type AskUrl, adoptionAsk, approvalAsk, askUrl, connectAsk, intakeAsk, policyAsk, withContext } from "../src/ask.ts"
import type { ScanReport } from "../src/adopt/scan.ts"
import { ADOPT_CARD_HTML, ASK_CARD_HTML } from "../src/mcp/ui/documents.ts"

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

const out = process.argv[2]
if (!out) {
  console.error("usage: bun apps/cli/scripts/mcp-ui-preview.ts <out-dir>")
  process.exit(2)
}

const VAULT = { vaultUrl: "https://vault.example.com", workspaceSlug: "acme" }
const link = (path: string): AskUrl => (askUrl(`https://vault.example.com/w/acme${path}`, VAULT) as { url: AskUrl }).url
const by = { device: "office", session: "claude-desktop" }
const context = { origin: VAULT.vaultUrl, workspace: { id: "ten_1", slug: "acme", name: "Acme" }, device: "dev_1" }
const inMinutes = (n: number) => new Date(Date.now() + n * 60_000).toISOString()

const approval = (expiresAt = inMinutes(48)): Ask =>
  withContext(approvalAsk({ id: "apr_7Hq2", url: link("/a/apr_7Hq2"), summary: "Send an email to the billing list", bindingCode: "K7Q2MX", item: "gmail-work", account: "sam@example.com", expiresAt, requestedBy: by }), context)
const intake = withContext(intakeAsk({ id: "int_9Ld", url: link("/i/int_9Ld"), name: "openai-personal", kind: "api-key", provider: "openai", reason: "run the evaluation suite", expiresAt: inMinutes(23 * 60), requestedBy: by }), context)
const connect = withContext(connectAsk({ id: "con_4Rt", url: link("/c/con_4Rt"), name: "gmail-work", provider: "google-gmail", account: "sam@example.com", reason: "read the support inbox", expiresAt: inMinutes(14), requestedBy: by }), context)
const policy = withContext(policyAsk({ id: "pol_2Pw", url: link("/p/pol_2Pw"), summary: "Relax POST api.github.com/repos/** for an hour. No access has changed yet.", bindingCode: "P0LC7Z", expiresAt: inMinutes(55), requestedBy: by }), context)
const adoption = withContext(adoptionAsk({ id: "adp_5Xc", url: link("/b/adp_5Xc"), items: 14, machine: "office", expiresAt: inMinutes(22 * 60), requestedBy: by }), context)

const text = (value: unknown) => [{ type: "text", text: JSON.stringify(value, null, 2) }]
const result = (structuredContent: Record<string, unknown>, isError = false) => ({ content: text(structuredContent), structuredContent, isError })
const state = (id: string, value: string, message: string) => result({ id, kind: "approval", state: value, expiresAt: inMinutes(48), message })

const scan: ScanReport = {
  scan: "/Users/sam/.config/mehen/adopt/scan.json",
  files: 41,
  secrets: 23,
  distinct: 19,
  config: 30,
  unsupported: 4,
  folders: [
    { folder: "/Users/sam/code/billing-api", category: "repo", home: "project", secrets: 9, config: 6, unknown: 0, unsupported: 0, stale: 0 },
    { folder: "/Users/sam/code/web", category: "repo", home: "project", secrets: 5, config: 12, unknown: 1, unsupported: 0, stale: 1 },
    { folder: "/Users/sam/.local-secrets", category: "local-secrets", home: "private", secrets: 4, config: 0, unknown: 0, unsupported: 0, stale: 0 },
    { folder: "/Users/sam/.config/gh", category: "login", home: "private", secrets: 2, config: 0, unknown: 0, unsupported: 2, stale: 0 },
    { folder: "/Users/sam/code/infra/terraform/environments/production", category: "repo", home: "workspace", secrets: 3, config: 8, unknown: 0, unsupported: 0, stale: 0 },
    { folder: "/Users/sam/code/scratch", category: "repo", home: "project", secrets: 0, config: 4, unknown: 0, unsupported: 0, stale: 2 },
  ],
  errors: [{ path: "/Users/sam/old/exports/a.sh", lines: 3, first: 1, why: "not a KEY=value line" }],
  errorFiles: 86,
  unreadFolders: [
    { folder: "/Users/sam/old/exports", files: 85 },
    { folder: "/Users/sam/code/tmp", files: 1 },
  ],
  skipped: [{ path: "/Users/sam/code/link", why: "a symlink out of the root" }],
  skippedFiles: 3,
  next: { command: "mehen adopt plan --scan /Users/sam/.config/mehen/adopt/scan.json --json" },
}

// One preview: the card, the tool's input and result, and how vault_ask_state answers.
type Scenario = { name: string; card: string; input: Record<string, unknown>; result: unknown; askState?: Record<string, { afterMs: number; result: unknown }> }

const scenarios: Scenario[] = [
  { name: "ask-waiting", card: ASK_CARD_HTML, input: { kind: "api-key", name: "openai-personal" }, result: result({ intake: "int_9Ld", url: intake.url, kind: "api-key", name: "openai-personal", provider: "openai", ask: intake, next: {} }) },
  { name: "ask-turns-done", card: ASK_CARD_HTML, input: { action: "propose" }, result: result({ proposal: "pol_2Pw", item: "github-ci", status: "pending", bindingCode: "P0LC7Z", summary: "Relax", expiresAt: policy.expiresAt, outcome: null, url: policy.url, ask: policy, next: {}, warning: null }), askState: { pol_2Pw: { afterMs: 1500, result: state("pol_2Pw", "done", "The policy change was approved.") } } },
  { name: "ask-declined", card: ASK_CARD_HTML, input: {}, result: result({ connect: "con_4Rt", url: connect.url, provider: "google-gmail", client: "google-oauth-client", name: "gmail-work", account: "sam@example.com", ask: connect, next: {} }), askState: { con_4Rt: { afterMs: 300, result: state("con_4Rt", "mismatch", "Connection con_4Rt was signed in as other@example.com, not the expected one.") } } },
  { name: "ask-expired", card: ASK_CARD_HTML, input: {}, result: result({ error: "approval_required", message: "Approval required", next: {}, ask: approval(inMinutes(-5)) }, true) },
  { name: "pending-list", card: ASK_CARD_HTML, input: {}, result: result({ pending: [approval(), intake, connect] }), askState: { int_9Ld: { afterMs: 1200, result: state("int_9Ld", "done", "The credential was added to the vault.") }, con_4Rt: { afterMs: 900, result: state("con_4Rt", "declined", "The human cancelled it.") } } },
  { name: "error-with-ask", card: ASK_CARD_HTML, input: {}, result: result({ error: "approval_required", message: "Approval required to send an email to the billing list", next: { say: "Hand the human the link." }, approval: "apr_7Hq2", ask: approval() }, true), askState: { apr_7Hq2: { afterMs: 300, result: state("apr_7Hq2", "declined", "The human denied approval apr_7Hq2: Send an email to the billing list.") } } },
  { name: "policy-show-empty", card: ASK_CARD_HTML, input: { action: "show", item: "github-ci" }, result: result({ item: "github-ci", selector: { device: "dev_1", session: null }, policyMode: "standard" }) },
  { name: "adopt-scan", card: ADOPT_CARD_HTML, input: {}, result: result(scan as unknown as Record<string, unknown>) },
  { name: "adopt-status-open", card: ADOPT_CARD_HTML, input: { adoption: "adp_5Xc" }, result: result({ adoption: "adp_5Xc", status: "open", expiresAt: adoption.expiresAt, machines: [{ device: "dev_1", name: "office", items: 14 }, { device: "dev_2", name: "build-box", items: 3 }], url: adoption.url }) },
]

const THEMES = {
  light: { page: "#faf9f5", text: "#3d3929", variables: { "--font-sans": 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif', "--border-radius-lg": "14px" } },
  dark: { page: "#262624", text: "#c2c0b6", variables: { "--font-sans": 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif', "--border-radius-lg": "14px" } },
} as const

// A value inside the harness's own inline script: JSON with every < escaped.
const embed = (value: unknown) => JSON.stringify(value).replace(/</g, "\\u003c")

function harness(scenario: Scenario, theme: keyof typeof THEMES): string {
  const t = THEMES[theme]
  const host = {
    initialize: {
      protocolVersion: "2026-01-26",
      hostInfo: { name: "mehen-preview", version: "1" },
      hostCapabilities: { openLinks: {}, serverTools: {}, updateModelContext: { structuredContent: {} } },
      hostContext: { theme, displayMode: "inline", locale: "en-GB", styles: { variables: t.variables } },
    },
    input: scenario.input,
    result: scenario.result,
    askState: scenario.askState ?? {},
  }
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${scenario.name} (${theme})</title>
<style>
html{color-scheme:${theme}}
body{margin:0;padding:24px;background:${t.page};color:${t.text};font:13px/1.4 system-ui,sans-serif}
iframe{display:block;border:0;width:100%;max-width:592px;height:0}
#log{margin:14px 0 0;max-width:592px;font:11px/1.4 ui-monospace,Menlo,monospace;opacity:.7;white-space:pre-wrap}
</style></head>
<body>
<iframe id="card" sandbox="allow-scripts" title="${scenario.name}"></iframe>
<pre id="log"></pre>
<script>
const host = ${embed(host)};
const html = ${embed(scenario.card)};
const frame = document.getElementById("card");
const log = (line) => { document.getElementById("log").textContent += line + "\\n"; };
const post = (message) => frame.contentWindow.postMessage(message, "*");
window.addEventListener("message", (event) => {
  if (event.source !== frame.contentWindow) return;
  const m = event.data;
  if (m.method === "ui/initialize") post({ jsonrpc: "2.0", id: m.id, result: host.initialize });
  else if (m.method === "ui/notifications/initialized") {
    post({ jsonrpc: "2.0", method: "ui/notifications/tool-input", params: { arguments: host.input } });
    post({ jsonrpc: "2.0", method: "ui/notifications/tool-result", params: host.result });
  } else if (m.method === "ui/notifications/size-changed") {
    log("size-changed " + JSON.stringify(m.params));
    frame.style.height = m.params.height + "px";
  }
  else if (m.method === "tools/call") {
    log("tools/call " + m.params.name + " " + JSON.stringify(m.params.arguments));
    const scripted = host.askState[m.params.arguments.id];
    // Unscripted: the vault keeps the ask open, as a long poll would.
    if (scripted) setTimeout(() => post({ jsonrpc: "2.0", id: m.id, result: scripted.result }), scripted.afterMs);
  } else if (m.method === "ui/open-link") { log("ui/open-link " + m.params.url); post({ jsonrpc: "2.0", id: m.id, result: {} }); }
  else if (m.method === "ui/update-model-context") { log("ui/update-model-context " + JSON.stringify(m.params)); post({ jsonrpc: "2.0", id: m.id, result: {} }); }
});
frame.srcdoc = html;
</script>
</body></html>
`
}

await mkdir(out, { recursive: true })
const chrome = existsSync(CHROME)
for (const scenario of scenarios) {
  for (const theme of ["light", "dark"] as const) {
    const page = resolve(join(out, `${scenario.name}-${theme}.html`))
    await writeFile(page, harness(scenario, theme))
    if (!chrome) {
      console.log(page)
      continue
    }
    const png = page.replace(/\.html$/, ".png")
    // Without site isolation the sandboxed frame is painted in the page's
    // own process, so the screenshot shows it at the height the card reported.
    const shot = Bun.spawnSync([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--disable-site-isolation-trials", "--disable-features=site-per-process,IsolateOrigins", `--screenshot=${png}`, "--window-size=640,900", "--virtual-time-budget=4000", `file://${page}`], { stdout: "ignore", stderr: "pipe" })
    if (shot.exitCode !== 0) throw new Error(`Chrome could not screenshot ${page}: ${shot.stderr.toString()}`)
    console.log(png)
  }
}
