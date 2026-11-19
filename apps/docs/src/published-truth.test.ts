import { expect, test } from "bun:test"
import { readdir } from "node:fs/promises"
import { resolve } from "node:path"
import { EXIT_FOR_LOCAL_ERROR } from "@mehen/protocol/api"

// Regressions for published claims that were corrected, read from the built public/ tree the
// Worker serves (index.test.ts proves the served twins are these bytes).
const PUBLIC = resolve(import.meta.dir, "../public")
const publicText = (file: string) => Bun.file(resolve(PUBLIC, file)).text()

const PIN_OUTDATED = "This host uses an outdated managed-agent configuration. Stop and contact the harness owner. Relay the refusal and its next step; do not edit the pin, identity files or launch environment yourself."

test("no published page carries the managed pin rewrite procedure", async () => {
  for (const file of ["skill.md", "reference/errors.md"]) expect(await publicText(file), file).toContain(PIN_OUTDATED)
  for (const file of ["skill.md", "changelog.md", "reference/errors.md", "concepts/machines.md", "llms-full.txt"]) {
    const text = await publicText(file)
    for (const recipe of ["rewrites the pin", "rewrite the pin", "as version 3", "version-2 map", "pin map is version 2", "privateCredentials` set to", "privateCredentials set to"]) {
      expect(text, `${file}: ${recipe}`).not.toContain(recipe)
    }
  }
  expect(await publicText("concepts/machines.md")).toContain("only the harness owner can repair it")
})

const TRUST_BOUNDARY = "Whoever can deploy vault code, write trusted account identity state or operate account recovery can take over the vault's trust boundary. The operator must restrict those powers independently of agent access. These pages do not establish current operator-machine isolation. Beyond Cloudflare's own durability, every workspace's stored data has Cloudflare's 30-day point-in-time recovery, and each workspace not managed by a platform also has a daily dump of the whole workspace, sealed under a key derived from the root key and kept in a separate bucket. Setting that bucket to refuse deletion for 30 days is a step in the operator's setup, and whether an account administrator can lift that lock is not established. A dump opens only with that root key and only as its own workspace, so it lets no one read what the root key does not already open. Where copies of the root key and of the dumps are kept off the host is not established here."

test("the operator's takeover power is stated, unverified custody is not", async () => {
  for (const file of ["security.md", "security/threat-model.md"]) expect(await publicText(file), file).toContain(TRUST_BOUNDARY)
  const full = await publicText("llms-full.txt")
  for (const claim of ["no agent reaches", "with an offline copy", "runs from a machine"]) expect(full, claim).not.toContain(claim)
  expect(await publicText("security/keys-and-signing.md")).toContain("possession of a root key and the stored ciphertext permits decryption")
  expect(await publicText("security/keys-and-signing.md")).toContain("not proof that a production key is provisioned today")
})

test("the byte-published guide and skill carry the corrected sentences", async () => {
  const guide = await publicText("guide.md")
  const skill = await publicText("skill.md")
  expect(guide).toBe(await Bun.file(resolve(import.meta.dir, "../../cli/src/guide.md")).text())
  const modes = "Relay and placeholder modes keep credential values off the agent's machine. Explicitly allowed lease mode delivers values to the child process. Requests marked for approval by policy, and protected runs, need an eligible human's passkey"
  const reuse = "Repeating the same open request from the same requester, with the same home and details, reuses its link without extending it. Other requests under that name conflict; `--new` replaces your own open request."
  for (const [file, text] of [["guide.md", guide], ["skill.md", skill]] as const) {
    expect(text, file).toContain(modes)
    expect(text, file).toContain(reuse)
  }
  expect(guide).toContain("Refusals include a reason. The CLI adds a next step where it can: a command, a human link or advice. Some problems need a human to repair the setup.")
  expect(guide).toContain("It sends no request upstream and creates no approval.")
  expect(guide).toContain("it is not a byte-for-byte copy of the upstream response")
  expect(skill).toContain("Check fetches public item metadata from the vault, evaluates base binding and policy locally, sends nothing upstream and creates no approval. It does not predict live permission to send.")
  expect(skill).toContain("usable by members within their machine scope; a guest's or team's machine needs an authorised project environment that references the credential")
  expect(skill).toContain("No MCP tool starts an enrolment, approves, revokes or freezes. `vault_wait` can finish an enrolment already started at the terminal.")
  const threat = await publicText("security/threat-model.md")
  expect(threat).toContain("A consuming app should draw a trusted vault card only for an ask from its own authenticated call, after checking exact origin, workspace and device context. Each app must enforce this boundary.")
  const full = await publicText("llms-full.txt")
  for (const stale of ["will ever give you one", "No command and no tool returns a secret value to you", "approves anything sensitive", "Every refusal says what to do", "for the same slug returns the same open link", "Asking again for the same slug", "(everyone in the workspace)", "advisory, sends nothing\n", "It sends nothing and creates nothing", "No tool approves, enrols", "does so only for an ask its own authenticated call raised", "such an app shows a card only for"]) {
    expect(full, stale).not.toContain(stale)
  }
})

test("standalone scrubbing claims carry the limits", async () => {
  const api = await publicText("guides/call-an-api.md")
  expect(api).toContain("The vault scrubs credential echoes in raw, URL-encoded, JSON-escaped and supported base64 forms. It cannot catch arbitrary transformations, and values shorter than six characters are not redacted. A detected echo flags the credential for review.")
  expect(api).not.toContain("Any echo of the secret in the response")
  expect(await publicText("security/threat-model.md")).toContain("For supported representations of values at least six characters long, get the echo past the scrubber")
})

test("run approval pages are described by what they display", async () => {
  const shown = "The approval page shows the project, environment, command arguments, variable names and which variables receive real values or placeholders. The request digest also binds the submitted remote, worktree and commit, but this page does not display those fields. Check the CLI's resolved context before requesting approval."
  for (const file of ["guides/approvals.md", "concepts/projects.md", "concepts/approvals.md"]) {
    const text = await publicText(file)
    expect(text, file).toContain(shown)
    expect(text, file).not.toContain("environment, remote, worktree, commit, every argument")
    expect(text, file).not.toContain("the command, environment, worktree and which variables")
  }
})

test("the generated CLI reference states the special parsers' exceptions", async () => {
  const cli = await publicText("reference/cli.md")
  expect(cli).toContain("These are Mehen's own exit codes. `mehen run` returns the child's exit code after a successful start; it is not limited to this table.")
  expect(cli).toContain("Standard commands accept the global flags `--json`, `--help`, `--no-qr`, `--workspace`. `run`, `env`, `init` and `mcp` have the command-specific exceptions described under")
  expect(cli).not.toContain("Every command also takes the global flags")
  expect(cli).not.toContain("Every command exits with one of these")
  for (const name of ["run", "env", "init", "mcp"]) {
    const section = cli.slice(cli.indexOf(`## \`${name}\``)).split("\n## ")[0] as string
    expect(section, name).toContain("Global flags: see the exceptions above")
    expect(section, name).not.toContain("the global flags apply")
  }
})

const TEXT_FILES = /\.(?:html|md|txt|json|xml|css|js)$/

test("no served file, generated or handwritten, names gmail-alex", async () => {
  const files = (await readdir(PUBLIC, { recursive: true })).filter((file) => TEXT_FILES.test(file))
  expect(files).toContain("reference/cli.json")
  expect(files).toContain("llms-full.txt")
  for (const file of files) expect(await publicText(file), file).not.toContain("gmail-alex")
  expect(await publicText("guides/oauth.md")).toContain("mehen connect google-gmail --name gmail-personal")
})

const RELEASE_KEY = "Installed release builds with a compiled trusted release key check for signed updates automatically; a build with no trusted key updates nothing."

test("self-update is qualified by the compiled release key", async () => {
  for (const file of ["guides/connect-one-workspace.md", "skill.md", "guide.md", "changelog.md"]) expect(await publicText(file), file).toContain(RELEASE_KEY)
  const full = await publicText("llms-full.txt")
  for (const stale of ["`mehen` keeps itself current", "a CLI that keeps itself current", "the machine keeps itself current", "`mehen` updates itself in the background"]) expect(full, stale).not.toContain(stale)
})

test("HMAC lease delivery and the incident command's reason", async () => {
  const credentials = await publicText("concepts/credentials.md")
  expect(credentials).toContain("An HMAC key cannot be used to sign through Mehen; if a human explicitly sets its ceiling to lease and the machine and run allow it, its key field can be delivered to the child.")
  expect(credentials).not.toContain("`hmac-key` and `ssh-key` items can be stored but not used")
  const incident = await publicText("guides/incident.md")
  for (const home of ["--home workspace", "--home project --project <prj_id>"]) expect(incident, home).toContain(`${home} --reason 'Rotate this credential after a machine compromise'`)
})

test("no fixed setup time, a conditional connect code, a neutral stylesheet", async () => {
  const full = await publicText("llms-full.txt")
  expect(full.toLowerCase()).not.toContain("three minutes")
  for (const file of ["index.md", "start/team.md"]) expect(await publicText(file), file).toContain("when available, a connect code")
  const css = await publicText("docs.css")
  for (const internal of ["apps/", "packages/", ".test.ts", "lane"]) expect(css, internal).not.toContain(internal)
  expect(css).toContain("/* role tokens: start */")
  expect(css).toContain("/* role tokens: end */")
  for (const licence of ["OFL-inter.txt", "OFL-fraunces.txt", "OFL-jetbrains-mono.txt"]) expect(await Bun.file(resolve(PUBLIC, "fonts", licence)).exists(), licence).toBe(true)
})

// Alex's decision of 29 October: the category line and the promise.
test("the category line and promise; the old slogan is on no served page", async () => {
  expect(await publicText("llms.txt")).toContain("> Access for agents. Use credentials without reading them.")
  const home = await publicText("index.html")
  expect(home).toContain('<p class="sub">Access for agents.</p>')
  expect(home).toContain('<meta property="og:title" content="Mehen: use credentials without reading them">')
  expect(home).toContain('<meta name="twitter:title" content="Mehen: use credentials without reading them">')
  const files = (await readdir(PUBLIC, { recursive: true })).filter((file) => TEXT_FILES.test(file))
  for (const file of files) {
    const text = await publicText(file)
    for (const old of ["never secrets", "credential vault and proxy"]) expect(text, `${file}: ${old}`).not.toContain(old)
  }
})

test("the docs serve the lander's social card", async () => {
  const docs = await Bun.file(resolve(PUBLIC, "og.jpg")).arrayBuffer()
  const web = await Bun.file(resolve(import.meta.dir, "../../web/public/og.jpg")).arrayBuffer()
  expect(Buffer.from(docs).equals(Buffer.from(web))).toBe(true)
})

// Regressions from the docs-live hunt of 30 October, read from the same
// built tree and checked against the code each sentence describes.

test("connect-one-workspace states the exit status --workspace gives a workspace this machine is not in", async () => {
  const guide = await publicText("guides/connect-one-workspace.md")
  expect(guide).toContain(`\`workspace_unknown\` (exit ${EXIT_FOR_LOCAL_ERROR.workspace_unknown})`)
  expect(guide).not.toContain("Not enrolled there is exit 6")
})

test("every docs page names the lander's touch icon, and the docs serve it", async () => {
  const docs = await Bun.file(resolve(PUBLIC, "apple-touch-icon.png")).arrayBuffer()
  const web = await Bun.file(resolve(import.meta.dir, "../../web/public/apple-touch-icon.png")).arrayBuffer()
  expect(Buffer.from(docs).equals(Buffer.from(web))).toBe(true)
  for (const file of ["index.html", "start.html", "404.html", "search.html"]) expect(await publicText(file), file).toContain('<link rel="apple-touch-icon" href="/apple-touch-icon.png">')
})

// `mehen workload` and the scoped enrolment flags came with 0.3.1; 0.3.0
// does not have them. Every page that tells a reader to run them says so,
// and the changelog records workloads.
test("pages naming mehen workload or the scoped enrolment flags say 0.3.0 does not have them", async () => {
  for (const file of ["concepts/machines.md", "guides/harnesses.md", "changelog.md"]) {
    const text = await publicText(file)
    expect(text, file).toContain("`mehen workload")
    expect(text, file).toMatch(/0\.3\.0[^.]* (has neither|does not have)/)
  }
  expect(await publicText("changelog.md")).toContain("### 29 October 2026: workloads, a key per task")
})

test("the 404 and search pages ask not to be indexed, as the lander's 404 does; content pages do not", async () => {
  for (const file of ["404.html", "search.html"]) expect(await publicText(file), file).toContain('<meta name="robots" content="noindex">')
  for (const file of ["index.html", "start.html", "reference/errors.html"]) expect(await publicText(file), file).not.toContain("noindex")
})
