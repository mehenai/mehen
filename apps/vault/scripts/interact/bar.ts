// The decision bar's interaction scenarios: both
// actions inside the viewport and unclipped, the bar clear of the last
// card, the keyboard reaching both, a disabled accepting action doing
// nothing. scripts/ui-interact.ts runs them, at 360 and 390 px.
//
// The pages are the asks gallery's own fixtures: the unwarned and warned
// approvals and the enrolment page. Their digests and checks are fixtures,
// so the accepting action stays off on its own; a scenario that needs it on
// to walk the focus order turns it on itself, after the disabled checks.
// The gallery's origin is not the local server's, so the geometry
// scenarios run without a workspace shell and their decision handlers stay
// unwired; they prove the bar's geometry and the keyboard.
//
// The wired scenarios then make the page the vault would serve:
// they point the shell at this origin, answer the API from the scenario
// and stand in for the passkey prompt, and load the client bundle again so
// the real handlers wire up. Nothing is turned on by hand: the approval's
// digest matches and its code is ticked, the enrolment's group is typed
// and hashes to the page's check. Each scenario then drives pointer and
// keyboard, Enter in the decision form, an attempt in flight, a vault
// action the page did not show, and the exact one.

import type { WorkspaceApprovalView, WorkspaceEnrolView, WorkspaceStepUpAction } from "@mehen/protocol/workspace"
import { fingerprintGroupCheck, fingerprintGroups, fingerprintOf, fingerprintWords } from "@mehen/protocol/fingerprint"
import { type ConnectTerms, connectStartExpected } from "../../src/ui/client/ask-logic.ts"
import { digestOf } from "../../src/ui/client/logic.ts"
import type { PageInput } from "../../src/ui/layout.ts"
import { approvalSubjectOf, workspaceApprovalPage } from "../../src/ui/pages/workspace-asks.ts"
import { enrolmentPage } from "../../src/ui/pages/workspace-enrol.ts"
import { PEOPLE_PROJECTS, THUMBPRINT, peopleShell } from "../../src/ui/people-gallery.ts"
import { PEOPLE_ENROL_BY_ID, galleryRunApproval, workspaceAsksGallery } from "../../src/ui/workspace-asks-gallery.ts"
import { galleryShell } from "../../src/ui/workspace-projects-gallery.ts"
import type { InteractPage, InteractScenario } from "../ui-interact.ts"

function galleryPage(id: string): () => PageInput {
  return () => {
    const found = workspaceAsksGallery().find((e) => e.id === id)
    if (found === undefined) throw new Error(`interact: no asks gallery entry ${id}`)
    return found.page
  }
}

function check(ok: boolean, message: string): void {
  if (!ok) throw new Error(message)
}

type Box = { action: string; emphasised: boolean; left: number; right: number; top: number; bottom: number; clipped: boolean }

// Every button in the bar, where it is and whether its label is cut.
async function barButtons(page: InteractPage): Promise<{ buttons: Box[]; width: number; height: number; barTop: number }> {
  return page.evaluate(`(() => {
    const bar = document.querySelector('[data-region="bar"]');
    if (!bar) throw new Error("no decision bar");
    const buttons = Array.from(bar.querySelectorAll("button.btn")).map((b) => {
      const r = b.getBoundingClientRect();
      return { action: b.dataset.action, emphasised: b.classList.contains("primary") || b.classList.contains("danger"), left: r.left, right: r.right, top: r.top, bottom: r.bottom, clipped: b.scrollWidth > b.clientWidth + 1 || b.scrollHeight > b.clientHeight + 1 };
    });
    return { buttons, width: innerWidth, height: innerHeight, barTop: bar.getBoundingClientRect().top };
  })()`)
}

// Both actions inside the viewport, neither label cut, and the emphasised
// one on the right, or lowest when the two stack.
async function inView(page: InteractPage, expected: readonly string[]): Promise<void> {
  const { buttons, width, height } = await barButtons(page)
  check(JSON.stringify(buttons.map((b) => b.action)) === JSON.stringify(expected), `the bar holds ${buttons.map((b) => b.action).join(", ")}, not ${expected.join(", ")}`)
  for (const b of buttons) {
    check(b.left >= 0 && b.right <= width + 0.5, `${b.action} runs outside the viewport (${b.left}..${b.right} of ${width})`)
    check(b.top >= 0 && b.bottom <= height + 0.5, `${b.action} is below the fold of the viewport (${b.bottom} of ${height})`)
    check(!b.clipped, `${b.action} clips its label`)
  }
  emphasisLast(buttons)
}

function emphasisLast(buttons: readonly Box[]): void {
  const strong = buttons.find((b) => b.emphasised)
  if (strong === undefined) return
  for (const other of buttons.filter((b) => b !== strong)) {
    // One row when their boxes overlap vertically: a label on two lines
    // makes one button taller, centred against the other.
    const sameRow = other.top < strong.bottom && strong.top < other.bottom
    check(sameRow ? strong.left > other.left : strong.top > other.top, `${strong.action} is not ${sameRow ? "on the right" : "lowest"} of the bar`)
  }
}

// Scrolled to the end, the last card's foot is above the bar.
async function clearOfLastCard(page: InteractPage): Promise<void> {
  const gap = await page.evaluate<{ last: number; barTop: number }>(`(() => {
    window.scrollTo(0, document.documentElement.scrollHeight);
    const bar = document.querySelector('[data-region="bar"]');
    const main = document.querySelector("main");
    const shown = Array.from(main.children).filter((el) => el !== bar && !bar.contains(el) && el.getBoundingClientRect().height > 0);
    const last = Math.max(...shown.map((el) => el.getBoundingClientRect().bottom));
    return { last, barTop: bar.getBoundingClientRect().top };
  })()`)
  check(gap.last <= gap.barTop + 0.5, `the bar covers the last card (its foot at ${gap.last}, the bar at ${gap.barTop})`)
}

// Records the page's own calls, so a key that should do nothing is seen
// doing nothing.
const RECORD_CALLS = `(() => {
  window.__calls = [];
  const original = window.fetch.bind(window);
  window.fetch = (input, init) => { window.__calls.push(String(input)); return original(input, init); };
  return true;
})()`

async function active(page: InteractPage): Promise<string> {
  return page.evaluate<string>(`document.activeElement?.dataset?.action ?? document.activeElement?.tagName ?? ""`)
}

// Enter with the disabled accepting action as the target does nothing: it
// cannot take focus, nothing is sent and the page stays as it was.
async function disabledDoesNothing(page: InteractPage, accept: string): Promise<void> {
  await page.evaluate(RECORD_CALLS)
  const before = await page.evaluate<{ href: string; notice: string }>(`({ href: location.href, notice: document.querySelector("#notice")?.textContent?.trim() ?? "" })`)
  await page.evaluate(`(() => { document.activeElement?.blur?.(); document.querySelector('[data-action="${accept}"]').focus(); return true })()`)
  check((await active(page)) !== accept, `the disabled ${accept} took focus`)
  await page.press("Enter")
  const after = await page.evaluate<{ href: string; calls: string[]; disabled: boolean; notice: string }>(`({ href: location.href, calls: window.__calls, disabled: document.querySelector('[data-action="${accept}"]').disabled, notice: document.querySelector("#notice")?.textContent?.trim() ?? "" })`)
  check(after.href === before.href, "Enter on the disabled action navigated")
  check(after.disabled, `${accept} turned on by itself`)
  check(after.calls.length === 0, `Enter on the disabled action sent ${after.calls.join(", ")}`)
  check(after.notice === before.notice, `Enter on the disabled action showed: ${after.notice}`)
}

async function enable(page: InteractPage, action: string): Promise<void> {
  await page.evaluate(`(() => { document.querySelector('[data-action="${action}"]').disabled = false; return true })()`)
}

// With approval keys: D focuses the declining action, Y the accepting one
// only once it is on; Tab goes from the declining action to the accepting.
async function keyboardApproval(page: InteractPage): Promise<void> {
  await page.evaluate("(() => { document.activeElement?.blur?.(); window.scrollTo(0, 0); return true })()")
  await page.press("d")
  check((await active(page)) === "deny", `D focused ${await active(page)}, not Decline`)
  await page.press("y")
  check((await active(page)) === "deny", "Y moved focus to an Approve that is off")
  await enable(page, "approve")
  await page.press("d")
  await page.press("Tab")
  check((await active(page)) === "approve", `Tab from Decline reached ${await active(page)}, not Approve`)
  await page.press("d")
  await page.press("y")
  check((await active(page)) === "approve", `Y focused ${await active(page)}, not Approve`)
}

async function tabOrder(page: InteractPage, decline: string, accept: string): Promise<void> {
  await enable(page, accept)
  await page.evaluate(`(() => { document.querySelector('[data-action="${decline}"]').focus(); return true })()`)
  check((await active(page)) === decline, `${decline} cannot take focus`)
  await page.press("Tab")
  check((await active(page)) === accept, `Tab from ${decline} reached ${await active(page)}, not ${accept}`)
}

// Forces the two to stack (a wider basis than the phone can hold twice)
// and checks the emphasised action is the lower one, nearest the thumb.
async function stacked(page: InteractPage): Promise<void> {
  await page.evaluate(`(() => { document.querySelector('[data-region="bar"]').style.setProperty("--bar-btn-min", "15rem"); return true })()`)
  const { buttons } = await barButtons(page)
  const [first, second] = buttons
  check(first !== undefined && second !== undefined && (second.top >= first.bottom || first.top >= second.bottom), "the actions did not stack when their basis could not fit twice")
  emphasisLast(buttons)
  for (const b of buttons) check(!b.clipped, `${b.action} clips its label when stacked`)
}

// ---------------------------------------------------------------- wired

// A run approval whose stored digest is the one its page rebuilds.
async function matchingApproval(): Promise<Extract<WorkspaceApprovalView, { view: "detail" }>> {
  const view = galleryRunApproval(true, ["Tom"])
  if (view.view !== "detail" || !view.binding) throw new Error("interact: the run approval fixture has no binding")
  const digest = await digestOf({ subject: approvalSubjectOf(view.approval), snapshotDigest: view.binding.snapshotDigest, presentationDigest: view.binding.presentationDigest })
  return { ...view, approval: { ...view.approval, digest } }
}
const APPROVAL = await matchingApproval()
const DECIDER = { role: "admin" as const, member: "mem_tom00001" }
const APPROVE: Extract<WorkspaceStepUpAction, { type: "approval.decide" }> = { type: "approval.decide", approval: APPROVAL.approval.approval, digest: APPROVAL.approval.digest, decision: "approve", constraints: { uses: 1, ttlSeconds: 60 } }

// An enrolment whose groups and words come from a real key, its check
// keyed by the id the page is opened with.
const KEY_GROUPS = fingerprintGroups(fingerprintOf(THUMBPRINT))
const HIDDEN = PEOPLE_ENROL_BY_ID.fingerprint.hidden
const TRUE_GROUP = KEY_GROUPS[HIDDEN] ?? ""
function visibleGroups(): [string, string, string] {
  const [a, b, c] = KEY_GROUPS.filter((_, i) => i !== HIDDEN)
  if (a === undefined || b === undefined || c === undefined) throw new Error("interact: a key has four groups")
  return [a, b, c]
}
const ENROL: WorkspaceEnrolView = { ...PEOPLE_ENROL_BY_ID, fingerprint: { groups: visibleGroups(), hidden: HIDDEN, check: await fingerprintGroupCheck(PEOPLE_ENROL_BY_ID.ref, TRUE_GROUP), words: fingerprintWords(THUMBPRINT) } }
const ENROL_PAGE = enrolmentPage(peopleShell("member", { member: "mem_tom01" }), ENROL, { viewer: { member: "mem_tom01", role: "member", blocked: false }, projects: PEOPLE_PROJECTS, now: Date.parse("2026-10-27T18:30:00Z") })

// Makes the page the vault would serve and wires the real handlers: the
// shell for this origin, the API answered from window.__answers (a path
// held with "hold" waits for window.__release), the passkey prompt
// answered with a stand-in credential, every call kept in window.__calls.
const WIRE = `(async () => {
  const app = document.getElementById("app");
  const boot = JSON.parse(app.dataset.boot);
  boot.shell.origin = location.origin;
  app.dataset.boot = JSON.stringify(boot);
  window.__calls = [];
  window.__answers = { ["/api/w/" + boot.shell.workspace.slug]: { status: 200, body: boot.shell.workspace }, ["/api/w/" + boot.shell.workspace.slug + "/stepup/start"]: { status: 200, body: { nonce: "n", options: { challenge: "Y2hhbGxlbmdl" } } } };
  window.__held = [];
  window.__release = (status, body) => { const next = window.__held.shift(); if (next) next(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } })); };
  window.fetch = async (input, init) => {
    const path = String(input);
    window.__calls.push({ path, body: init && init.body ? JSON.parse(init.body) : undefined });
    const answer = window.__answers[path];
    if (answer === "hold") return new Promise((resolve) => window.__held.push(resolve));
    const a = answer || { status: 404, body: { error: "not_found", message: "No such route." } };
    return new Response(JSON.stringify(a.body), { status: a.status, headers: { "content-type": "application/json" } });
  };
  const bytes = new Uint8Array([1, 2, 3]).buffer;
  navigator.credentials.get = async () => { window.__calls.push({ path: "passkey" }); return { id: "AQID", rawId: bytes, type: "public-key", response: { clientDataJSON: bytes, authenticatorData: bytes, signature: bytes, userHandle: null }, getClientExtensionResults: () => ({}), authenticatorAttachment: null }; };
  await import("/assets/app.js?wired=" + Date.now());
  await new Promise((r) => setTimeout(r, 50));
  return true;
})()`

async function wired(page: InteractPage): Promise<string> {
  await page.evaluate(WIRE)
  return page.evaluate<string>(`"/api/w/" + JSON.parse(document.getElementById("app").dataset.boot).shell.workspace.slug`)
}

async function answer(page: InteractPage, path: string, value: unknown): Promise<void> {
  await page.evaluate(`(() => { window.__answers[${JSON.stringify(path)}] = ${JSON.stringify(value)}; return true })()`)
}

async function calls(page: InteractPage): Promise<{ path: string; body?: unknown }[]> {
  return page.evaluate(`window.__calls.filter((c) => c.path === "passkey" || c.path.startsWith("/api/w/"))`)
}

async function settled(page: InteractPage, ms = 150): Promise<void> {
  await page.evaluate(`new Promise((r) => setTimeout(() => r(true), ${ms}))`)
}

async function disabled(page: InteractPage, action: string): Promise<boolean> {
  return page.evaluate<boolean>(`document.querySelector('[data-action="${action}"]').disabled`)
}

function samePaths(got: readonly { path: string }[], want: readonly string[], what: string): void {
  check(JSON.stringify(got.map((c) => c.path)) === JSON.stringify(want), `${what}: sent ${got.map((c) => c.path).join(", ") || "nothing"}, not ${want.join(", ") || "nothing"}`)
}

async function clearCalls(page: InteractPage): Promise<void> {
  await page.evaluate("(() => { window.__calls = []; return true })()")
}

// Types into a field as a person does: focus, select what is there, keys.
async function typeInto(page: InteractPage, selector: string, text: string): Promise<void> {
  await page.evaluate(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); el.focus(); el.select(); return true })()`)
  for (const ch of text) await page.press(ch)
}

async function approvalWired(page: InteractPage): Promise<void> {
  const api = await wired(page)
  const action = `${api}/approvals/${APPROVAL.approval.approval}/action`
  const decide = `${api}/approvals/${APPROVAL.approval.approval}/decide`
  check(await disabled(page, "approve"), "Approve is on before the code is ticked")
  // Y leaves an Approve that is off alone; T reaches the tick; Enter on it
  // submits nothing.
  await page.evaluate("(() => { document.activeElement?.blur?.(); return true })()")
  await page.press("y")
  check((await active(page)) !== "approve", "Y focused an Approve that is off")
  await page.press("t")
  check(await page.evaluate<boolean>(`document.activeElement === document.querySelector('[data-input="code-matches"]')`), "T did not reach the tick")
  const href = await page.evaluate<string>("location.href")
  await page.press("Enter")
  await settled(page)
  samePaths(await calls(page), [], "Enter on the tick")
  check((await page.evaluate<string>("location.href")) === href, "Enter on the tick navigated")
  // Space ticks it; the page's own digest check has matched: Approve is on.
  await page.press(" ")
  await settled(page)
  check(!(await disabled(page, "approve")), "Approve stayed off with the digest matching and the code ticked")
  // A vault action wider than the page showed stops before the passkey.
  await answer(page, action, { status: 200, body: { ...APPROVE, constraints: { uses: 5, ttlSeconds: 3600 } } })
  // The keys stay quiet while a field has focus, as for anyone typing.
  await page.evaluate("(() => { document.activeElement?.blur?.(); return true })()")
  await page.press("y")
  check((await active(page)) === "approve", "Y did not reach Approve once it was on")
  await page.press("Enter")
  await settled(page)
  samePaths(await calls(page), [action], "a wider vault action")
  // The exact action: the workspace read, the step-up, the passkey, the
  // decision, which the vault refuses here so the page stays.
  await clearCalls(page)
  await answer(page, action, { status: 200, body: APPROVE })
  await answer(page, decide, { status: 409, body: { error: "conflict", message: "Refused by the scenario." } })
  await page.click('[data-action="approve"]')
  await settled(page)
  const sent = await calls(page)
  samePaths(sent, [action, api, `${api}/stepup/start`, "passkey", decide], "the exact approval")
  check(JSON.stringify((sent[4]?.body as { constraints?: unknown } | undefined)?.constraints) === JSON.stringify(APPROVE.constraints), "the decision did not carry the terms shown")
  // In flight: unticking keeps Approve off, and so does the failure.
  await clearCalls(page)
  await answer(page, action, "hold")
  await page.click('[data-action="approve"]')
  await settled(page)
  check(await disabled(page, "approve"), "Approve stayed on while its attempt ran")
  await page.click('[data-input="code-matches"]')
  await page.click('[data-action="approve"]').catch(() => undefined)
  await page.evaluate(`(() => { window.__release(409, { error: "conflict", message: "Refused by the scenario." }); return true })()`)
  await settled(page)
  check(await disabled(page, "approve"), "a failed attempt turned Approve back on without the tick")
  samePaths(await calls(page), [action], "an unticked Approve")
}

async function enrolWired(page: InteractPage): Promise<void> {
  const api = await wired(page)
  const base = `${api}/enrolments/${ENROL.ref}`
  const href = await page.evaluate<string>("location.href")
  await typeInto(page, '[data-input="fingerprint-group"]', "2222")
  await settled(page)
  check(await disabled(page, "enrol-accept"), "Accept is on for a wrong group")
  await page.press("Enter")
  await settled(page)
  check((await page.evaluate<string>("location.href")) === href, "Enter in the group field submitted the page")
  samePaths(await calls(page), [], "Enter in the group field")
  await typeInto(page, '[data-input="fingerprint-group"]', TRUE_GROUP)
  await settled(page)
  check(!(await disabled(page, "enrol-accept")), "Accept stayed off for the right group")
  // In flight, a new group turns Accept off at once and keeps it off
  // through the attempt's failure; nothing more is sent.
  await answer(page, `${base}/action`, "hold")
  await page.click('[data-action="enrol-accept"]')
  await settled(page)
  await typeInto(page, '[data-input="fingerprint-group"]', "2222")
  check(await disabled(page, "enrol-accept"), "Accept stayed on with a new group typed")
  await page.evaluate(`(() => { window.__release(403, { error: "forbidden", message: "Refused by the scenario." }); return true })()`)
  await settled(page)
  check(await disabled(page, "enrol-accept"), "a failed attempt turned Accept back on for a wrong group")
  samePaths(await calls(page), [`${base}/action`], "Accept in flight")
  // A planned acceptance for another member stops before the passkey; the
  // exact one is signed.
  await typeInto(page, '[data-input="fingerprint-group"]', TRUE_GROUP)
  await settled(page)
  const shown = JSON.parse(await page.evaluate<string>(`JSON.stringify(JSON.parse(document.getElementById("app").dataset.boot).acceptance)`)) as { scope: Record<string, unknown> } & Record<string, unknown>
  // Tom accepts his own machine with the private tick on, as the page starts it.
  const exact = { type: "enrol.accept", ...shown, scope: { ...shown.scope, privateCredentials: true }, thumbprint: THUMBPRINT }
  await clearCalls(page)
  await answer(page, `${base}/action`, { status: 200, body: { action: { ...exact, member: "mem_somebody01" } } })
  await page.click('[data-action="enrol-accept"]')
  await settled(page)
  samePaths(await calls(page), [`${base}/action`], "an acceptance for another member")
  await clearCalls(page)
  await answer(page, `${base}/action`, { status: 200, body: { action: exact } })
  await answer(page, `${base}/accept`, { status: 409, body: { error: "conflict", message: "Refused by the scenario." } })
  await page.click('[data-action="enrol-accept"]')
  await settled(page)
  samePaths(await calls(page), [`${base}/action`, api, `${api}/stepup/start`, "passkey", `${base}/accept`], "the exact acceptance")
}

async function connectWired(page: InteractPage): Promise<void> {
  const api = await wired(page)
  const boot = JSON.parse(await page.evaluate<string>(`document.getElementById("app").dataset.boot`)) as { connect: string; terms: ConnectTerms }
  const action = `${api}/connect/${boot.connect}/action`
  const start = `${api}/connect/${boot.connect}/start`
  const href = await page.evaluate<string>("location.href")
  // The fold names the home chosen once it closes again.
  await page.click('[data-region="home-choice"] summary')
  await page.click('[data-input="home"][value="workspace"]')
  await page.click('[data-region="home-choice"] summary')
  const summary = await page.evaluate<string>(`document.querySelector('[data-region="home-current"]').textContent`)
  check(summary === "Whole workspace", `the closed fold says ${summary}, not Whole workspace`)
  const expected = connectStartExpected(boot.connect, boot.terms, { kind: "workspace" })
  if (expected === null) throw new Error("interact: the connect fixture has no client")
  // Wider scopes than the page showed: nothing after the planning call.
  await answer(page, action, { status: 200, body: { ...expected, scopes: [...expected.type === "connect.start" ? expected.scopes : [], "https://mail.google.com/"] } })
  await page.click('[data-action="start-connect"]')
  await settled(page)
  samePaths(await calls(page), [action], "wider scopes")
  // The exact terms: the passkey comes before the start, and an address
  // that is not https is never opened.
  await clearCalls(page)
  await answer(page, action, { status: 200, body: expected })
  await answer(page, start, { status: 200, body: { authorizeUrl: "http://provider.invalid/authorize" } })
  await page.click('[data-action="start-connect"]')
  await settled(page)
  const sent = await calls(page)
  samePaths(sent, [action, api, `${api}/stepup/start`, "passkey", start], "the exact connect.start")
  check(JSON.stringify((sent[4]?.body as { home?: unknown } | undefined)?.home) === JSON.stringify({ kind: "workspace" }), "the start did not sign the home the fold names")
  check((await page.evaluate<string>("location.href")) === href, "the page opened a sign-in address that is not https")
}

export const BAR_SCENARIOS: readonly InteractScenario[] = [
  {
    name: "decision bar, approval",
    page: galleryPage("ws-approval-decider"),
    run: async (page) => {
      await inView(page, ["deny", "approve"])
      await disabledDoesNothing(page, "approve")
      await keyboardApproval(page)
      await clearOfLastCard(page)
    },
  },
  {
    name: "decision bar, warned approval",
    page: galleryPage("ws-approval-deceptive"),
    run: async (page) => {
      await inView(page, ["deny", "approve"])
      const classes = await page.evaluate<string[]>(`Array.from(document.querySelectorAll('[data-region="bar"] button.btn')).map((b) => b.className)`)
      check(JSON.stringify(classes) === JSON.stringify(["btn danger", "btn quiet"]), `the warned bar's buttons are ${classes.join(", ")}`)
      await disabledDoesNothing(page, "approve")
      await keyboardApproval(page)
      await clearOfLastCard(page)
      await stacked(page)
    },
  },
  {
    name: "decision bar, enrolment",
    page: galleryPage("enrol-accept"),
    run: async (page) => {
      await inView(page, ["enrol-reject", "enrol-accept"])
      await disabledDoesNothing(page, "enrol-accept")
      await tabOrder(page, "enrol-reject", "enrol-accept")
      await clearOfLastCard(page)
      await stacked(page)
    },
  },
  {
    name: "decision bar, team admission with the longest label",
    page: galleryPage("enrol-team-admit"),
    run: async (page) => {
      await inView(page, ["enrol-reject", "enrol-admit"])
      await clearOfLastCard(page)
      await stacked(page)
    },
  },
  {
    name: "wired approval: keys, Enter, exact terms, in flight",
    page: () => workspaceApprovalPage(galleryShell(DECIDER), { viewer: DECIDER, view: APPROVAL, project: null, items: [], now: Date.parse("2026-10-27T18:30:00Z") }),
    run: approvalWired,
  },
  {
    name: "wired enrolment: typed group, Enter, in flight, exact acceptance",
    page: () => ENROL_PAGE,
    run: enrolWired,
  },
  {
    name: "wired connect: folded home, exact terms, passkey before start",
    page: galleryPage("ws-connect"),
    run: connectWired,
  },
]
