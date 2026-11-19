// The consoles' interaction scenarios: what a screenshot cannot prove about
// a platform key made in the browser. scripts/ui-interact.ts runs them, at
// 360 and 390 px, on the operator's register page with the real client
// bundle: the API answered from the scenario and the passkey prompt
// answered with a stand-in credential, every call kept.
//
// - A key made here shows its private half once, with the warning; the
//   register form refuses to send until the box is ticked, asks for a
//   passkey for the exact register command (its digest is
//   platformCommandDigest of the command it then sends), sends only the
//   public JWK, and the private half is gone from the page once it has been
//   sent.
// - Forgetting the key, switching to pasting, and the page going
//   (pagehide), drop it too.
// - A pasted private key is refused under the field, and only there,
//   before any passkey, and the field is cleared.

import { type OperatorRegister, platformCommandDigest } from "@mehen/protocol/platform-console"
import type { PageInput } from "../../src/ui/layout.ts"
import { CONSOLE_ACCOUNT_SHELL } from "../../src/ui/console-gallery.ts"
import { PASTED_KEY_PROBLEMS } from "../../src/ui/client/platform-key-logic.ts"
import { operatorRegisterPage } from "../../src/ui/pages/operator.ts"
import type { InteractPage, InteractScenario } from "../ui-interact.ts"

function check(ok: boolean, message: string): void {
  if (!ok) throw new Error(message)
}

const registerPage = (): PageInput => operatorRegisterPage(CONSOLE_ACCOUNT_SHELL, [])

// The API and the passkey prompt, answered here: the step-up start, then
// the register itself with the platform's ids.
const STAND_IN = `(() => {
  window.__calls = [];
  const answers = {
    "/api/operator/stepup/start": { status: 200, body: { nonce: "n", options: { challenge: "Y2hhbGxlbmdl" } } },
    "/api/operator/platforms": { status: 201, body: { done: "Registered globex.", platform: { id: "plt_8kQw2Lm4Zp7Rt5Vx", slug: "globex", keys: [{ id: "pky_9fQ2mX7vR4tLp8Wz", live: true }] } } },
  };
  window.fetch = async (input, init) => {
    const path = String(input);
    window.__calls.push({ path, body: init && init.body ? String(init.body) : "" });
    const a = answers[path] || { status: 404, body: { error: "not_found", message: "No such route." } };
    return new Response(JSON.stringify(a.body), { status: a.status, headers: { "content-type": "application/json" } });
  };
  const bytes = new Uint8Array([1, 2, 3]).buffer;
  navigator.credentials.get = async () => { window.__calls.push({ path: "passkey", body: "" }); return { id: "AQID", rawId: bytes, type: "public-key", response: { clientDataJSON: bytes, authenticatorData: bytes, signature: bytes, userHandle: null }, getClientExtensionResults: () => ({}), authenticatorAttachment: null }; };
  return true;
})()`

type Call = { path: string; body: string }

async function settled(page: InteractPage, ms = 200): Promise<void> {
  await page.evaluate(`new Promise((r) => setTimeout(() => r(true), ${ms}))`)
}

async function text(page: InteractPage, region: string): Promise<string> {
  return page.evaluate<string>(`document.querySelector('[data-region="${region}"]').textContent`)
}

async function hidden(page: InteractPage, region: string): Promise<boolean> {
  return page.evaluate<boolean>(`document.querySelector('[data-region="${region}"]').hidden`)
}

async function fill(page: InteractPage, input: string, value: string): Promise<void> {
  await page.evaluate(`(() => { const el = document.querySelector('[data-input="${input}"]'); el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event("input", { bubbles: true })); return true })()`)
}

// Chooses "Make a key pair", makes one, and answers its private half.
async function makeKey(page: InteractPage): Promise<string> {
  await page.click('[data-input="key-source"][value="make"]')
  check(!(await hidden(page, "key-make")) && (await hidden(page, "key-paste")), "choosing to make a key did not show its part")
  await page.click('[data-action="make-key"]')
  await settled(page)
  const key = await text(page, "private-key")
  check(/^[A-Za-z0-9_-]{120,}$/.test(key), `the made key's private half is not PKCS8 in base64url: ${JSON.stringify(key.slice(0, 20))}`)
  check(!(await hidden(page, "key-made")), "the private half is not shown")
  check(/^[A-Za-z0-9_-]{43}$/.test(await text(page, "key-thumbprint")), "the thumbprint is not shown")
  return key
}

async function madeKeySentOnce(page: InteractPage): Promise<void> {
  await page.evaluate(STAND_IN)
  const privateKey = await makeKey(page)
  await fill(page, "name", "Globex")
  await fill(page, "slug", "globex")
  await fill(page, "confirm", "globex")
  await page.click('[data-form="platform-register"] button[type="submit"]')
  await settled(page)
  check((await page.evaluate<Call[]>("window.__calls")).length === 0, "the form was sent before the box was ticked")
  check((await text(page, "key-problem")).startsWith("Copy the private key"), "no word under the key about the box")
  check(await noticeHidden(page), "the refusal under the key was said again in the page notice")
  await page.click('[data-input="key-kept"]')
  check(await page.evaluate<boolean>(`document.querySelector('[data-input="key-kept"]').checked`), "the box did not tick")
  await page.click('[data-form="platform-register"] button[type="submit"]')
  await settled(page, 400)
  const calls = await page.evaluate<Call[]>("window.__calls")
  check(JSON.stringify(calls.map((c) => c.path)) === JSON.stringify(["/api/operator/stepup/start", "passkey", "/api/operator/platforms"]), `sent ${calls.map((c) => c.path).join(", ")}`)
  const start = JSON.parse(calls[0]?.body ?? "{}") as { action?: { type?: string; platform?: string; platformId?: string | null; command?: string; digest?: string } }
  check(start.action?.type === "platform.operate" && start.action.platform === "globex" && start.action.platformId === null && start.action.command === "register", "the passkey was not asked for the register command")
  const sent = JSON.parse(calls[2]?.body ?? "{}") as { command?: OperatorRegister & { key?: Record<string, unknown> } }
  // The vault takes the digest of the command it parses; the page's must be
  // that of the very command it sent, or every write from the web fails.
  check(sent.command !== undefined && start.action?.digest === (await platformCommandDigest(sent.command)), "the passkey's digest is not that of the command sent")
  check(sent.command?.confirm === "globex", "the register did not carry the slug typed back")
  check(JSON.stringify(Object.keys(sent.command?.key ?? {}).sort()) === JSON.stringify(["crv", "kty", "x", "y"]), "the register sent more than the public JWK")
  check(calls.every((c) => !c.body.includes(privateKey) && !c.body.includes('"d"')), "the private half left the page")
  check((await text(page, "private-key")) === "", "the private half is still on the page after it was sent")
  check(!(await hidden(page, "register-done")) && (await text(page, "done-platform")) === "plt_8kQw2Lm4Zp7Rt5Vx" && (await text(page, "done-key")) === "pky_9fQ2mX7vR4tLp8Wz", "the ids to hand over are not shown")
}

async function noticeHidden(page: InteractPage): Promise<boolean> {
  return page.evaluate<boolean>(`document.querySelector("#notice").hidden`)
}

async function forgotten(page: InteractPage): Promise<void> {
  await makeKey(page)
  await page.click('[data-action="forget-key"]')
  check((await text(page, "private-key")) === "" && (await hidden(page, "key-made")), "Forget left the private half on the page")
  await makeKey(page)
  await page.click('[data-input="key-source"][value="paste"]')
  check((await text(page, "private-key")) === "" && (await hidden(page, "key-made")), "switching to pasting left the made key's private half on the page")
  await page.click('[data-input="key-source"][value="make"]')
  check((await text(page, "private-key")) === "" && (await hidden(page, "key-made")), "switching back brought the made key back")
  await makeKey(page)
  await page.evaluate(`(() => { window.dispatchEvent(new PageTransitionEvent("pagehide")); return true })()`)
  check((await text(page, "private-key")) === "", "the private half outlived the page")
}

async function pastedPrivateRefused(page: InteractPage): Promise<void> {
  await page.evaluate(STAND_IN)
  const jwk = await page.evaluate<string>(`(async () => {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    return JSON.stringify(await crypto.subtle.exportKey("jwk", pair.privateKey));
  })()`)
  await fill(page, "name", "Globex")
  await fill(page, "slug", "globex")
  await fill(page, "confirm", "globex")
  await fill(page, "public-jwk", jwk)
  await page.click('[data-form="platform-register"] button[type="submit"]')
  await settled(page)
  check((await page.evaluate<Call[]>("window.__calls")).length === 0, "a private key reached the passkey or the vault")
  check((await text(page, "key-problem")) === PASTED_KEY_PROBLEMS.private, "the private key was not refused under the field")
  check(await noticeHidden(page), "the refusal under the field was said again in the page notice")
  check((await page.evaluate<string>(`document.querySelector('[data-input="public-jwk"]').value`)) === "", "the refused private key was left in the field")
}

export const CONSOLE_SCENARIOS: readonly InteractScenario[] = [
  { name: "register: a made key shown once, sent as its public half only, then gone", page: registerPage, run: madeKeySentOnce },
  { name: "register: a made key forgotten, dropped on switching to pasting, and when the page goes", page: registerPage, run: forgotten },
  { name: "register: a pasted private key refused once, under the field, before any passkey, and cleared", page: registerPage, run: pastedPrivateRefused },
]
