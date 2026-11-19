import { cardText } from "../components.ts"
import { html } from "../html.ts"
import type { PageInput } from "../layout.ts"

// Google verification for signing in, linking an identity and a workspace's
// identity gate. An invitation's Google step runs on /signup, not here.
export type OidcPage = { mode: "verify" | "result" | "app-start" | "app-callback"; enabled: boolean; purpose?: string; result?: string; workspace?: string; next?: string; identity?: { email: string; subject: string; name: string | null } }
export function oidcVerifyPage(input: OidcPage): PageInput {
  const callback = input.mode === "app-callback", result = input.mode === "result"
  return { title: callback ? "Return to your app" : "Verify with Google", viewer: null, focus: true, boot: { page: "oidc", ...input, identity: input.identity ?? null }, body: html`
    <section class="focus-card"><h1>${callback ? "Return to your app" : "Verify with Google"}</h1>
    ${callback ? html`<p>Return to the app that opened this verification. Nothing here signs you in.</p>` : html`<p>Google proves your identity. Your passkey still signs you in and confirms every change.</p>
      ${input.workspace ? html`<p>Workspace: <code>${cardText(input.workspace)}</code></p>` : ""}
      ${input.identity ? html`<p>Google account: <strong>${cardText(input.identity.email)}</strong>${input.identity.name ? html` (${cardText(input.identity.name)})` : ""}</p>` : ""}
      ${!input.enabled ? html`<p>Google verification is not configured. Sign in with your passkey instead. Email-bound invitations and workspace checks must wait.</p><a class="button secondary" href="/signin">Sign in with a passkey</a>` : input.mode === "app-start" ? html`<p>Opening Google in this browser...</p>` : result ? html`
        ${input.purpose === "signin" ? html`<button type="button" class="button" data-action="oidc-signin">Sign in with your passkey</button>` : ""}
        ${input.purpose === "link" ? html`<button type="button" class="button" data-action="oidc-link">Link this Google account</button>` : ""}
        ${input.purpose === "gate" ? html`<button type="button" class="button" data-action="oidc-gate">Use this verified identity</button>` : ""}
      ` : html`<button type="button" class="button" data-action="oidc-start">Verify with Google</button>`}
    `}</section>` }
}
