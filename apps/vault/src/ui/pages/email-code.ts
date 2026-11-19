// The emailed code beside "Verify with Google" on /signup's first step
// (directory/email-proof.ts; driven by ui/client/email-code.ts). The code
// goes only to the address the invitation names, which the page never shows
// before it is proved. Rendered hidden: the peek says whether it is offered,
// or whether the workspace's identity rule leaves only Google.

import { type Html, html } from "../html.ts"

export const EMAIL_CODE_LEAD = "No Google account? Mehen can email a six-digit code to the invited address instead."
export const EMAIL_CODE_SENT_WORDS = "A code is on its way to the invited address. It works for 10 minutes."
export const EMAIL_CODE_FAILED_WORDS = "The code could not be sent. Verify with Google instead, or try again later."
export const EMAIL_CODE_GOOGLE_ONLY_WORDS = "This workspace asks for a Google Workspace account for this role, so only Google can verify this invitation."

export function emailCodeOption(): Html {
  return html`<div data-region="email-code" hidden>
      <p class="muted">${EMAIL_CODE_LEAD}</p>
      <div class="actions" data-region="email-code-start"><button type="button" class="btn secondary" data-action="email-code-send">Email me a code</button></div>
      <p class="inline-error" role="alert" data-region="email-code-failed" hidden>${EMAIL_CODE_FAILED_WORDS}</p>
      <form class="stack" data-form="email-code" novalidate data-region="email-code-sent" hidden>
        <p role="status">${EMAIL_CODE_SENT_WORDS}</p>
        <label class="field"><span class="label">Code from the email</span>
          <input type="text" class="mono" data-input="email-code" inputmode="numeric" autocomplete="one-time-code" spellcheck="false" maxlength="7"></label>
        <p class="inline-error" role="alert" data-region="email-code-error" hidden></p>
        <div class="actions"><button type="submit" class="btn primary" data-action="email-code-verify">Verify code</button>
          <button type="button" class="btn quiet" data-action="email-code-resend">Send a new code</button></div>
      </form>
    </div>
    <p class="muted" data-region="email-code-google-only" hidden>${EMAIL_CODE_GOOGLE_ONLY_WORDS}</p>`
}
