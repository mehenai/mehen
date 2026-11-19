import type { Template } from "../templates.ts"
import { CLIENT_SETUP_CALLBACK } from "./shared.ts"

// OAuth clients: the binding reaches only the provider's token endpoints,
// which is all the vault's own sign-in flow needs; the policy adds nothing.
export const microsoftOauthClient: Template = {
  id: "microsoft-oauth-client",
  displayName: "Microsoft Entra app registration",
  kind: "oauth-client",
  category: "clients",
  docsUrl: "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
  binding: { hosts: ["login.microsoftonline.com"], paths: ["/common/oauth2/v2.0/token"], methods: ["POST"] },
  injection: null,
  policy: { default: "allow", rules: [] },
  ceiling: "relay",
  fields: { client_id: { label: "Application (client) ID" }, client_secret: { label: "Client secret value" } },
  clientSetup: [
    { title: "Register an application", body: "Open App registrations in Microsoft Entra and choose New registration. Give it a name you will recognise.", consoleUrl: "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade" },
    { title: "Choose who can sign in", body: "Under Supported account types, choose accounts in any organisation's directory and personal Microsoft accounts." },
    { title: "Set the redirect URI", body: `Under Redirect URI, choose Web and enter ${CLIENT_SETUP_CALLBACK}, exactly as written. Then register the application.` },
    { title: "Add a client secret", body: "Under Certificates and secrets, add a new client secret. Microsoft shows its value only once, so copy the Value, not the Secret ID." },
    { title: "Copy the ID and secret", body: "Copy the Application (client) ID from the Overview page, and the secret's value, into the form." },
  ],
}
