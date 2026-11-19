import type { Template } from "../templates.ts"
import { CLIENT_SETUP_CALLBACK } from "./shared.ts"

// OAuth clients: the binding reaches only the provider's token endpoints,
// which is all the vault's own sign-in flow needs; the policy adds nothing.
export const githubOauthClient: Template = {
  id: "github-oauth-client",
  displayName: "GitHub OAuth app",
  kind: "oauth-client",
  category: "clients",
  docsUrl: "https://github.com/settings/developers",
  binding: { hosts: ["github.com"], paths: ["/login/oauth/access_token"], methods: ["POST"] },
  injection: null,
  policy: { default: "allow", rules: [] },
  ceiling: "relay",
  fields: { client_id: { label: "Client ID" }, client_secret: { label: "Client secret" } },
  clientSetup: [
    { title: "Register a new OAuth app", body: "Open your GitHub developer settings and choose New OAuth app. Give it a name you will recognise, and any homepage URL, such as your own profile.", consoleUrl: "https://github.com/settings/applications/new" },
    { title: "Set the callback", body: `Set the Authorization callback URL to ${CLIENT_SETUP_CALLBACK}, exactly as written, and register the application.` },
    { title: "Generate a client secret", body: "On the app's page, choose Generate a new client secret. GitHub shows it only once." },
    { title: "Copy the ID and secret", body: "Copy the client ID and the client secret into the form." },
  ],
}
