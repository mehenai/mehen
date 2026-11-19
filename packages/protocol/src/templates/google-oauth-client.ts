import type { Template } from "../templates.ts"
import { CLIENT_SETUP_CALLBACK } from "./shared.ts"

// OAuth clients: the binding reaches only the provider's token endpoints,
// which is all the vault's own sign-in flow needs; the policy adds nothing.
export const googleOauthClient: Template = {
  id: "google-oauth-client",
  displayName: "Google OAuth client",
  kind: "oauth-client",
  category: "clients",
  docsUrl: "https://console.cloud.google.com/apis/credentials",
  // The client secret is only ever sent to Google's token endpoints.
  binding: { hosts: ["oauth2.googleapis.com"], paths: ["/token", "/revoke"], methods: ["POST"] },
  injection: null,
  policy: { default: "allow", rules: [] },
  ceiling: "relay",
  fields: {
    client_id: { label: "Client ID", pattern: "\\.apps\\.googleusercontent\\.com$" },
    client_secret: { label: "Client secret", pattern: "^GOCSPX-" },
  },
  prefixes: ["GOCSPX-"],
  setup: {
    title: "In Google Cloud",
    redirectUri: "/oauth/callback",
    steps: [
      { title: "Open the credentials page", body: "Sign in to Google Cloud and pick a project, or create one; its name does not matter.", docs: true },
      {
        title: "Enable the API the connection needs",
        body: "APIs and services, then Library: search for Gmail, Calendar or Drive, whichever the connection is for, and press Enable.",
      },
      {
        title: "Set up the consent screen",
        body: "Google auth platform, then Branding. Name the app Mehen. Choose Internal if this is a Google Workspace account. Otherwise choose External and add your own address as a test user.",
        warn: "If it is External, publish the app (Audience, then Publish app). Otherwise Google signs you out every seven days and the vault asks you to reconnect. Published or not, the first sign-in shows an unverified app warning because the app is yours, not Google's: choose Advanced, then Go to Mehen.",
      },
      {
        title: "Create a Web application client",
        body: "Credentials, then Create credentials, then OAuth client ID. Choose the type Web application and add this redirect URI exactly:",
        redirectUri: true,
        field: "client_id",
      },
      { title: "Copy the ID and secret into the form", body: "Google shows the secret once. Paste both below; the vault seals the secret on this device before it leaves.", field: "client_secret" },
    ],
  },
  clientSetup: [
    { title: "Create a project", body: "Open Google Cloud and create a project, or pick one of your own. Its name does not matter.", consoleUrl: "https://console.cloud.google.com/projectcreate" },
    { title: "Enable the API", body: "Open the API library and enable the API this connection needs: Gmail, Google Calendar or Google Drive.", consoleUrl: "https://console.cloud.google.com/apis/library" },
    { title: "Set up the consent screen", body: "In Google Auth Platform, open Branding and give the app a name you will recognise. Under Audience, choose External, or Internal if this is a Google Workspace account.", consoleUrl: "https://console.cloud.google.com/auth/branding" },
    { title: "Add yourself as a test user", body: "Under Audience, add your own Google address as a test user.", consoleUrl: "https://console.cloud.google.com/auth/audience" },
    { title: "Publish the app to production", body: "Under Audience, press Publish app, because while the app is in Testing Google ends its sign-in after 7 days. Google has not verified your own app, so signing in shows you an unverified app notice, which is expected.", consoleUrl: "https://console.cloud.google.com/auth/audience" },
    { title: "Create a Web client", body: `Under Clients, create an OAuth client of type Web application. Add ${CLIENT_SETUP_CALLBACK} as its authorised redirect URI, exactly as written.`, consoleUrl: "https://console.cloud.google.com/auth/clients" },
    { title: "Copy the ID and secret", body: "Copy the client ID and the client secret into the form. Google shows the secret only once." },
  ],
}
