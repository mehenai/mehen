import type { OAuthProviderTemplate } from "../templates.ts"
import { ACCESS_TOKEN_BEARER, ALLOW_READS, GOOGLE_AUTH, GOOGLE_IDENTITY, GOOGLE_LIFETIMES, GOOGLE_REFRESH, WRITES } from "./shared.ts"

// Without a human: reads. Creating, changing, copying or sharing files
// (which can write into a folder someone else shared) and deletes need an
// approval; push notifications are refused.
export const googleDrive: OAuthProviderTemplate = {
  id: "google-drive",
  family: "google",
  displayName: "Google Drive",
  category: "mail",
  docsUrl: "https://developers.google.com/drive/api/guides/api-specific-auth",
  clientTemplate: "google-oauth-client",
  auth: GOOGLE_AUTH(["drive"], ["drive", "drive.file", "drive.readonly", "drive.metadata.readonly", "drive.appdata"]),
  identity: GOOGLE_IDENTITY,
  upstream: {
    baseUrl: "https://www.googleapis.com/drive/v3",
    binding: { hosts: ["www.googleapis.com"], paths: ["/drive/v3/**", "/upload/drive/v3/**"] },
    injection: ACCESS_TOKEN_BEARER,
  },
  refresh: GOOGLE_REFRESH,
  lifetimes: GOOGLE_LIFETIMES,
  defaultPolicy: { default: "approve", rules: [ALLOW_READS] },
  sensitiveEndpoints: [
    { action: "approve", methods: WRITES, paths: ["/drive/v3/files/*/permissions", "/drive/v3/files/*/permissions/**"], why: "shares a file" },
    { action: "approve", methods: ["DELETE"], paths: ["/drive/v3/files/*"], why: "permanent deletes" },
    { action: "approve", methods: ["DELETE"], paths: ["/drive/v3/files/trash"], why: "empties the trash" },
    { action: "deny", methods: ["POST"], paths: ["/drive/v3/**/watch", "/drive/v3/changes/watch"], why: "push notifications to an outside address" },
  ],
}
