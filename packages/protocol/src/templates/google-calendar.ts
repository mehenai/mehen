import type { OAuthProviderTemplate } from "../templates.ts"
import { ACCESS_TOKEN_BEARER, ALLOW_READS, GOOGLE_AUTH, GOOGLE_IDENTITY, GOOGLE_LIFETIMES, GOOGLE_REFRESH, WRITES } from "./shared.ts"

// Without a human: reads and free/busy queries. Creating or changing
// events (which can invite and email anyone), sharing and deletes need an
// approval; push notifications are refused.
export const googleCalendar: OAuthProviderTemplate = {
  id: "google-calendar",
  family: "google",
  displayName: "Google Calendar",
  category: "mail",
  docsUrl: "https://developers.google.com/calendar/api/auth",
  clientTemplate: "google-oauth-client",
  auth: GOOGLE_AUTH(["calendar.events"], ["calendar", "calendar.readonly", "calendar.events", "calendar.events.readonly", "calendar.freebusy"]),
  identity: GOOGLE_IDENTITY,
  upstream: {
    baseUrl: "https://www.googleapis.com/calendar/v3",
    binding: { hosts: ["www.googleapis.com"], paths: ["/calendar/v3/**"] },
    injection: ACCESS_TOKEN_BEARER,
  },
  refresh: GOOGLE_REFRESH,
  lifetimes: GOOGLE_LIFETIMES,
  defaultPolicy: {
    default: "approve",
    rules: [ALLOW_READS, { action: "allow", methods: ["POST"], paths: ["/calendar/v3/freeBusy"], note: "free/busy query" }],
  },
  sensitiveEndpoints: [
    { action: "approve", methods: WRITES, paths: ["/calendar/v3/calendars/*/acl", "/calendar/v3/calendars/*/acl/**"], why: "shares a calendar" },
    { action: "approve", methods: ["DELETE"], paths: ["/calendar/v3/calendars/*", "/calendar/v3/users/me/calendarList/*"], why: "deletes a calendar" },
    { action: "deny", methods: ["POST"], paths: ["/calendar/v3/**/watch"], why: "push notifications to an outside address" },
  ],
}
