import { oidcVerifyPage } from "./pages/oidc-verify.ts"
import type { ShellGalleryEntry } from "./shell-gallery.ts"
export function oidcGallery(): ShellGalleryEntry[] {
  return [
    { id: "oidc-signin",input: { mode: "verify" as const,enabled: true,purpose: "signin" } },
    { id: "oidc-disabled",input: { mode: "verify" as const,enabled: false,purpose: "signin" } },
    { id: "oidc-gate-work",input: { mode: "verify" as const,enabled: true,purpose: "gate",workspace: "northwind" } },
    { id: "oidc-link-hostile",input: { mode: "result" as const,enabled: true,purpose: "link",identity: { email: "alex@northwind.example",subject: "123",name: '<b>Alex</b>\u202e\u0007' } } },
    { id: "oidc-app-callback",input: { mode: "app-callback" as const,enabled: false } },
  ].map(({ id,input }) => ({ id,group: "Google identity",title: id,note: "Identity proof only; passkeys retain authentication and authority.",page: oidcVerifyPage(input) }))
}
