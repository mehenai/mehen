// The provider adapters by destination: what a push may call, the preview
// read before anyone decides, and the write once a human has approved.
// Nothing here checks who may push: the caller has already authorised the
// push, the via's binding covers every call in pushCalls, and the preview
// reads are made only where the via's policy allows them.

import type { PushDestination, PushPreview } from "@mehen/protocol"
import { cloudflareCalls, cloudflarePreview, cloudflareWrite } from "./cloudflare.ts"
import type { PreviewAllowed, PushCalls, PushValue, PushVia, PushWritten } from "./common.ts"
import { flyCalls, flyPreview, flyWrite } from "./fly.ts"
import { githubCalls, githubPreview, githubWrite } from "./github.ts"
import { vercelCalls, vercelPreview, vercelWrite } from "./vercel.ts"

export type { PreviewAllowed, PushCall, PushCalls, PushValue, PushVia, PushWritten } from "./common.ts"

export function pushCalls(d: PushDestination): PushCalls {
  switch (d.provider) {
    case "github": return githubCalls(d)
    case "vercel": return vercelCalls(d)
    case "cloudflare": return cloudflareCalls(d)
    case "fly": return flyCalls(d)
  }
}

export function pushPreview(d: PushDestination, via: PushVia, allowed: PreviewAllowed): Promise<PushPreview> {
  switch (d.provider) {
    case "github": return githubPreview(d, via, allowed)
    case "vercel": return vercelPreview(d, via, allowed)
    case "cloudflare": return cloudflarePreview(d, via, allowed)
    case "fly": return flyPreview(d, via, allowed)
  }
}

export function pushWrite(d: PushDestination, value: PushValue, via: PushVia): Promise<PushWritten> {
  switch (d.provider) {
    case "github": return githubWrite(d, value, via)
    case "vercel": return vercelWrite(d, value, via)
    case "cloudflare": return cloudflareWrite(d, value, via)
    case "fly": return flyWrite(d, value, via)
  }
}
