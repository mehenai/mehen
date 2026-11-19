// The platform API's OAuth routes (D0 1.4, routes 16 to 19), by their names
// in PLATFORM_ROUTES. routes/platform.ts authenticates each of them and sends
// it to the subject's workspace as the operation `platform.<name>`, with its
// params, query and body parsed by the route's schemas; the operations live
// in vault/areas/oauth-workspace.ts. connects.finish is a JSON call from the
// platform's own callback, so Mehen serves no redirect for it.
import type { PlatformRouteName } from "@mehen/protocol"

export const platformOAuthRoutes = ["connects.start", "connects.finish", "connects.get", "connects.cancel"] as const satisfies readonly PlatformRouteName[]

export type PlatformOAuthRouteName = (typeof platformOAuthRoutes)[number]
