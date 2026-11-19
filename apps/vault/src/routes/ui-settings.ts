// The workspace settings page under /w/:ws, registered into WORKSPACE_PAGES.
// It reads the workspace's identity and GET /api/w/:ws/settings, so it is
// served only once that route is, and shows what this account may change.

import type { BackupStatus } from "@mehen/protocol/backup"
import type { WorkspaceSettingsView } from "@mehen/protocol/workspace"
import { pageResponse, redirect } from "../ui/layout.ts"
import { workspaceApiGet } from "../ui/load.ts"
import { workspaceSettingsPage } from "../ui/pages/workspace-settings.ts"
import { peopleViewer, refused } from "./ui-people.ts"
import type { WorkspacePage } from "./ui.ts"

export const SETTINGS_PAGES: WorkspacePage[] = [
  {
    key: "settings",
    path: "/settings",
    reads: ["", "/settings", "/backup/recipients"],
    render: async (rc, page) => {
      const loaded = await workspaceApiGet<WorkspaceSettingsView>(rc, page.workspace, "/settings")
      if (!loaded.ok && loaded.error.error === "unauthenticated") return redirect(`/signin?next=${encodeURIComponent(rc.url.pathname)}`)
      // A refusal (an identity check due, a suspended membership) is shown
      // as the vault words it; anything else is a read that failed.
      if (!loaded.ok && loaded.status < 500) return refused(page.shell, loaded)
      const role = peopleViewer(page.shell)?.role ?? null
      const backups = loaded.ok && role !== "guest" ? await workspaceApiGet<BackupStatus>(rc, page.workspace, "/backup/recipients") : null
      return pageResponse(workspaceSettingsPage(page.shell, { settings: loaded.ok ? loaded.value : null, role, backups: backups?.ok ? backups.value : null }))
    },
  },
]
