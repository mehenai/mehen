import { expect,it } from "vitest"
import { galleryShell,VIEWERS } from "../src/ui/workspace-projects-gallery.ts"
import { galleryRunApproval } from "../src/ui/workspace-asks-gallery.ts"
import { workspaceApprovalPage } from "../src/ui/pages/workspace-asks.ts"
import { renderDocument } from "../src/ui/layout.ts"

it("workspace approval pages visibly mark bidi and zero-width characters in title, argv, URL and headers",() => {
  const view = galleryRunApproval(true,["Tom"])
  if (view.view !== "detail") throw new Error("Expected detail fixture")
  const a = view.approval
  a.title = "Run \u202Ehidden\u200B title"
  a.request.body = '"node"\n"arg\u202Ehidden\u200B"'
  a.request.url = "https://api.example.com/url\u202Ehidden\u200B"
  a.request.headers = [["X-Note","header\u202Ehidden\u200B"]]
  const page = workspaceApprovalPage(galleryShell(VIEWERS.owner),{ viewer: VIEWERS.owner,view,project: null,items: [] })
  const document = renderDocument(page).value
  for (const visible of ["Run [RLO U+202E]hidden[ZWSP U+200B] title","arg[RLO U+202E]hidden[ZWSP U+200B]","url[RLO U+202E]hidden[ZWSP U+200B]","header[RLO U+202E]hidden[ZWSP U+200B]"]) expect(document.replace(/<[^>]+>/g,""),visible).toContain(visible)
  expect(document).not.toContain("\u202E")
  expect(document).not.toContain("\u200B")
  // The digest boot keeps the original signed strings, not the display markers.
  const boot = /data-boot="([^"]+)"/.exec(document)![1]!
  expect(boot).toContain("\\u202E")
  expect(boot).toContain("\\u200B")
})
