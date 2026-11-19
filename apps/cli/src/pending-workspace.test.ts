// normaliseWorkspacePending keeps only this machine's own asks: a
// projection for the same workspace that another device asked for is
// dropped, as are other workspaces, stop views and
// unknown kinds. The server already filters by device; this is the CLI's
// own defence behind it.
import { describe, expect, test } from "bun:test"
import type { OwnerRef, WorkspaceRef } from "@mehen/protocol"
import { normaliseWorkspacePending } from "./pending-workspace.ts"
import { pendingWorkspaceFixtures } from "./testing/pending-workspace-fixtures.ts"

const ORIGIN = "https://vault.test"
const WORKSPACE: WorkspaceRef = { id: "tn_mock00000001", slug: "mock-space", name: "Mock Space" }
const OWNER: OwnerRef = { kind: "member", member: "mem_owner0000001", name: "Owner" }
const DEVICE = "dev_self00000001"

describe("normaliseWorkspacePending", () => {
  test("drops a same-workspace ask from another device and keeps exactly the own one", () => {
    const fixture = pendingWorkspaceFixtures(ORIGIN, WORKSPACE, DEVICE, OWNER)
    if (fixture.otherDevice.view !== "detail" || fixture.own.view !== "detail") throw new Error("detail fixtures")
    expect(fixture.otherDevice.workspace).toEqual(fixture.own.workspace)
    expect(fixture.otherDevice.detail.requestedBy).toEqual({ device: "dev_other0000001", deviceName: "workspace-machine", session: null })
    const context = { origin: ORIGIN, workspace: WORKSPACE, device: DEVICE }
    expect(normaliseWorkspacePending([fixture.otherDevice], context)).toEqual([])
    expect(normaliseWorkspacePending(fixture.pending, context)).toEqual([fixture.own.detail])
  })

  test("the other device's ask is that device's own: the filter follows the enrolled device, not the list", () => {
    const fixture = pendingWorkspaceFixtures(ORIGIN, WORKSPACE, DEVICE, OWNER)
    if (fixture.otherDevice.view !== "detail") throw new Error("detail fixture")
    const other = { origin: ORIGIN, workspace: WORKSPACE, device: "dev_other0000001" }
    expect(normaliseWorkspacePending(fixture.pending, other)).toEqual([fixture.otherDevice.detail])
  })

  test("with no enrolled device in the context, no workspace projection is shown", () => {
    const fixture = pendingWorkspaceFixtures(ORIGIN, WORKSPACE, DEVICE, OWNER)
    expect(normaliseWorkspacePending(fixture.pending, { origin: ORIGIN, workspace: WORKSPACE, device: null })).toEqual([])
  })
})
