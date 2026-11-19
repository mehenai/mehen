// The controls a workspace page offers against the evaluator's rules: each
// row here is a control the vault would refuse, and the page must not show
// it. The vault still decides; these keep the page from offering a refusal.

import { describe, expect, it } from "vitest"
import type { EffectiveAccess, WorkspaceProject } from "@mehen/protocol/workspace"
import { accessSourceLines, belongsToWords, canCreateProject, canPurgePrivate, canPushAgain, creatableHomes, credentialControls, projectControls } from "./workspace-rights.ts"

const manage: EffectiveAccess = { level: "manage", runProtected: true, editProtected: true, sources: [] }
const edit: EffectiveAccess = { level: "edit", runProtected: false, editProtected: false, sources: [] }
const editProtected: EffectiveAccess = { level: "edit", runProtected: true, editProtected: true, sources: [] }
const use: EffectiveAccess = { level: "use", runProtected: false, editProtected: false, sources: [] }

function project(access: EffectiveAccess): Pick<WorkspaceProject, "slug" | "access" | "defaultEnv" | "environments"> {
  return { slug: "platform", access, defaultEnv: "dev", environments: [{ name: "dev", protected: false, fences: [], fourEyes: false }, { name: "staging", protected: true, fences: ["api.openai.com"], fourEyes: true }, { name: "prod", protected: true, fences: [], fourEyes: true }] }
}

const withWorkspaceRefs = { dev: { workspaceReference: true }, staging: { workspaceReference: true }, prod: { workspaceReference: true } }
const noRefs = { dev: { workspaceReference: false }, staging: { workspaceReference: false }, prod: { workspaceReference: false } }

describe("project controls", () => {
  it("an owner sees every control, and nobody may unprotect prod", () => {
    const c = projectControls({ role: "owner", member: "mem_a" }, project(manage), withWorkspaceRefs, false)
    expect(c.share && c.shareWithGuests && c.remotes && c.delete).toBe(true)
    expect(c.environments.staging).toMatchObject({ unprotect: true, fourEyesOff: true, fences: true, ownerOnly: [] })
    expect(c.environments.prod).toMatchObject({ unprotect: false, fourEyesOff: true, fences: true })
    // The default environment can never be protected.
    expect(c.environments.dev?.protect).toBe(false)
  })

  it("a member who manages it cannot loosen, fence or protect where a workspace credential is used, and sees the vault's words instead", () => {
    const c = projectControls({ role: "member", member: "mem_k" }, { ...project(manage), defaultEnv: "staging" }, withWorkspaceRefs, false)
    expect(c.environments.prod).toMatchObject({ unprotect: false, fourEyesOff: false, fences: false })
    expect(c.environments.prod?.ownerOnly).toEqual(["Only an owner or admin can loosen platform/prod: it uses workspace credentials.", "Only an owner or admin can change fences for platform/prod."])
    expect(c.environments.dev).toMatchObject({ protect: false })
    expect(c.environments.dev?.ownerOnly).toContain("Only an owner or admin can protect platform/dev: it uses workspace credentials.")
    expect(c.shareWithGuests).toBe(false)
    expect(c.delete).toBe(false)
    expect(c.deleteOwnerOnly).toBe("Only an owner or admin can delete platform: a protected environment uses workspace credentials.")
  })

  it("a member who manages it may loosen where only project credentials are used, but never fences", () => {
    const c = projectControls({ role: "member", member: "mem_k" }, project(manage), noRefs, false)
    expect(c.environments.staging).toMatchObject({ unprotect: true, fourEyesOff: true, fences: false })
    expect(c.environments.staging?.ownerOnly).toEqual(["Only an owner or admin can change fences for platform/staging."])
    expect(c.delete).toBe(true)
  })

  it("an editor sets unprotected variables only, a protected tick adds protected ones, and use sets none", () => {
    const editor = projectControls({ role: "member", member: "mem_e" }, project(edit), noRefs, false)
    expect(editor.share || editor.remotes || editor.delete).toBe(false)
    expect(editor.environments.dev).toMatchObject({ setVariables: true, workspaceSources: true, protect: false, fourEyesOn: false, ownerOnly: [] })
    expect(editor.environments.prod).toMatchObject({ setVariables: false, workspaceSources: false })
    expect(projectControls({ role: "member", member: "mem_e" }, project(editProtected), noRefs, false).environments.prod).toMatchObject({ setVariables: true, workspaceSources: false, repointWorkspace: false })
    const user = projectControls({ role: "member", member: "mem_u" }, project(use), noRefs, false)
    expect(Object.values(user.environments).some((e) => e.setVariables)).toBe(false)
  })

  it("in a project shared with a guest or a team, only owners and admins point variables at workspace credentials", () => {
    expect(projectControls({ role: "member", member: "mem_e" }, project(edit), noRefs, true).environments.dev?.workspaceSources).toBe(false)
    expect(projectControls({ role: "admin", member: "mem_a" }, project(manage), noRefs, true).environments.dev?.workspaceSources).toBe(true)
  })

  it("when the share list is not sent (the viewer does not manage it), no workspace source is offered", () => {
    expect(projectControls({ role: "member", member: "mem_e" }, project(edit), noRefs, null).environments.dev).toMatchObject({ setVariables: true, workspaceSources: false })
    expect(projectControls({ role: "guest", member: "mem_g" }, project(edit), noRefs, null).environments.dev?.workspaceSources).toBe(false)
    expect(projectControls({ role: "owner", member: "mem_o" }, project(manage), noRefs, null).environments.dev?.workspaceSources).toBe(true)
  })

  it("a guest never manages, shares or protects, even with a manage-shaped access", () => {
    const c = projectControls({ role: "guest", member: "mem_g" }, project(manage), noRefs, false)
    expect(c.share || c.remotes || c.delete).toBe(false)
    expect(Object.values(c.environments).some((e) => e.protect || e.unprotect || e.fences || e.fourEyesOff || e.fourEyesOn)).toBe(false)
  })
})

describe("credential controls", () => {
  const projects = [{ id: "prj_a", access: manage }, { id: "prj_b", access: edit }, { id: "prj_c", access: use }]

  it("the owner of a private credential rotates, deletes and moves it into a project they edit, never to the workspace", () => {
    const c = credentialControls({ role: "member", member: "mem_m" }, { kind: "member", member: "mem_m" }, projects, [])
    expect(c).toEqual({ rotate: true, update: true, delete: true, rehomeTo: [{ kind: "project", project: "prj_a" }, { kind: "project", project: "prj_b" }] })
  })

  it("a member cannot rotate, delete or move a workspace credential; an admin can, but not into a project while another project uses it", () => {
    expect(credentialControls({ role: "member", member: "mem_m" }, { kind: "workspace" }, projects, [])).toEqual({ rotate: false, update: false, delete: false, rehomeTo: [] })
    const admin = credentialControls({ role: "admin", member: "mem_a" }, { kind: "workspace" }, projects, ["prj_a"])
    expect(admin).toMatchObject({ rotate: true, delete: true })
    expect(admin.rehomeTo).toEqual([{ kind: "project", project: "prj_a" }])
  })

  it("a project credential is managed by the project's managers; a guest who edits it may not", () => {
    expect(credentialControls({ role: "member", member: "mem_m" }, { kind: "project", project: "prj_a" }, projects, [])).toMatchObject({ rotate: true, delete: true, rehomeTo: [] })
    expect(credentialControls({ role: "member", member: "mem_m" }, { kind: "project", project: "prj_b" }, projects, [])).toMatchObject({ rotate: false, delete: false })
    expect(credentialControls({ role: "guest", member: "mem_g" }, { kind: "project", project: "prj_a" }, projects, [])).toMatchObject({ rotate: false, delete: false })
  })

  // access.ts credential.push: a private credential only its owner; a shared
  // one an owner, an admin or a manager of its home, never a guest.
  it("push again: the owner of a private credential, and for a shared one never a guest, even one who manages its home", () => {
    expect(canPushAgain({ role: "guest", member: "mem_g" }, { kind: "member", member: "mem_g" }, projects)).toBe(true)
    expect(canPushAgain({ role: "member", member: "mem_m" }, { kind: "member", member: "mem_g" }, projects)).toBe(false)
    expect(canPushAgain({ role: "member", member: "mem_m" }, { kind: "project", project: "prj_a" }, projects)).toBe(true)
    expect(canPushAgain({ role: "member", member: "mem_m" }, { kind: "project", project: "prj_b" }, projects)).toBe(false)
    expect(canPushAgain({ role: "guest", member: "mem_g" }, { kind: "project", project: "prj_a" }, projects)).toBe(false)
    expect(canPushAgain({ role: "guest", member: "mem_g" }, { kind: "workspace" }, projects)).toBe(false)
    expect(canPushAgain({ role: "admin", member: "mem_a" }, { kind: "workspace" }, [])).toBe(true)
  })

  it("creatable homes: always one's own, projects one edits, the workspace for owners and admins", () => {
    expect(creatableHomes({ role: "member", member: "mem_m" }, [{ id: "prj_a", slug: "a", access: edit }, { id: "prj_c", slug: "c", access: use }])).toEqual([{ kind: "member", member: "mem_m" }, { kind: "project", project: "prj_a" }])
    expect(creatableHomes({ role: "admin", member: "mem_a" }, [])).toEqual([{ kind: "member", member: "mem_a" }, { kind: "workspace" }])
    expect(canPurgePrivate({ role: "member", member: "mem_m" })).toBe(false)
    expect(canPurgePrivate({ role: "admin", member: "mem_a" })).toBe(true)
  })

  it("Belongs to says This project, Whole workspace or Only me", () => {
    const slugs = new Map([["prj_a", "platform"]])
    expect(belongsToWords({ kind: "project", project: "prj_a" }, slugs, "prj_a")).toBe("This project")
    expect(belongsToWords({ kind: "project", project: "prj_a" }, slugs)).toBe("This project (platform)")
    expect(belongsToWords({ kind: "workspace" }, slugs)).toBe("Whole workspace")
    expect(belongsToWords({ kind: "member", member: "mem_m" }, slugs)).toBe("Only me")
  })
})

describe("a held account", () => {
  // access.ts refuses a restricted or transitioning member every change that
  // is not a read or a narrowing, whatever their role.
  it("is offered no project, credential or create control, even as an owner", () => {
    const held = { role: "owner", member: "mem_a", held: true } as const
    const c = projectControls(held, project(manage), noRefs, false)
    expect(c).toMatchObject({ share: false, shareWithGuests: false, remotes: false, delete: false })
    for (const env of Object.values(c.environments)) expect(env).toMatchObject({ protect: false, unprotect: false, fourEyesOn: false, fourEyesOff: false, fences: false, setVariables: false, workspaceSources: false, ownerOnly: [] })
    expect(credentialControls(held, { kind: "member", member: "mem_a" }, [], [])).toEqual({ rotate: false, update: false, delete: false, rehomeTo: [] })
    expect(creatableHomes(held, [])).toEqual([])
    expect(canPurgePrivate(held)).toBe(false)
    expect(canCreateProject(held)).toBe(false)
    expect(canCreateProject({ role: "member", member: "mem_m" })).toBe(true)
    expect(canCreateProject({ role: "guest", member: "mem_g" })).toBe(false)
  })
})

describe("access sources", () => {
  it("keeps each source as granted: a team's use including protected and a direct edit stay two lines", () => {
    const access: EffectiveAccess = {
      level: "edit",
      runProtected: true,
      editProtected: false,
      sources: [
        { kind: "share", share: { id: "shr_t", project: "prj_a", subject: { kind: "team", team: "tm_e" }, level: "use", protected: true, expiresAt: null }, via: { kind: "team", team: "tm_e" } },
        { kind: "share", share: { id: "shr_d", project: "prj_a", subject: { kind: "member", member: "mem_m" }, level: "edit", protected: false, expiresAt: "2026-12-01T00:00:00.000Z" }, via: { kind: "member", member: "mem_m" } },
      ],
    }
    expect(accessSourceLines(access, { member: () => "you", team: (id) => id })).toEqual([
      { from: "Through the team tm_e", level: "use", protectedRun: true, protectedEdit: false, expiresAt: null },
      { from: "Shared with you", level: "edit", protectedRun: false, protectedEdit: false, expiresAt: "2026-12-01T00:00:00.000Z" },
    ])
  })
})
