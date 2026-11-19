import { AccountSessionSchema } from "@mehen/protocol"
import { beforeEach, describe, expect, it } from "vitest"
import { currentAccountSession } from "../src/directory/account-session.ts"
import { accountSessionView } from "../src/directory/workspace-account-admin.ts"
import type { WorkspaceMetadataClient } from "../src/directory/workspace-client.ts"
import { workspaceCreationCeiling, workspaceCreationDefault } from "../src/directory/workspace-creation.ts"
import { VaultError } from "../src/http.ts"
import { createWorkspaceFixture, type WorkspaceTestFixture } from "./workspace-fixtures.ts"

let f: WorkspaceTestFixture
beforeEach(async () => { f = await createWorkspaceFixture() })
const noMemberships: WorkspaceMetadataClient = { async metadata() { throw new VaultError("not_found","No such workspace.") },async membership() { throw new VaultError("not_found","No such workspace.") } }
async function read(rule: string | undefined) {
  const account = await currentAccountSession(new Request("https://vault.test",{ headers: { cookie: f.cookie } }),f.env)
  if (!account) throw new Error("Missing account")
  const session = AccountSessionSchema.parse(await accountSessionView({ ...f.env,WORKSPACE_CREATION: rule },account,noMemberships))
  return { canCreateWorkspaces: session.canCreateWorkspaces,workspaceCreation: session.workspaceCreation }
}
const decide = (allowed: 0 | 1) => f.env.DB.prepare("UPDATE accounts SET can_create_workspaces=?,can_create_workspaces_by='operator:test',can_create_workspaces_op=lower(hex(randomblob(16))) WHERE id=?").bind(allowed,f.account).run()

const setting = (value: string) => f.env.DB.prepare("INSERT INTO deployment_settings(key,value,updated_at,updated_by) VALUES ('workspace_creation',?,?,'operator:test')").bind(value,Date.now()).run()

describe("workspace creation default",() => {
  it("has the ceiling accounts only when WORKSPACE_CREATION says so exactly; unset or anything else is operator",() => {
    expect(workspaceCreationCeiling({ ...f.env,WORKSPACE_CREATION: "accounts" })).toBe("accounts")
    for (const rule of ["operator",undefined,"","Accounts","yes"]) expect(workspaceCreationCeiling({ ...f.env,WORKSPACE_CREATION: rule })).toBe("operator")
  })
  it("is the ceiling while no operator set it, the operators' setting under it, and never above it",async () => {
    expect(await workspaceCreationDefault({ ...f.env,WORKSPACE_CREATION: "accounts" })).toBe("accounts")
    expect(await workspaceCreationDefault({ ...f.env,WORKSPACE_CREATION: "operator" })).toBe("operator")
    await setting("operator")
    expect(await workspaceCreationDefault({ ...f.env,WORKSPACE_CREATION: "accounts" })).toBe("operator")
    await f.env.DB.prepare("UPDATE deployment_settings SET value='accounts' WHERE key='workspace_creation'").run()
    expect(await workspaceCreationDefault({ ...f.env,WORKSPACE_CREATION: "accounts" })).toBe("accounts")
    expect(await workspaceCreationDefault({ ...f.env,WORKSPACE_CREATION: "operator" })).toBe("operator")
  })
  it("is accounts for the production deployment and local development, operator in tests",() => {
    const config = Object.values(import.meta.glob<string>("../wrangler.jsonc",{ query: "?raw",import: "default",eager: true }))[0]!
    expect(config.match(/"WORKSPACE_CREATION": "(\w+)"/g)).toEqual(['"WORKSPACE_CREATION": "accounts"','"WORKSPACE_CREATION": "accounts"','"WORKSPACE_CREATION": "operator"'])
    expect(f.env.WORKSPACE_CREATION).toBe("operator")
  })
})

describe("the account read",() => {
  it("an account the operator never flagged: the deployment default decides",async () => {
    expect(await read("accounts")).toEqual({ canCreateWorkspaces: true,workspaceCreation: "default" })
    expect(await read("operator")).toEqual({ canCreateWorkspaces: false,workspaceCreation: "default" })
    expect(await read(undefined)).toEqual({ canCreateWorkspaces: false,workspaceCreation: "default" })
  })
  it("an account the operator never flagged cannot create once the operators narrowed the default, under the accounts ceiling",async () => {
    await setting("operator")
    expect(await read("accounts")).toEqual({ canCreateWorkspaces: false,workspaceCreation: "default" })
    await decide(1)
    expect(await read("accounts")).toEqual({ canCreateWorkspaces: true,workspaceCreation: "operator-allowed" })
  })
  it("an account the operator denied cannot create under either default, and says the operator denied it",async () => {
    await decide(0)
    expect(await read("accounts")).toEqual({ canCreateWorkspaces: false,workspaceCreation: "operator-denied" })
    expect(await read("operator")).toEqual({ canCreateWorkspaces: false,workspaceCreation: "operator-denied" })
  })
  it("an account the operator allowed can create under either default",async () => {
    await decide(1)
    expect(await read("accounts")).toEqual({ canCreateWorkspaces: true,workspaceCreation: "operator-allowed" })
    expect(await read("operator")).toEqual({ canCreateWorkspaces: true,workspaceCreation: "operator-allowed" })
  })
})
