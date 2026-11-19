import { expect, test } from "bun:test"
import { AdminPlatformCommandSchema, OperatorPlatformCommandSchema, OperatorRegisterSchema, adminStepUpAction, operatorStepUpAction, platformCommandDigest } from "./platform-console.ts"
import { WORKSPACE_WHILE_RESTRICTED, workspaceAllowedWhileRestricted } from "./step-up-rules.ts"
import { WorkspaceStepUpActionSchema } from "./workspace.ts"

test("a console step-up binds the slug, the platform id, the command and the whole command's digest, whatever the key order", async () => {
  const command = OperatorPlatformCommandSchema.parse({ command: "suspend", reason: "Odd traffic", confirm: "globex" })
  const action = await operatorStepUpAction("globex", "plt_globex0001", command)
  expect(WorkspaceStepUpActionSchema.parse(action)).toEqual(action)
  expect(action).toMatchObject({ type: "platform.operate", platform: "globex", platformId: "plt_globex0001", command: "suspend" })
  expect(await platformCommandDigest({ confirm: "globex", reason: "Odd traffic", command: "suspend" })).toBe(await platformCommandDigest(command))
  expect(await platformCommandDigest({ command: "suspend", reason: "Other", confirm: "globex" })).not.toBe(await platformCommandDigest(command))
  const admin = await adminStepUpAction("globex", "plt_globex0001", AdminPlatformCommandSchema.parse({ command: "revoke-key", key: "pky_abcdef", confirm: "globex" }))
  expect(admin).toMatchObject({ type: "platform.administer", platform: "globex", platformId: "plt_globex0001", command: "revoke-key" })
  // A platform's id is named for every command but register, whose platform has none yet.
  const register = OperatorRegisterSchema.parse({ command: "register", slug: "globex", name: "Globex", key: {}, limits: {}, confirm: "globex" })
  expect(await operatorStepUpAction("globex", null, register)).toMatchObject({ platformId: null, command: "register" })
  await expect(operatorStepUpAction("globex", "plt_globex0001", register)).rejects.toThrow("names the platform's id")
  await expect(operatorStepUpAction("globex", null, command)).rejects.toThrow("names the platform's id")
})

test("console writes are refused while the account cools off", async () => {
  expect([WORKSPACE_WHILE_RESTRICTED["platform.operate"], WORKSPACE_WHILE_RESTRICTED["platform.administer"]]).toEqual(["refused", "refused"])
  expect(workspaceAllowedWhileRestricted(await operatorStepUpAction("globex", "plt_globex0001", { command: "resume" }))).toBe(false)
})

test("a reason is plain words with no space at either end, and an admin's commands are only the admin's", () => {
  expect(OperatorPlatformCommandSchema.safeParse({ command: "suspend", reason: " Odd", confirm: "globex" }).success).toBe(false)
  expect(OperatorPlatformCommandSchema.safeParse({ command: "suspend", reason: "Odd\nline", confirm: "globex" }).success).toBe(false)
  expect(OperatorRegisterSchema.safeParse({ command: "register", slug: "globex", name: "Globex", key: {}, limits: { nope: 1 } }).success).toBe(false)
  for (const command of ["suspend", "resume", "limits", "retire", "remove", "add-admin", "delete-subjects"]) expect(AdminPlatformCommandSchema.safeParse({ command }).success).toBe(false)
})
