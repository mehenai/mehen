import { describe, expect, it } from "bun:test"
import { deploymentSettingCeiling, deploymentSettingCeilingWords, deploymentSettingChange, effectiveDeploymentSetting } from "./deployment-settings.ts"

describe("deployment settings", () => {
  it("reads a ceiling only from a value the setting has, exactly; missing or unknown is the narrowest", () => {
    expect(deploymentSettingCeiling("workspace_creation", "accounts")).toBe("accounts")
    expect(deploymentSettingCeiling("signup_mode", "open")).toBe("open")
    expect(deploymentSettingCeiling("signup_mode", "request")).toBe("request")
    for (const raw of [undefined, "", "Open", "everyone", "accounts"]) expect(deploymentSettingCeiling("signup_mode", raw)).toBe("invite")
    for (const raw of [undefined, "", "Accounts", "invite"]) expect(deploymentSettingCeiling("workspace_creation", raw)).toBe("operator")
  })

  it("is in force as stored, capped by the ceiling; with nothing stored, the ceiling for workspace creation and invitation only for sign-up", () => {
    expect(effectiveDeploymentSetting("workspace_creation", null, "accounts")).toBe("accounts")
    expect(effectiveDeploymentSetting("workspace_creation", null, "operator")).toBe("operator")
    expect(effectiveDeploymentSetting("workspace_creation", "operator", "accounts")).toBe("operator")
    expect(effectiveDeploymentSetting("workspace_creation", "accounts", "operator")).toBe("operator")
    expect(effectiveDeploymentSetting("signup_mode", null, "open")).toBe("invite")
    expect(effectiveDeploymentSetting("signup_mode", "open", "request")).toBe("request")
    expect(effectiveDeploymentSetting("signup_mode", "request", "open")).toBe("request")
    expect(effectiveDeploymentSetting("signup_mode", "accounts", "open")).toBe("invite")
  })

  it("orders each setting's values from narrowest to widest", () => {
    expect(deploymentSettingChange("workspace_creation", "accounts", "operator")).toBe("narrow")
    expect(deploymentSettingChange("workspace_creation", "operator", "accounts")).toBe("widen")
    expect(deploymentSettingChange("signup_mode", "open", "request")).toBe("narrow")
    expect(deploymentSettingChange("signup_mode", "invite", "open")).toBe("widen")
    expect(deploymentSettingChange("signup_mode", "request", "request")).toBe("same")
  })

  it("says why a value past the ceiling cannot be chosen, naming the deploy variable", () => {
    expect(deploymentSettingCeilingWords("signup_mode", "invite")).toBe("This deploy allows at most Invitation only (SIGNUP_MODE_MAX is invite); the deploy must allow more first.")
  })
})
