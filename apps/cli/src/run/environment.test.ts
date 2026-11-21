import { describe, expect, test } from "bun:test"
import { EXIT } from "@mehen/protocol/api"
import { CommandError } from "./deps.ts"
import { inheritedEnv, resolveEnv } from "./environment.ts"
import { capture } from "./fake-vault-api.ts"
import type { Manifest } from "./manifest.ts"

const manifest: Manifest = {
  path: "/repo/mehen.toml",
  project: "prj_1",
  workspace: null,
  vault: null,
  defaultEnv: "dev",
  vars: [
    { name: "DATABASE_URL", source: "vault" },
    { name: "LOG_LEVEL", source: "plain", value: "info" },
  ],
}

describe("resolveEnv", () => {
  test("--env beats MEHEN_ENV beats default_env, and says which one won", () => {
    expect(resolveEnv("staging", { MEHEN_ENV: "test" }, manifest)).toEqual({ env: "staging", source: "flag" })
    expect(resolveEnv(undefined, { MEHEN_ENV: "test" }, manifest)).toEqual({ env: "test", source: "env-var" })
    expect(resolveEnv(undefined, { MEHEN_ENV: "" }, manifest)).toEqual({ env: "dev", source: "default" })
    expect(resolveEnv(undefined, {}, manifest)).toEqual({ env: "dev", source: "default" })
  })

  test("MEHEN_ENV naming a protected environment is still sent as env-var, for the vault to refuse", () => {
    expect(resolveEnv(undefined, { MEHEN_ENV: "prod" }, manifest)).toEqual({ env: "prod", source: "env-var" })
  })

  test("no environment at all, or a malformed one, is a usage error", () => {
    const noDefault = { ...manifest, defaultEnv: null }
    expect(() => resolveEnv(undefined, {}, noDefault)).toThrow(CommandError)
    try {
      resolveEnv("Prod!", {}, manifest)
      throw new Error("expected a refusal")
    } catch (error) {
      expect(error).toBeInstanceOf(CommandError)
      expect((error as CommandError).code).toBe(EXIT.usage)
    }
  })
})

describe("inheritedEnv", () => {
  test("drops MEHEN_* and declared ambient variables, warning for each override", () => {
    const err = capture()
    const env = inheritedEnv({ PATH: "/bin", MEHEN_ENV: "dev", MEHEN_TOKEN: "x", DATABASE_URL: "postgres://prod", LOG_LEVEL: "debug", HOME: "/home/a" }, manifest.vars.map((v) => v.name), [], err)
    expect(env).toEqual({ PATH: "/bin", HOME: "/home/a" })
    expect(err.text()).toContain("ignoring DATABASE_URL from your shell")
    expect(err.text()).toContain("ignoring LOG_LEVEL from your shell")
    expect(err.text()).not.toContain("postgres://prod")
  })

  test("drops a variable an --item sets, naming the item", () => {
    const err = capture()
    expect(inheritedEnv({ PATH: "/bin", OPENAI_API_KEY: "sk-from-shell" }, [], [{ item: "openai", variable: "OPENAI_API_KEY" }], err)).toEqual({ PATH: "/bin" })
    expect(err.text()).toBe("mehen: warning: ignoring OPENAI_API_KEY from your shell; --item openai sets it\n")
  })
})
