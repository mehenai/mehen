import { describe, expect, it } from "bun:test"
import { base64UrlEncode, utf8 } from "@mehen/protocol/bytes"
import { CliError } from "../errors.ts"
import { OutputGuard, OutputWithheld, WITHHELD } from "./output-guard.ts"

describe("OutputGuard", () => {
  const value = "hunter2-secret-value"

  it("withholds a line that contains a value read, as is or encoded", () => {
    const guard = new OutputGuard()
    guard.add(value, "secret")
    expect(guard.clean("uploaded 3 items to adp_x")).toBe(true)
    expect(() => guard.assertClean(`DB=${value}`)).toThrow(WITHHELD)
    expect(guard.clean(base64UrlEncode(utf8(value)))).toBe(false)
    expect(guard.clean(encodeURIComponent(`${value}/x`))).toBe(false)
    expect(guard.clean([...utf8(value)].map((b) => `%${b.toString(16)}`).join(""))).toBe(false)
  })

  it("lets an error through only when its message and next step are clean", () => {
    const guard = new OutputGuard()
    guard.add(value, "unknown")
    expect(guard.error(new CliError("bad_request", "The plan has 1 problem."))).toBeInstanceOf(CliError)
    expect(guard.error(new CliError("bad_request", `unexpected ${value}`))).toBeInstanceOf(OutputWithheld)
    expect(guard.error(new CliError("bad_request", "x", { say: `try ${value}` }))).toBeInstanceOf(OutputWithheld)
    expect(guard.error(new Error(`boom ${value}`)).message).toBe(WITHHELD)
  })

  it("takes no needle from plain config, the fixed vocabulary or the paths it read", () => {
    const guard = new OutputGuard()
    guard.addPath("/Users/someone/code/billing-api/.env.production")
    guard.add("production", "config")
    guard.add("secret", "secret")
    guard.add("production", "unknown")
    guard.add("/Users/someone", "unknown")
    guard.add("/Users/someone/", "unknown")
    guard.add("billing", "secret")
    guard.add(value, "secret")
    expect(guard.clean('{"class":"secret","path":"/Users/someone/code/billing-api/.env.production","env":"production"}')).toBe(true)
    expect(guard.clean(`/Users/someone/code/${value}`)).toBe(false)
    expect(guard.size).toBe(7)
  })

  it("takes no needle from a value that sits inside a variable name or JSON pointer it read", () => {
    const guard = new OutputGuard()
    guard.add("SLACK_BOT_TOKEN", "unknown")
    guard.add("ollama", "secret")
    guard.add(value, "secret")
    const line = '{"variable":"SLACK_BOT_TOKEN","pointer":"/providers/ollamaCloud/apiKey"}'
    expect(guard.clean(line)).toBe(false)
    guard.addName("SLACK_BOT_TOKEN")
    guard.addName("/providers/ollamaCloud/apiKey")
    guard.addName(null)
    expect(guard.clean(line)).toBe(true)
    expect(guard.clean(`SLACK_BOT_TOKEN=${value}`)).toBe(false)
  })
})
