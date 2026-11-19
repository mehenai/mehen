import { describe, expect, it } from "bun:test"
import { dockerRegistry, parseDocker, parseDotenv, parseGhHosts, parseJson, parsePlist, parseSystemd } from "./parse.ts"

const values = (text: string, envrc = false) => Object.fromEntries(parseDotenv(text, { envrc }).entries.map((e) => [e.variable, e.value]))

describe("dotenv", () => {
  it("reads export, comments, quotes and inline comments as dotenv does", () => {
    const text = ["# a comment", "export A=one", "B = two # trailing", "C='single # kept'", 'D="esc\\naped \\"q\\""', "E=", "", "F=with=equals"].join("\n")
    expect(values(text)).toEqual({ A: "one", B: "two", C: "single # kept", D: 'esc\naped "q"', E: "", F: "with=equals" })
  })

  it("reads a multi-line quoted value and keeps counting lines after it", () => {
    const parsed = parseDotenv('KEY="-----BEGIN X-----\nabc\n-----END X-----"\nNEXT=1\n')
    expect(parsed.entries.map((e) => [e.variable, e.line])).toEqual([["KEY", 1], ["NEXT", 4]])
    expect(parsed.entries[0]?.value).toBe("-----BEGIN X-----\nabc\n-----END X-----")
  })

  it("reports a bad line by number and reason, never its content", () => {
    const parsed = parseDotenv("GOOD=1\nthis is sentinel-content-xyz\nOPEN=\"never closes\n")
    expect(parsed.errors).toEqual([{ line: 2, why: "not NAME=value" }, { line: 3, why: "a quote that never closes" }])
    expect(JSON.stringify(parsed.errors)).not.toContain("sentinel")
  })
})

describe(".envrc", () => {
  it("reads literal exports only and reports dynamic lines without a value", () => {
    const parsed = parseDotenv(["export LITERAL=abc", "export SUB=$(pass show x)", "export TICK=`cat f`", 'export BRACE="${HOME}/x"', "export REF=$OTHER", "dotenv", "use nix", "PLAIN=not-exported"].join("\n"), { envrc: true })
    expect(parsed.entries.map((e) => [e.variable, e.value])).toEqual([["LITERAL", "abc"], ["SUB", null], ["TICK", null], ["BRACE", null], ["REF", null]])
    expect(parsed.errors).toEqual([])
  })
})

describe("JSON settings", () => {
  it("reports candidate keys at any depth as JSON pointers", () => {
    const parsed = parseJson(JSON.stringify({ env: { OPENAI_API_KEY: "sk-x", theme: "dark" }, nested: [{ "api/token": "t" }], editor: { fontSize: "12" } }))
    expect(parsed.entries.map((e) => [e.pointer, e.variable])).toEqual([["/env/OPENAI_API_KEY", "OPENAI_API_KEY"], ["/nested/0/api~1token", null]])
  })

  it("reads a service account key file as one value", () => {
    const text = JSON.stringify({ type: "service_account", private_key: "x" })
    expect(parseJson(text).entries).toEqual([{ variable: null, pointer: "", line: 1, value: text }])
  })
})

describe("launchd and systemd", () => {
  it("reads a plist's EnvironmentVariables with entities decoded", () => {
    const plist = `<?xml version="1.0"?>\n<plist><dict>\n<key>Label</key><string>ai.x</string>\n<key>EnvironmentVariables</key>\n<dict>\n  <key>TOKEN</key>\n  <string>a&amp;b</string>\n  <key>EMPTY</key><string/>\n</dict>\n</dict></plist>`
    const parsed = parsePlist(plist)
    expect(parsed.entries.map((e) => [e.variable, e.value, e.line])).toEqual([["TOKEN", "a&b", 6], ["EMPTY", "", 8]])
  })

  it("reads Environment= words and EnvironmentFile= paths", () => {
    const unit = ["[Service]", 'Environment="A=one two" B=three', "Environment=C='x y'", "EnvironmentFile=-%h/.config/svc.env", "EnvironmentFile=/etc/%i.env"].join("\n")
    const parsed = parseSystemd(unit, "/home/u")
    expect(parsed.entries.map((e) => [e.variable, e.value])).toEqual([["A", "one two"], ["B", "three"], ["C", "x y"]])
    expect(parsed.envFiles).toEqual(["/home/u/.config/svc.env"])
  })
})

describe("login state", () => {
  it("finds gh's oauth_token under its host, in either layout", () => {
    const parsed = parseGhHosts("github.com:\n    users:\n        sam:\n            oauth_token: gho_abc\n    oauth_token: gho_abc\n    user: sam\n")
    expect(parsed.entries.map((e) => e.pointer)).toEqual(["/github.com/users/sam/oauth_token", "/github.com/oauth_token"])
  })

  it("splits a docker auth into user and password under its registry", () => {
    const auth = Buffer.from("me:pa:ss").toString("base64")
    const parsed = parseDocker(JSON.stringify({ auths: { "https://index.docker.io/v1/": { auth }, "ghcr.io": {} } }))
    expect(parsed.entries.map((e) => [e.pointer, e.value])).toEqual([
      ["/auths/https:~1~1index.docker.io~1v1~1/auth/username", "me"],
      ["/auths/https:~1~1index.docker.io~1v1~1/auth/password", "pa:ss"],
    ])
    expect(dockerRegistry(parsed.entries[0]?.pointer as string)).toBe("index.docker.io")
  })
})
