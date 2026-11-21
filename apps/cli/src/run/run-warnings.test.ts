import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { chmodSync, existsSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { removeDir, tempDir } from "./fake-vault-api.ts"
import { RUN_COMPATIBILITY_URL, bypassWarning, childNodeVersion, dotenvFiles, dotenvWarning, nodeProxyGap, nodeWarning, startsNode } from "./run-warnings.ts"

let dir: string

beforeAll(() => {
  dir = tempDir("mehen-run-warnings-")
})

afterAll(() => {
  if (dir !== undefined) removeDir(dir)
})

// A stand-in `node` that prints `version` for --version and records that it was asked.
function fakeNode(folder: string, version: string, sleepSeconds = 0): string {
  mkdirSync(folder, { recursive: true })
  const path = join(folder, "node")
  writeFileSync(path, `#!/bin/sh\nif [ "$1" = "--version" ]; then touch "${folder}/asked"; sleep ${sleepSeconds}; echo ${version}; fi\nexit 0\n`)
  chmodSync(path, 0o755)
  return path
}

describe(".env files", () => {
  test("finds .env and .env.* files in each folder once, and leaves out examples, .envrc, folders and dangling links", () => {
    const root = join(dir, "root")
    const sub = join(root, "app")
    mkdirSync(join(sub, ".env.d"), { recursive: true })
    for (const name of [".env", ".env.local", ".env.example", ".env.sample", ".env.template", ".envrc", "env", "x.env"]) writeFileSync(join(root, name), "A=1\n")
    writeFileSync(join(sub, ".env.production"), "A=1\n")
    symlinkSync(join(root, "missing"), join(sub, ".env.dangling"))
    symlinkSync(join(root, ".env"), join(sub, ".env.linked"))
    symlinkSync(root, join(dir, "root-link"))
    expect(dotenvFiles([root, sub, join(dir, "root-link"), join(root, "nowhere")])).toEqual([join(root, ".env"), join(root, ".env.local"), join(sub, ".env.linked"), join(sub, ".env.production")])
  })

  test("the warning names each file, relative to the working folder when inside it, with one adopt command per file", () => {
    const warning = dotenvWarning([join(dir, ".env"), "/elsewhere/.env.local"], dir, "bun")
    expect(warning?.message).toBe(".env, /elsewhere/.env.local are next to this run: Bun, Next.js, Vite, dotenv and others load them by themselves, so bun can see their plaintext values instead of the vault's")
    expect(warning?.next.say).toContain("mehen adopt retire")
    expect(warning?.commands).toEqual(["mehen adopt file .env", "mehen adopt file /elsewhere/.env.local"])
    expect(dotenvWarning([join(dir, ".env")], dir, "bun")?.message).toStartWith(".env is next to this run:")
    expect(dotenvWarning([], dir, "bun")).toBeNull()
  })
})

describe("Node versions", () => {
  test("NODE_USE_ENV_PROXY covers every request from 22.21.0 on 22 and from 24.5.0; 24.0 to 24.4 cover fetch only", () => {
    for (const version of ["v22.21.0", "v22.22.1", "v24.5.0", "v24.22.3", "v25.0.0", "v26.13.1"]) expect(nodeProxyGap(version)).toBeNull()
    for (const version of ["v24.0.0", "v24.4.1"]) expect(nodeProxyGap(version)).toBe("fetch-only")
    for (const version of ["v22.20.0", "v23.11.1", "v20.19.5", "v18.0.0"]) expect(nodeProxyGap(version)).toBe("none")
    expect(nodeProxyGap("not a version")).toBeNull()
  })

  test("the warning gives the minimum and what happens to the placeholder", () => {
    expect(nodeWarning("v20.11.0")?.message).toBe("Node v20.11.0 ignores NODE_USE_ENV_PROXY, so its requests skip mehen's local relay: a placeholder they send goes straight to the API, which answers 401")
    expect(nodeWarning("v24.4.0")?.message).toContain("honours NODE_USE_ENV_PROXY for fetch() only, so node:http and node:https requests skip")
    expect(nodeWarning("v20.11.0")?.next.say).toBe(`Use Node 22.21.0 or later on 22, or 24.5.0 or later. Other options: ${RUN_COMPATIBILITY_URL}`)
    expect(nodeWarning("v24.5.0")).toBeNull()
  })

  test("only node, npm, npx, pnpm, yarn and tsx count as starting Node, by basename", () => {
    for (const argv0 of ["node", "/usr/local/bin/node", "npm", "npx", "pnpm", "yarn", "tsx", "node.exe", "npx.cmd"]) expect(startsNode(argv0)).toBe(true)
    for (const argv0 of ["bun", "deno", "python3", "nodemon", "sh"]) expect(startsNode(argv0)).toBe(false)
  })

  test("asks the node on the child's PATH, for node itself by its path, and gives up on a slow one", async () => {
    const old = join(dir, "old-node")
    fakeNode(old, "v20.11.0")
    expect(await childNodeVersion("npx", { PATH: `${old}:/usr/bin:/bin` }, dir)).toBe("v20.11.0")
    const pinned = fakeNode(join(dir, "pinned-node"), "v22.21.0")
    expect(await childNodeVersion(pinned, { PATH: `${old}:/usr/bin:/bin` }, dir)).toBe("v22.21.0")
    const other = join(dir, "other-node")
    fakeNode(other, "v20.11.0")
    expect(await childNodeVersion("bun", { PATH: `${other}:/usr/bin:/bin` }, dir)).toBeNull()
    expect(existsSync(join(other, "asked"))).toBe(false)
    expect(await childNodeVersion("node", { PATH: join(dir, "nowhere") }, dir)).toBeNull()
    const slow = join(dir, "slow-node")
    fakeNode(slow, "v20.11.0", 5)
    const started = Date.now()
    expect(await childNodeVersion("node", { PATH: `${slow}:/usr/bin:/bin` }, dir, 300)).toBeNull()
    expect(Date.now() - started).toBeLessThan(3000)
  })
})

describe("relay bypass", () => {
  test("names up to three hosts and links the compatibility guide", () => {
    expect(bypassWarning(["api.openai.com"], "python3")?.message).toBe(
      "no connection to api.openai.com came through mehen's local relay. If python3 called it, it bypassed the proxy (some HTTP clients ignore HTTPS_PROXY) and the API saw only the placeholder",
    )
    expect(bypassWarning(["a.test", "b.test", "c.test", "d.test", "e.test"], "go")?.message).toStartWith("no connection to a.test, b.test, c.test and 2 more came through")
    expect(bypassWarning(["a.test"], "go")?.next.say).toContain(RUN_COMPATIBILITY_URL)
    expect(bypassWarning([], "go")).toBeNull()
  })
})
