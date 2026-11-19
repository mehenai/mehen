// How the Worker reads a request before any workspace sees it: the body's
// shape, and the refusals every prefix answers in the vault's own JSON.
import { expect, it, vi } from "vitest"
import { MAX_JSON_DEPTH, parseJson } from "../src/http.ts"
import { z } from "zod"
import { createWorkspaceFixture } from "./workspace-fixtures.ts"
import { fetchWorkspaceWorker, ORIGIN } from "./helpers.ts"

const nested = (depth: number) => `${"[".repeat(depth)}${"]".repeat(depth)}`

it("a body nested past MAX_JSON_DEPTH is refused as bad_request, and one at the limit is read", () => {
  expect(parseJson(z.unknown(), new TextEncoder().encode(nested(MAX_JSON_DEPTH)))).toBeInstanceOf(Array)
  expect(() => parseJson(z.unknown(), new TextEncoder().encode(`{"a":${nested(MAX_JSON_DEPTH)}}`))).toThrow(`The body must be JSON nested at most ${MAX_JSON_DEPTH} levels deep.`)
})

it("a deeply nested body to a workspace route answers 400, never a 500 from the call into the workspace", async () => {
  const f = await createWorkspaceFixture()
  const errors = vi.spyOn(console, "error")
  try {
    for (const path of ["/api/w/alex/intakes", "/api/w/alex/connect", "/api/w/alex/policy/preview"]) {
      const response = await fetchWorkspaceWorker(f.env, path, { method: "POST", headers: { cookie: f.cookie, origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "application/json" }, body: `{"input":${nested(5000)}}` })
      expect({ path, status: response.status, body: await response.json() }).toEqual({ path, status: 400, body: { error: "bad_request", message: `The body must be JSON nested at most ${MAX_JSON_DEPTH} levels deep.` } })
    }
    expect(errors).not.toHaveBeenCalled()
  } finally {
    errors.mockRestore()
  }
})

it("a method a route does not take answers 405 with Mehen-Error under every prefix", async () => {
  const f = await createWorkspaceFixture()
  for (const path of ["/api/w/alex/members", "/api/account", "/v1/items", "/healthz"]) {
    const response = await fetchWorkspaceWorker(f.env, path, { method: "PATCH", headers: { cookie: f.cookie, origin: ORIGIN, "sec-fetch-site": "same-origin", "content-type": "application/json" }, body: "{}" })
    expect({ path, status: response.status, header: response.headers.get("Mehen-Error"), body: await response.json() }).toEqual({ path, status: 405, header: "1", body: { error: "bad_request", message: "Method not allowed." } })
  }
})
