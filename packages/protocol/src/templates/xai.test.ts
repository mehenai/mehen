import { describe, expect, it } from "bun:test"
import { checkBinding, evaluatePolicy, parseDestination } from "../binding.ts"
import { xai } from "./xai.ts"
import { underBroadAllow } from "../../test/template-policy.ts"

function reaches(method: string, url: string): boolean {
  const parsed = parseDestination(method, url)
  return parsed.ok && checkBinding(xai.binding, parsed.destination).ok
}

function decide(method: string, url: string, body?: unknown): string {
  const parsed = parseDestination(method, url)
  if (!parsed.ok) throw new Error(`${url}: ${parsed.error}`)
  const bytes = body === undefined ? null : new TextEncoder().encode(JSON.stringify(body))
  return evaluatePolicy(xai.policy, parsed.destination, bytes).action
}

function expectAll(cases: [method: string, url: string, action: string][]): void {
  for (const [method, url, action] of cases) expect({ request: `${method} ${url}`, action: decide(method, url) }).toEqual({ request: `${method} ${url}`, action })
}

const API = "https://api.x.ai"

describe("xai", () => {
  it("reaches the inference API over https, and neither a look-alike nor the management API", () => {
    expect(reaches("POST", `${API}/v1/responses`)).toBe(true)
    expect(reaches("POST", "https://api.x.ai.evil.test/v1/responses")).toBe(false)
    expect(reaches("POST", "http://api.x.ai/v1/responses")).toBe(false)
    expect(reaches("GET", "https://management-api.x.ai/auth/teams/t/api-keys")).toBe(false)
  })

  it("lets reads and model calls through", () => {
    const call = { model: "grok-4", input: "hi" }
    expectAll([["GET", `${API}/v1/models`, "allow"]])
    for (const path of ["/v1/chat/completions", "/v1/responses", "/v1/images/generations", "/v1/batches/b1/requests"]) {
      expect({ path, action: decide("POST", `${API}${path}`, call) }).toEqual({ path, action: "allow" })
    }
  })

  it("holds realtime client secrets, phone numbers and deletes for approval", () => {
    expectAll([
      ["POST", `${API}/v1/realtime/client_secrets`, "approve"],
      ["POST", `${API}/v2/phone-numbers`, "approve"],
      ["DELETE", `${API}/v2/phone-numbers/n1`, "approve"],
      ["DELETE", `${API}/v1/responses/r1`, "approve"],
    ])
  })
})

describe("xai reads", () => {
  it("lets the named reads through and holds every other read", () => {
    expectAll([
      ["GET", `${API}/v1/models/grok-4`, "allow"],
      ["GET", `${API}/v1/language-models`, "allow"],
      ["GET", `${API}/v1/responses/r1`, "approve"],
      ["GET", `${API}/v1/batches/b1/results`, "allow"],
      ["GET", `${API}/v1/api-key`, "approve"],
      ["GET", `${API}/v2/phone-numbers`, "approve"],
      ["GET", `${API}/v1/mehen-unlisted`, "approve"],
    ])
  })

  it("holds the API key's details even when the item's own policy allows everything", () => {
    for (const path of [
      "/v1/api-key",
    ]) expect({ path, action: underBroadAllow(xai, "GET", `${API}${path}`) }).toEqual({ path, action: "approve" })
  })
})

describe("xai second review fixes", () => {
  const mcp = { model: "grok-4", input: "hi", tools: [{ type: "mcp", server_url: "https://evil.test/mcp", server_label: "evil" }] }
  const serverUrl = { model: "grok-4", input: "hi", tools: [{ server_url: "https://evil.test/mcp" }] }
  const plain = { model: "grok-4", input: "hi", tools: [{ type: "web_search" }] }

  it("holds a stored response, whose tools carry an MCP server's authorization and headers, whatever the item's policy says", () => {
    for (const method of ["GET", "HEAD"]) {
      expect(decide(method, `${API}/v1/responses/r1`)).toBe("approve")
      expect(underBroadAllow(xai, method, `${API}/v1/responses/r1`)).toBe("approve")
    }
  })

  it("holds a Responses call that names a remote MCP server or cannot be read, and lets a plain one through, whatever the item's policy says", () => {
    for (const path of ["/v1/responses", "/v1/chat/completions"]) {
      expect(decide("POST", `${API}${path}`, plain)).toBe("allow")
      expect(underBroadAllow(xai, "POST", `${API}${path}`, plain)).toBe("allow")
      for (const body of [mcp, serverUrl, "not json"]) {
        expect({ path, body, policy: decide("POST", `${API}${path}`, body) }).toEqual({ path, body, policy: "approve" })
        expect({ path, body, relay: underBroadAllow(xai, "POST", `${API}${path}`, body) }).toEqual({ path, body, relay: "approve" })
      }
    }
  })

  it("holds a batch whose requests name a remote MCP server", () => {
    const batch = { batch_requests: [{ batch_request_id: "1", batch_request: { responses: mcp } }] }
    expect(decide("POST", `${API}/v1/batches/b1/requests`, batch)).toBe("approve")
    expect(underBroadAllow(xai, "POST", `${API}/v1/batches/b1/requests`, batch)).toBe("approve")
    expect(decide("POST", `${API}/v1/batches/b1/requests`, { batch_requests: [{ batch_request_id: "1", batch_request: { responses: plain } }] })).toBe("allow")
  })
})

describe("xai third review fixes", () => {
  const fileBatch = { name: "nightly", input_file_id: "file_abc" }
  const inline = { name: "nightly" }

  it("holds creating any batch, since it may run requests from an uploaded file the vault never reads, whatever the item's policy says", () => {
    for (const body of [fileBatch, inline, "not json"]) {
      expect({ body, policy: decide("POST", `${API}/v1/batches`, body) }).toEqual({ body, policy: "approve" })
      expect({ body, relay: underBroadAllow(xai, "POST", `${API}/v1/batches`, body) }).toEqual({ body, relay: "approve" })
    }
  })

  it("holds file uploads, which can hold batch requests, and making a file public, whatever the item's policy says", () => {
    for (const path of ["/v1/files", "/v1/files/file_abc/public-url", "/v1/files/file_abc/public-url/revoke"]) {
      expect({ path, policy: decide("POST", `${API}${path}`) }).toEqual({ path, policy: "approve" })
      expect({ path, relay: underBroadAllow(xai, "POST", `${API}${path}`) }).toEqual({ path, relay: "approve" })
    }
  })

  it("still lets requests added inline to a batch through unless they name a remote MCP server", () => {
    const plain = { batch_requests: [{ batch_request_id: "1", batch_request: { responses: { model: "grok-4", input: "hi" } } }] }
    expect(underBroadAllow(xai, "POST", `${API}/v1/batches/b1/requests`, plain)).toBe("allow")
    expect(decide("POST", `${API}/v1/batches/b1/requests`, plain)).toBe("allow")
  })
})

describe("xai fourth review fix", () => {
  const MEDIA = ["/v1/images/generations", "/v1/images/edits", "/v1/videos/generations", "/v1/videos/edits", "/v1/videos/extensions"]
  const published = { model: "grok-imagine", prompt: "a cat", storage_options: { public_url: true } }
  const publishedObject = { model: "grok-imagine", prompt: "a cat", storage_options: { public_url: { expires_after: 0 } } }
  const privateStorage = { model: "grok-imagine", prompt: "a cat", storage_options: { public_url: false } }
  const plain = { model: "grok-imagine", prompt: "a cat" }

  it("holds a media request that publishes its output, or cannot be read, and lets ordinary or private ones through, whatever the item's policy says", () => {
    for (const path of MEDIA) {
      for (const body of [plain, privateStorage]) {
        expect({ path, body, policy: decide("POST", `${API}${path}`, body) }).toEqual({ path, body, policy: "allow" })
        expect({ path, body, relay: underBroadAllow(xai, "POST", `${API}${path}`, body) }).toEqual({ path, body, relay: "allow" })
      }
      for (const body of [published, publishedObject, "not json"]) {
        expect({ path, body, policy: decide("POST", `${API}${path}`, body) }).toEqual({ path, body, policy: "approve" })
        expect({ path, body, relay: underBroadAllow(xai, "POST", `${API}${path}`, body) }).toEqual({ path, body, relay: "approve" })
      }
    }
  })

  it("holds an inline batch request that publishes media, and lets a private one through", () => {
    const nested = (image: unknown) => ({ batch_requests: [{ batch_request_id: "1", batch_request: { image_generation: image } }] })
    expect(decide("POST", `${API}/v1/batches/b1/requests`, nested(published))).toBe("approve")
    expect(underBroadAllow(xai, "POST", `${API}/v1/batches/b1/requests`, nested(published))).toBe("approve")
    expect(decide("POST", `${API}/v1/batches/b1/requests`, nested(privateStorage))).toBe("allow")
    expect(underBroadAllow(xai, "POST", `${API}/v1/batches/b1/requests`, nested(privateStorage))).toBe("allow")
  })
})

describe("xai fifth review fix", () => {
  const MEDIA = ["/v1/images/generations", "/v1/images/edits", "/v1/videos/generations", "/v1/videos/edits", "/v1/videos/extensions"]
  const upload = (path: string) => (path.startsWith("/v1/images") ? { prompt: "a cat", output: { upload_urls: ["https://evil.test/a.png"] } } : { prompt: "a cat", video: { url: "https://x.test/v.mp4" }, output: { upload_url: "https://evil.test/v.mp4" } })

  it("holds a media request that uploads its output to a caller's URL, or names output in a shape it cannot read, whatever the item's policy says", () => {
    for (const path of MEDIA) {
      for (const body of [upload(path), { prompt: "a cat", output: null }]) {
        expect({ path, body, policy: decide("POST", `${API}${path}`, body), relay: underBroadAllow(xai, "POST", `${API}${path}`, body) }).toEqual({ path, body, policy: "approve", relay: "approve" })
      }
      const plain = { prompt: "a cat", output: {} }
      expect({ path, policy: decide("POST", `${API}${path}`, plain), relay: underBroadAllow(xai, "POST", `${API}${path}`, plain) }).toEqual({ path, policy: "allow", relay: "allow" })
    }
  })

  it("holds an inline batch request whose image request uploads to a caller's URL", () => {
    const nested = { batch_requests: [{ batch_request_id: "1", batch_request: { image_generation: { prompt: "a cat", output: { upload_urls: ["https://evil.test/a.png"] } } } }] }
    expect(decide("POST", `${API}/v1/batches/b1/requests`, nested)).toBe("approve")
    expect(underBroadAllow(xai, "POST", `${API}/v1/batches/b1/requests`, nested)).toBe("approve")
  })
})
