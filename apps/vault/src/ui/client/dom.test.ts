import { describe, expect, it } from "vitest"
import { browserRefusalWords } from "./dom.ts"

// The error @simplewebauthn/browser throws: an Error named after the
// browser's own refusal, with its code.
function webAuthnError(name: string, code: string): Error {
  const error = new Error("The authenticator was previously registered")
  error.name = name
  Object.assign(error, { code })
  return error
}

describe("browserRefusalWords", () => {
  it("a second passkey on a device that already holds one says so and what to do instead", () => {
    const words = browserRefusalWords(webAuthnError("InvalidStateError", "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED"))
    expect(words).toEqual({ title: "This device already has a passkey for your account.", say: "Add the new one on another device or a security key instead. Nothing was changed." })
    expect(browserRefusalWords(new DOMException("excluded", "InvalidStateError"))?.title).toBe("This device already has a passkey for your account.")
  })

  it("a cancelled or timed out prompt keeps its words", () => {
    for (const error of [webAuthnError("NotAllowedError", "ERROR_CEREMONY_ABORTED"), new DOMException("cancelled", "NotAllowedError"), new DOMException("aborted", "AbortError")]) {
      expect(browserRefusalWords(error)?.title).toBe("The passkey check did not finish.")
    }
  })

  it("anything else is not the browser's refusal", () => {
    expect(browserRefusalWords(new Error("boom"))).toBeNull()
    expect(browserRefusalWords("boom")).toBeNull()
  })
})
