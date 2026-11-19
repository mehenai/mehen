import { expect, test } from "bun:test"
import { publicFieldRefusal, secretLikeness } from "./secret-likeness.ts"

test("a PEM block, a URL with a password, a provider key or a long random string looks like a secret", () => {
  expect(secretLikeness("-----BEGIN OPENSSH PRIVATE KEY-----\nabc")).toBe("it contains a PEM block")
  expect(secretLikeness("postgres://app:hunter2@db.example.com/app")).toBe("it is a URL with a password in it")
  expect(secretLikeness("sk-proj-abcdefghij")).toBe('it starts like a provider key ("sk-proj-")')
  expect(secretLikeness("token=ghp_abcdefghijk")).toBe('it starts like a provider key ("ghp_")')
  expect(secretLikeness("https://example.com/?k=Zq8vN2xL7pR4tY9wK3mB6cH1")).toBe("it contains a long random-looking string")
})

test("ordinary config does not look like a secret", () => {
  for (const value of ["info", "production", "3000", "true", "https://api.example.com/v1", "postgres://db.example.com/app", "sk-short", "a".repeat(40)]) {
    expect(secretLikeness(value), value).toBeNull()
  }
})

test("a canonical UUID on its own does not look like a secret, in any case or as a URL path segment", () => {
  for (const value of ["8f3c2a1e-7b6d-4c5e-9a0f-1b2c3d4e5f60", "8F3C2A1E-7B6D-4C5E-9A0F-1B2C3D4E5F60", "client_id=8f3c2a1e-7b6d-4c5e-9a0f-1b2c3d4e5f60", "https://api.example.com/v1/projects/8f3c2a1e-7b6d-4c5e-9a0f-1b2c3d4e5f60"]) {
    expect(secretLikeness(value), value).toBeNull()
    expect(publicFieldRefusal("oauth-client", "client_id", value), value).toBeNull()
  }
  for (const value of ["8f3c2a1e7b6d4c5e9a0f1b2c3d4e5f60aa", "key-8f3c2a1e-7b6d-4c5e-9a0f-1b2c3d4e5f60", "8f3c2a1e-7b6d-4c5e-9a0f-1b2c3d4e5f60Zq8vN2xL", "8f3c2a1e-7b6d-4c5e-9a0f-1b2c3d4e5f6g"]) {
    expect(secretLikeness(value), value).toBe("it contains a long random-looking string")
  }
})

test("the reason never echoes the value", () => {
  const value = "sk-ant-api03-SENTINELabcdefghijklmnop"
  expect(secretLikeness(value)).not.toContain("SENTINEL")
})

test("a public field is refused when the kind has no such public field or its value looks like a secret, never echoing the value", () => {
  expect(publicFieldRefusal("file", "filename", "AuthKey_SENTINELq8vN2xL7pR4tY9wK3mB6cH1.p8")).toBe('"filename" looks like a secret; send it sealed, as a secret field.')
  expect(publicFieldRefusal("file", "content", "x")).toBe('"content" is not a public field of a Secret file.')
  expect(publicFieldRefusal("file", "nope", "x")).toBe('"nope" is not a public field of a Secret file.')
  expect(publicFieldRefusal("file", "filename", "AuthKey.p8")).toBeNull()
})

test("an SSH key's public key is public, however random it looks", () => {
  const publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIZq8vN2xL7pR4tY9wK3mB6cH1Zq8vN2xL7pR4 me@laptop"
  expect(secretLikeness(publicKey)).not.toBeNull()
  expect(publicFieldRefusal("ssh-key", "public_key", publicKey)).toBeNull()
  expect(publicFieldRefusal("basic-auth", "username", publicKey)).toBe('"username" looks like a secret; send it sealed, as a secret field.')
})
