import { afterEach, describe, expect, test } from "bun:test"
import { chmod, lstat, mkdir, stat, symlink, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { DEFAULT_VAULT_URL, configPath, ensureConfigDir, readConfig, resolveVaultUrl, writeConfig } from "./config.ts"
import { SOFTWARE_KEY_FILE, createDeviceKey, loadDeviceKey } from "./device-key.ts"
import { CliError } from "./errors.ts"
import { tempDir } from "./testing/run-mehen.ts"

let dir: { path: string; remove(): Promise<void> }
afterEach(async () => dir?.remove())

async function mode(path: string): Promise<number> {
  return (await stat(path)).mode & 0o777
}

describe("config files", () => {
  test("config.json is written 0600 and read back", async () => {
    dir = await tempDir()
    const config = { vault: "https://vault.example", tenant: "ten_a", device: "dev_a", backend: "software" as const }
    await writeConfig(dir.path, config)
    expect(await mode(configPath(dir.path))).toBe(0o600)
    expect(await readConfig(dir.path)).toEqual(config)
  })

  test("the machine's recorded name is read back; an empty or overlong one is refused; a field this version does not know is ignored", async () => {
    dir = await tempDir()
    const config = { vault: "https://vault.example", tenant: "ten_a", device: "dev_a", backend: "software" as const, name: "tom-laptop" }
    await writeConfig(dir.path, config)
    expect(await readConfig(dir.path)).toEqual(config)
    for (const name of ["", "x".repeat(65), 7]) {
      await writeFile(configPath(dir.path), JSON.stringify({ ...config, name }))
      await expect(readConfig(dir.path)).rejects.toBeInstanceOf(CliError)
    }
    await writeFile(configPath(dir.path), JSON.stringify({ ...config, later: "a field from a newer mehen" }))
    expect(await readConfig(dir.path)).toMatchObject(config)
  })

  test("rewriting a 0644 config.json leaves it 0600", async () => {
    dir = await tempDir()
    await writeFile(configPath(dir.path), "{}", { mode: 0o644 })
    await writeConfig(dir.path, { vault: "https://vault.example", tenant: "ten_a", device: "dev_a", backend: "software" })
    expect(await mode(configPath(dir.path))).toBe(0o600)
  })

  test("no config means not enrolled; a broken one is an error", async () => {
    dir = await tempDir()
    expect(await readConfig(dir.path)).toBeNull()
    await writeFile(configPath(dir.path), '{"vault":1}')
    await expect(readConfig(dir.path)).rejects.toBeInstanceOf(CliError)
  })

  test("the config directory is created 0700", async () => {
    dir = await tempDir()
    const nested = join(dir.path, "mehen")
    await writeConfig(nested, { vault: "https://vault.example", tenant: "ten_a", device: "dev_a", backend: "software" })
    expect(await mode(nested)).toBe(0o700)
  })

  test("an existing config directory this user owns is tightened to 0700 when its mode is looser", async () => {
    dir = await tempDir()
    const loose = join(dir.path, "mehen")
    await mkdir(loose, { mode: 0o755 })
    await chmod(loose, 0o755)
    expect(await mode(loose)).toBe(0o755)
    await ensureConfigDir(loose)
    expect(await mode(loose)).toBe(0o700)
    await ensureConfigDir(loose)
    expect(await mode(loose)).toBe(0o700)
  })

  test("a config directory that is a symbolic link is refused, before anything is written", async () => {
    dir = await tempDir()
    const real = join(dir.path, "real")
    await mkdir(real, { mode: 0o700 })
    const planted = join(dir.path, "mehen")
    await symlink(real, planted)
    const error = await ensureConfigDir(planted).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(CliError)
    expect((error as CliError).code).toBe("key_insecure")
    expect((error as CliError).message).toContain("symbolic link")
    await expect(writeConfig(planted, { vault: "https://vault.example", tenant: "ten_a", device: "dev_a", backend: "software" })).rejects.toBeInstanceOf(CliError)
    expect(await lstat(planted).then((i) => i.isSymbolicLink())).toBe(true)
    expect(await readConfig(real)).toBeNull()
    const file = join(dir.path, "file")
    await writeFile(file, "")
    await expect(ensureConfigDir(file)).rejects.toBeInstanceOf(CliError)
  })

})

describe("software device key", () => {
  test("device-key.json holds a private P-256 JWK, mode 0600, and signs", async () => {
    dir = await tempDir()
    const { key, jwk } = await createDeviceKey(dir.path, "software", {})
    const path = join(dir.path, SOFTWARE_KEY_FILE)
    expect(await mode(path)).toBe(0o600)
    const file = JSON.parse(await Bun.file(path).text()) as Record<string, string>
    expect(file).toMatchObject({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y })
    expect(file.d).toHaveLength(43)
    const signature = await key.signer("dev_x").sign(new TextEncoder().encode("hello"))
    expect(signature).toHaveLength(64)
    const loaded = await loadDeviceKey(dir.path, "software", {})
    const publicKey = await crypto.subtle.importKey("jwk", { ...jwk, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
    const again = await loaded.signer("dev_x").sign(new TextEncoder().encode("hello"))
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, again, new TextEncoder().encode("hello"))).toBe(true)
  })

  for (const insecure of [0o640, 0o604, 0o644, 0o660]) {
    test(`refuses to load a key file with mode ${insecure.toString(8)}`, async () => {
      dir = await tempDir()
      await createDeviceKey(dir.path, "software", {})
      await chmod(join(dir.path, SOFTWARE_KEY_FILE), insecure)
      const error = await loadDeviceKey(dir.path, "software", {}).catch((e: unknown) => e)
      expect(error).toBeInstanceOf(CliError)
      expect((error as CliError).code).toBe("key_insecure")
      expect((error as CliError).next?.command).toContain("chmod 600")
    })
  }

  test("a missing key file is an identity error pointing at mehen enrol", async () => {
    dir = await tempDir()
    const error = (await loadDeviceKey(dir.path, "software", {}).catch((e: unknown) => e)) as CliError
    expect(error.code).toBe("unauthenticated")
    expect(error.next?.command).toBe("mehen enrol --workspace <slug>")
  })
})

describe("vault URL", () => {
  const config = { vault: "https://enrolled.example", tenant: "t", device: "d", backend: "software" as const }

  test("MEHEN_VAULT_URL wins, then the enrolled vault, then the default", () => {
    expect(resolveVaultUrl({ MEHEN_VAULT_URL: "https://override.example/" }, config)).toBe("https://override.example")
    expect(resolveVaultUrl({}, config)).toBe("https://enrolled.example")
    expect(resolveVaultUrl({}, null)).toBe(DEFAULT_VAULT_URL)
  })

  test("plain http is refused except on this machine", () => {
    expect(() => resolveVaultUrl({ MEHEN_VAULT_URL: "http://vault.example" }, null)).toThrow(CliError)
    expect(resolveVaultUrl({ MEHEN_VAULT_URL: "http://127.0.0.1:8787" }, null)).toBe("http://127.0.0.1:8787")
    expect(resolveVaultUrl({ MEHEN_VAULT_URL: "http://localhost:8787" }, null)).toBe("http://localhost:8787")
  })
})
