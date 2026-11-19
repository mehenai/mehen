// A machine's config root before 0.3.0, byte for byte apart from
// the vault origin, which the test supplies (a mock vault's port): the
// default context enrolled in Northwind with an enclave key at the root,
// contexts/example/ holding the expired Personal enrolment, the hand-made
// revoked-* folder, the release caches, default-context and setup-state.json.
//
// The keys are test keys made for this fixture: the "enclave blob" is the
// fake helper's format (testing/fake-mehen-se.ts), so the migrated slot still
// signs through MEHEN_SE_PATH. Nothing here is a real key or a real file.

import { mkdir, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { askUrl, enrolAsk, intakeAsk } from "../../../ask.ts"

export const MACHINE_NORTHWIND = { tenant: "tn_Nw4dQ2m8xPLsJyKb3Rtvz", device: "dev_machineNw00001", slug: "northwind", name: "Northwind" } as const
export const MACHINE_PERSONAL = { tenant: "tn_Ex7mR4pLq9WzTnVc2Hdyk", slug: "example", name: "Personal", enrolment: "enr_f1xtR3cP4y5KIRtrusg", code: "K4T7W9QZ" } as const
export const MACHINE_STRAY = "revoked-dev_fx7QpwWDCq8M7BKe1KMrB-20261028"
export const MACHINE_INTAKE = "int_officeOpen0001"
export const MACHINE_OWNER = { kind: "member" as const, member: "mem_alexMachin001", name: "Alex" }

// The enclave blob's key (fake helper format) and the Personal software key.
const ENCLAVE_PRIVATE = { kty: "EC", crv: "P-256", x: "Ekzk-3YAl5EFT8PdG-OL-fGTxt6HQ_fLUWLD2-_LX_M", y: "AYg84JWP2V_LLu79MmUCANgskT3RXSnAGKhhl0tFH8M", d: "DFv014EBuKfQgahdN5jYZNMEcYeigUaMBMDS0YGZ_rk" } as const
const PERSONAL_PRIVATE = { kty: "EC", crv: "P-256", x: "lj3tBZ2l8UMW9gpqSGQfrN68mDdpzQfKM7FKvm_NTPY", y: "_e9H2jyRodY8x2DiMGlZuPSfX_3zvZif6FdkAOL2ejU", d: "VNUoc7Zlh6aB65ubDitiw_XjluhQw2MdTLDnXQnxSis" } as const
export const MACHINE_ENCLAVE_JWK = { kty: "EC" as const, crv: "P-256" as const, x: ENCLAVE_PRIVATE.x, y: ENCLAVE_PRIVATE.y }
export const MACHINE_PERSONAL_JWK = { kty: "EC" as const, crv: "P-256" as const, x: PERSONAL_PRIVATE.x, y: PERSONAL_PRIVATE.y }

const CREATED = "2026-10-28T12:00:00.000Z"
const EXPIRED = "2026-10-28T12:15:00.000Z"
const OPEN_UNTIL = "2099-01-01T00:00:00.000Z"

async function file(path: string, value: unknown): Promise<void> {
  await writeFile(path, typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 })
}

async function directory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 })
}

// Builds the fixture under `root` (created 0700) for a vault at `origin`.
export async function buildMachineFixture(root: string, origin: string): Promise<void> {
  await directory(root)
  const northwind = { vaultUrl: origin, workspaceSlug: MACHINE_NORTHWIND.slug }
  const intakeLink = askUrl(`${origin}/w/${MACHINE_NORTHWIND.slug}/i/${MACHINE_INTAKE}`, northwind)
  const enrolLink = askUrl(`${origin}/w/${MACHINE_PERSONAL.slug}/e/${MACHINE_PERSONAL.code}`, { vaultUrl: origin, workspaceSlug: MACHINE_PERSONAL.slug })
  if (!intakeLink || !enrolLink) throw new Error("the fixture origin must be a vault origin mehen accepts")
  const by = { device: "sam-mac-mini", session: "pi-office" }

  // The default context: Northwind, enclave key, one open intake.
  await file(join(root, "config.json"), { vault: origin, tenant: MACHINE_NORTHWIND.tenant, device: MACHINE_NORTHWIND.device, backend: "secure-enclave", fingerprint: "ZLSQ 8ZY0 FNHK WLS5", workspaceSlug: MACHINE_NORTHWIND.slug, workspaceName: MACHINE_NORTHWIND.name, owner: MACHINE_OWNER })
  await file(join(root, "device-key.se"), ENCLAVE_PRIVATE)
  await file(join(root, "device-key.se.pub.json"), MACHINE_ENCLAVE_JWK)
  await file(join(root, "device-key.se.scope.json"), { vault: origin, tenant: MACHINE_NORTHWIND.tenant })
  const intake = { ...intakeAsk({ id: MACHINE_INTAKE, url: intakeLink.url, name: "openai-office", kind: "api-key", provider: "openai", reason: "summarise the support inbox", expiresAt: OPEN_UNTIL, requestedBy: by }), context: { origin, workspace: { id: MACHINE_NORTHWIND.tenant, slug: MACHINE_NORTHWIND.slug, name: MACHINE_NORTHWIND.name }, device: MACHINE_NORTHWIND.device } }
  await file(join(root, "ledger.json"), { entries: [{ ask: intake, createdAt: CREATED, origin, workspace: MACHINE_NORTHWIND.tenant, device: MACHINE_NORTHWIND.device, slug: "openai-office", command: 'mehen request api-key --name openai-office --provider openai --reason "summarise the support inbox"' }] })
  await file(join(root, "update-check.json"), { checkedAt: CREATED, latest: "0.2.0" })
  await file(join(root, "default-context"), { origin, workspace: MACHINE_NORTHWIND.tenant })
  await file(join(root, "setup-state.json"), { ".claude.json": { server: "mehen", binary: "/Users/sam/.local/bin/mehen" }, ".claude.json#mehen-example": { server: "mehen-example", binary: "/Users/sam/.local/bin/mehen" } })

  // contexts/example: the Personal enrolment, expired at the vault long ago.
  const personal = join(root, "contexts", MACHINE_PERSONAL.slug)
  await directory(personal)
  await file(join(personal, "device-key.json"), PERSONAL_PRIVATE)
  await file(join(personal, "device-key.scope.json"), { vault: origin, tenant: null })
  const enrol = { ...enrolAsk({ id: MACHINE_PERSONAL.enrolment, url: enrolLink.url, name: "sam-mac-mini", backend: "software", fingerprint: "4SDW M2HG 3T0W 9MMW", expiresAt: EXPIRED, requestedBy: by }), context: { origin, workspace: null, device: null } }
  await file(join(personal, "ledger.json"), { entries: [{ ask: enrol, createdAt: CREATED, origin, workspace: null, device: null, slug: null, command: `mehen enrol --workspace ${MACHINE_PERSONAL.slug} --name sam-mac-mini --backend software`, enrol: { code: MACHINE_PERSONAL.code, name: "sam-mac-mini", backend: "software", jwk: MACHINE_PERSONAL_JWK, workspace: MACHINE_PERSONAL.slug, team: null } }] })
  await file(join(personal, "update-check.json"), { checkedAt: CREATED, latest: "0.2.0" })

  // The hand-made stray: a revoked device's old config and its cache.
  const stray = join(root, MACHINE_STRAY)
  await directory(stray)
  await file(join(stray, "config.json"), { vault: origin, tenant: MACHINE_NORTHWIND.tenant, device: "dev_fx7QpwWDCq8M7BKe1KMrB", backend: "secure-enclave", workspaceSlug: MACHINE_NORTHWIND.slug, workspaceName: MACHINE_NORTHWIND.name })
  await file(join(stray, "update-check.json"), { checkedAt: CREATED, latest: "0.2.0" })
}
