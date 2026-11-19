import type { Env } from "../src/env.ts"
import { refreshAccountRecoverySetup } from "../src/directory/account-recovery-setup.ts"
import { expect } from "vitest"
import { ERROR_HEADER,HTTP_STATUS_FOR_ERROR,type ApiError } from "@mehen/protocol"
import { responseFor } from "../src/http.ts"
import { base64UrlEncode, utf8 } from "@mehen/protocol"
import { type PasskeyCeremonies, simpleWebAuthnCeremonies } from "../src/directory/webauthn.ts"
import type { DirectoryWorkspaceClient } from "../src/directory/workspace-client.ts"
export const directoryCeremonies: PasskeyCeremonies = {
  ...simpleWebAuthnCeremonies,
  async verifyRegistration(response,expected) {
    const inner = response.response as { clientDataJSON?: string }
    const challenge = JSON.parse(atob((inner.clientDataJSON ?? "").replaceAll("-","+").replaceAll("_","/"))).challenge as string
    if (challenge !== expected.challenge || response.fail === true) return null
    return { credentialId: response.id as string,publicKey: new Uint8Array([1,2,3]),counter: 0,transports: [],aaguid: null,deviceType: null,backedUp: null }
  },
  async verifyAuthentication(response) { return response.fail === true ? null : { counter: 1,backedUp: false } },
}
export function directoryRegistration(id: string,challenge: string): Record<string,unknown> { return { id,rawId: id,type: "public-key",response: { clientDataJSON: base64UrlEncode(utf8(JSON.stringify({ challenge }))) } } }
export function successfulDirectoryClient(): DirectoryWorkspaceClient {
  return { async install(_w,i) { return { installedEpoch: i.committedEpoch } },async commit(_w,i) { return { installedEpoch: i.committedEpoch } },async mirror() {},async restriction() {},async revokeSession() {} }
}

export async function expectDirectoryRefusal(operation: Promise<unknown>,body: ApiError): Promise<void> {
  try { await operation } catch (error) {
    const response = responseFor(error)
    expect(response.status).toBe(HTTP_STATUS_FOR_ERROR[body.error])
    expect(response.headers.get(ERROR_HEADER)).toBe("1")
    expect(await response.json()).toEqual(body)
    return
  }
  throw new Error("Expected a directory refusal")
}

export async function seedAccountRecoverySetup(env: Env,account: string,now = Date.now()): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("INSERT INTO recovery_codes(code_hash,account,batch,position,status,created_at) VALUES (?,?,?,1,'active',?) ON CONFLICT(code_hash) DO UPDATE SET status='active',used_by_session=NULL,used_at=NULL").bind(`fixture-code:${account}`,account,`fixture-batch:${account}`,now),
    refreshAccountRecoverySetup(env,account,now),
  ])
}
