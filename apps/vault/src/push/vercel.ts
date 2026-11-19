// A push into one Vercel project's environment variable for one target
// (vercel.com/docs/rest-api: "Find a project by id or name", GET
// /v9/projects/{idOrName}, and "Create one or more environment variables",
// POST /v10/projects/{idOrName}/env with upsert=true). The variable is
// `sensitive` (a Secret: write-only once saved) for every target: Vercel
// now allows Secrets in Development too. A 201 still lists the variables it
// could not write under `failed`.

import type { PushPreview } from "@mehen/protocol"
import { type PreviewAllowed, type ProviderWords, type PushCalls, type PushValue, type PushVia, type PushWritten, type VercelDestination, answerError, encodeSegment, field, ok, previewRead, readOk, providerRefused, pushFetch, scrubbedMessage, stringField, unreadableAnswer } from "./common.ts"

export const VERCEL_API = "https://api.vercel.com"

function teamQuery(d: VercelDestination): string {
  if (d.team === null) return ""
  return `${d.team.startsWith("team_") ? "teamId" : "slug"}=${encodeURIComponent(d.team)}`
}

function words(d: VercelDestination): ProviderWords {
  return { provider: "Vercel", place: `project ${d.project}${d.team === null ? "" : ` in team ${d.team}`}`, store: "environment variables" }
}

export function vercelCalls(d: VercelDestination): PushCalls {
  const project = `${VERCEL_API}/v9/projects/${encodeSegment(d.project)}`
  const team = teamQuery(d)
  return {
    preview: [{ method: "GET", url: team === "" ? project : `${project}?${team}` }],
    write: [{ method: "POST", url: `${VERCEL_API}/v10/projects/${encodeSegment(d.project)}/env?upsert=true${team === "" ? "" : `&${team}`}` }],
  }
}

function vercelMessage(body: unknown): string | null {
  return stringField(field(body, "error"), "message")
}

export async function vercelPreview(d: VercelDestination, via: PushVia, allowed: PreviewAllowed): Promise<Extract<PushPreview, { provider: "vercel" }>> {
  const preview: Extract<PushPreview, { provider: "vercel" }> = { provider: "vercel", projectId: null, projectName: null, accountId: null, repo: null, exists: null, updatedAt: null }
  const [projectCall] = vercelCalls(d).preview
  if (!allowed(projectCall!)) return preview
  const project = await previewRead(projectCall!, via, words(d), [], true)
  if (!readOk(project)) return preview
  preview.projectId = stringField(project.body, "id")
  preview.projectName = stringField(project.body, "name")
  preview.accountId = stringField(project.body, "accountId")
  const link = field(project.body, "link")
  const org = stringField(link, "org")
  const repo = stringField(link, "repo")
  preview.repo = org !== null && repo !== null ? `${org}/${repo}` : null
  return preview
}

export async function vercelWrite(d: VercelDestination, value: PushValue, via: PushVia): Promise<PushWritten> {
  const [writeCall] = vercelCalls(d).write
  const answer = await pushFetch(writeCall!, via, words(d), [], { key: d.name, value: value.value, type: "sensitive", target: [d.target] })
  if (!ok(answer)) throw answerError(answer, via, words(d), scrubbedMessage(vercelMessage(answer.body), value, via))
  if (typeof answer.body !== "object" || answer.body === null || Array.isArray(answer.body)) throw unreadableAnswer(words(d), "variable")
  const failed = field(answer.body, "failed")
  if (Array.isArray(failed) && failed.length > 0) {
    const message = scrubbedMessage(stringField(field(failed[0], "error"), "message"), value, via)
    throw providerRefused(answer.status, `Vercel did not write ${d.name}${message === null ? "." : `: ${message}`}`)
  }
  return { outcome: "set", providerStatus: answer.status }
}
