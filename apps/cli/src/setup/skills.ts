import { createHash } from "node:crypto"
import { mkdir, readFile, readdir, readlink, rename, rm, stat } from "node:fs/promises"
import { dirname, join, relative, resolve } from "node:path"
import skill from "../../../../skills/mehen/SKILL.md" with { type: "text" }
import { VERSION } from "../version.ts"
import { type AgentName, agents } from "./agents.ts"
import { atomicText, info, safePath, textFile } from "./files.ts"
import type { State } from "./state.ts"

// The skills report: what setup did to each skill
// location, which the updater stores verbatim. `external` is policy (a
// symlinked or foreign skill, or an existing backup, left alone); `failed`
// is a write or refusal error and makes setup exit 1; `removed` only in
// remove mode. There is no `skipped` skill status.
export type SkillStatus = "added" | "updated" | "unchanged" | "removed" | "external" | "failed"
export type SkillReport = { path: string; status: SkillStatus; reason?: string }
// `bases` are the folders the detected or named agents read: setup adds
// the skill only there, and elsewhere refreshes a managed copy it finds.
export type SkillOptions = { home: string; bases: readonly SkillBase[]; dryRun?: boolean; remove?: boolean; force?: boolean; skillsOnly?: boolean; state: State }

// The folders agents read skills from; each agent names one (agents.ts).
export type SkillBase = ".claude" | ".agents"
export const SKILL_BASES: readonly SkillBase[] = [".claude", ".agents"]
export function skillPath(home: string, base: SkillBase): string {
  return join(home, base, "skills", "mehen", "SKILL.md")
}
// A state key that records a skill rather than an MCP entry.
export const SKILL_HASH = "skill"

const STAMP = /^  mehen-version: [^\r\n]+$/m
export function stampedSkill(version = VERSION): string {
  return skill.replace(/\n---\r?\n/, `\nmetadata:\n  mehen-version: ${JSON.stringify(version)}\n---\n`)
}
export function skillSha256(text: string): string {
  return createHash("sha256").update(text).digest("hex")
}
// The unstamped skill each release shipped, which docs.mehen.dev/skill.md
// published byte for byte: `git show <commit>:skills/mehen/SKILL.md |
// shasum -a 256` at each release commit. Add the new release's on release.
export const RELEASED_SKILL_SHA256: Readonly<Record<string, string>> = {
  "0.1.0": "111763f1c8dd1f58a5ce42620a1b860e4b487f51b0593356acc3edd7f8f754b9", // ecc074a
  "0.2.0": "a56b285984293872b2fe1b8996dacacc123a5cf8df37c31ac81ee297356e64c6", // dc95a2c
  "0.3.0": "430f26266e36db7f39cbc70abc19e76248d42f500fcfe09f8620170e7bf524a7", // f077c6c
  "0.3.1": "ba5613313268c332eb7c0bc016a1e714d6282e14d04d57d0b1a5bc258dcdf0ff", // 4dd712b
  "0.3.2": "dbe5a30b6147d18ce64130faf8ce8ce71ee9e1215a16b9286a523ded09ffbb7b", // bdf35ef
  "0.3.3": "454fd77b7797432a3a14a814b8502e44305498501badff2502550cb00a8bd7d8", // 4fdea51
  "0.3.4": "6891a78477e48d88e44f03c72c737a013fc5bc152dca159c082c001087325fa5", // e22bf5e
  "0.3.5": "6891a78477e48d88e44f03c72c737a013fc5bc152dca159c082c001087325fa5", // cbfab8f
  "0.3.6": "6891a78477e48d88e44f03c72c737a013fc5bc152dca159c082c001087325fa5", // d34bc2e
  "0.3.7": "043e1ecfd2a8d87e85966701a13d1470e1dbed6a18fb565642effcb7d7166b8e", // 3d2ad4c
  "0.3.8": "7a338c622c6a40f8125b65d831df71a614745f5bd00194d63c5ded4d60cfe26f", // dbe7449
  "0.3.9": "7a338c622c6a40f8125b65d831df71a614745f5bd00194d63c5ded4d60cfe26f", // 958d563
  "0.3.10": "7a338c622c6a40f8125b65d831df71a614745f5bd00194d63c5ded4d60cfe26f", // d2e291a
  "0.3.11": "84fb8174830ab5b1c66113b8dc2ed0a25cfe8765bc3f41319db91a895ac5f315", // 9bba5b7
  "0.3.12": "f7d77b9824dfb9fdf440b3856c975b803837511752d52dfd15daf3961fd545af", // 4fea471
  "0.3.13": "f7d77b9824dfb9fdf440b3856c975b803837511752d52dfd15daf3961fd545af", // b63ec88
  "0.3.14": "f7d77b9824dfb9fdf440b3856c975b803837511752d52dfd15daf3961fd545af", // 8cc94de
  "0.3.15": "1cd4752e957d85586304bc4d5b302183f8c14099bfa32791bbe2400fca37fd25", // dec7a26
  "0.3.16": "1cd4752e957d85586304bc4d5b302183f8c14099bfa32791bbe2400fca37fd25", // d43cf71
  "0.3.17": "8a7465def6c2243d8be439be82dc35de01a4329f3a7ec41bf49c967cbf4605d2", // b956b66
  "0.3.18": "36ee96be6c4b5adbafb760246baaf15ddf73caa57a1a4aed8ff5a567482eee14", // 59845d9
  "0.3.19": "847b53ec6490fbf1fdecfb3ac440c5b65714bae827e5735311dcd02de5fa4555", // 97e8ade
  "0.4.0": "412e8a2324c6d922bff76b0e79f87b7f86c47f61f21d8bd1c5bb9268b13224d5", // f52635f
  "0.4.1": "33fad9a8036e5d1e641b7f98ad7b45205268e2e76b76798dccb5467085f3d0e2", // a49c8aa
}
const RELEASED = new Set(Object.values(RELEASED_SKILL_SHA256))
// The version a managed copy is stamped with, or null when it has none.
function stamp(text: string): string | null {
  const frontmatter = text.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/)?.[1]
  const metadata = frontmatter?.match(/^metadata:[ \t]*\r?\n((?:[ \t]+[^\r\n]*(?:\r?\n|$))*)/m)?.[1]
  const line = metadata?.match(STAMP)?.[0]
  if (line === undefined) return null
  const value = line.slice("  mehen-version: ".length).trim()
  try { return String(JSON.parse(value)) } catch { return value }
}
// Mehen's own skill: stamped by setup, or a published copy saved by hand
// (this build's skill or an earlier release's, unstamped).
function managed(text: string): boolean {
  return stamp(text) !== null || text === skill || RELEASED.has(skillSha256(text))
}
async function prune(home: string, paths: string[]) {
  for (const path of paths) {
    await safePath(home, path)
    if (await info(path) && (await readdir(path)).length === 0) await rm(path, { recursive: true })
  }
}
// The skills kept by a removal that leaves other managed MCP entries: they
// still read the skill, so nothing is touched.
export function keptSkills(home: string, consumers: number): SkillReport[] {
  return SKILL_BASES.map((base) => ({ path: skillPath(home, base), status: "unchanged", reason: `Kept: ${consumers} managed MCP ${consumers === 1 ? "entry still uses" : "entries still use"} it; it goes with the last one.` }))
}
export async function installSkills(options: SkillOptions): Promise<SkillReport[]> {
  const { home, bases, dryRun, remove, force, skillsOnly, state } = options
  const results: SkillReport[] = []
  for (const base of SKILL_BASES) {
    const path = skillPath(home, base)
    const dir = dirname(path)
    const key = relative(home, path)
    const unchosen = !skillsOnly && !remove && !bases.includes(base)
    const refreshOnly = skillsOnly || unchosen
    try {
      await safePath(home, dirname(dir))
      const directory = await info(dir)
      const linked = directory?.isSymbolicLink() || (await info(path))?.isSymbolicLink()
      if (linked && (!force || remove || refreshOnly)) {
        results.push({ path, status: "external", reason: "Symlinked skill left alone." }); continue
      }
      const previous = linked ? null : await textFile(home, path)
      const owned = previous !== null && managed(previous)
      if (refreshOnly && !owned) {
        // A refresh never adds a skill and never replaces a foreign one.
        if (previous !== null) results.push({ path, status: "external", reason: "Foreign skill left alone." })
        else results.push(unchosen ? { path, status: "unchanged", reason: "No agent setup found reads this folder, so the skill was not added here." } : { path, status: "unchanged" })
        continue
      }
      if (previous !== null && !owned && !force) {
        results.push({ path, status: "external", reason: "Foreign skill left alone; use --force only with its owner's agreement." }); continue
      }
      if (remove) {
        if (!owned) { results.push({ path, status: "unchanged" }); continue }
        const record = state[key]
        if (!dryRun) {
          await rm(path)
          if ((await readdir(dir)).length === 0) {
            await rm(dir, { recursive: true })
            if (record?.backup) {
              const backup = join(home, record.backup)
              await safePath(home, dirname(backup))
              await rename(backup, dir)
              await prune(home, [dirname(backup), join(home, ".config/mehen/backups/skills"), join(home, ".config/mehen/backups")])
            }
          }
          await prune(home, record?.createdDirs ?? [])
        }
        delete state[key]
        results.push({ path, status: "removed" }); continue
      }
      const content = stampedSkill()
      const status = previous === content ? "unchanged" : previous !== null || linked ? "updated" : "added"
      const backup = join(home, ".config/mehen/backups/skills", base.slice(1), "mehen")
      const replaceForeign = linked || (previous !== null && !owned)
      if (replaceForeign) {
        await safePath(home, dirname(backup))
        if (await info(backup)) { results.push({ path, status: "external", reason: "A skill backup already exists; move it aside before forcing another replacement." }); continue }
      }
      const createdDirs: string[] = state[key]?.createdDirs ?? []
      if (!state[key]) for (const folder of [dirname(dir), join(home, base)]) if (!await info(folder)) createdDirs.push(folder)
      if (!dryRun && status !== "unchanged") {
        if (replaceForeign) {
          await mkdir(dirname(backup), { recursive: true, mode: 0o700 })
          await rename(dir, backup)
        }
        await atomicText(home, path, content)
      }
      state[key] = { hash: SKILL_HASH, existed: state[key]?.existed ?? previous !== null, createdDirs, ...(replaceForeign ? { backup: relative(home, backup) } : state[key]?.backup ? { backup: state[key]!.backup } : {}) }
      results.push({ path, status })
    } catch (error) {
      results.push({ path, status: "failed", reason: `${path}: ${error instanceof Error ? error.message : String(error)}` })
    }
  }
  return results
}

// What `mehen doctor` reports of each skill folder's copy: `current` is
// mehen's skill for this version (stamped, or this build's unstamped
// text), `stale` mehen's skill from another version, `external` a
// symlinked or foreign copy (`same` when its text is this build's), and
// `missing` names the installed agents that read the folder.
export type SkillCopy =
  | { path: string; state: "current" | "stale"; version: string | null }
  | { path: string; state: "external"; link: string | null; same: boolean }
  | { path: string; state: "missing"; readers: AgentName[] }
  | { path: string; state: "unreadable"; reason: string }

const COPY_MAX_BYTES = 1 << 20

// Installed as setup detects it, from the agent's folder, its file or its
// binary on PATH.
async function installedReaders(home: string, base: SkillBase, path: string, platform: NodeJS.Platform): Promise<AgentName[]> {
  const readers: AgentName[] = []
  for (const agent of agents(home, platform)) {
    if (agent.skills !== base || agent.name === "mcp-file") continue
    if ((agent.dir !== null && await info(agent.dir)) || await info(agent.file) || (agent.binary !== null && Bun.which(agent.binary, { PATH: path }))) readers.push(agent.name)
  }
  return readers
}

async function skillCopy(home: string, base: SkillBase, path: string, platform: NodeJS.Platform): Promise<SkillCopy> {
  const file = skillPath(home, base)
  const dir = dirname(file)
  const dirLinked = (await info(dir))?.isSymbolicLink() ?? false
  const fileLinked = !dirLinked && ((await info(file))?.isSymbolicLink() ?? false)
  const target = await stat(file).catch((error: unknown) => { if ((error as { code?: string }).code === "ENOENT") return null; throw error })
  if (target === null && !dirLinked && !fileLinked) return { path: file, state: "missing", readers: await installedReaders(home, base, path, platform) }
  if (target === null || !target.isFile()) return { path: file, state: "unreadable", reason: target === null ? "a symbolic link to nothing" : "not a file" }
  if (target.size > COPY_MAX_BYTES) return { path: file, state: "unreadable", reason: `larger than ${COPY_MAX_BYTES} bytes` }
  const text = await readFile(file, "utf8")
  if (dirLinked || fileLinked) {
    const link = dirLinked ? dir : file
    return { path: file, state: "external", link: resolve(dirname(link), await readlink(link)), same: text === skill || text === stampedSkill() }
  }
  if (!managed(text)) return { path: file, state: "external", link: null, same: false }
  const version = stamp(text)
  return { path: file, state: version === VERSION || (version === null && text === skill) ? "current" : "stale", version }
}

export async function skillCopies(home: string, path: string, platform = process.platform): Promise<SkillCopy[]> {
  const copies: SkillCopy[] = []
  for (const base of SKILL_BASES) {
    try {
      copies.push(await skillCopy(home, base, path, platform))
    } catch (error) {
      copies.push({ path: skillPath(home, base), state: "unreadable", reason: (error as { code?: string }).code ?? (error instanceof Error ? error.message : String(error)) })
    }
  }
  return copies
}
