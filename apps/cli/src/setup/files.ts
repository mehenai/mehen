import { chmod, lstat, realpath, stat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises"
import { dirname, isAbsolute, relative, resolve, sep } from "node:path"
import { randomUUID } from "node:crypto"
import { usageError } from "../errors.ts"

export async function info(path: string) {
  try { return await lstat(path) } catch (error) { if ((error as { code?: string }).code === "ENOENT") return null; throw error }
}

// Do not follow a config or parent link out of HOME, even for a dry run.
export async function safePath(home: string, path: string): Promise<void> {
  const rel = relative(home, path)
  if (!isAbsolute(home) || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw usageError("Setup only writes within HOME.")
  const root = await realpath(home)
  let current = resolve(home)
  for (const part of ["", ...rel.split(sep)]) {
    current = resolve(current, part)
    const stat = await info(current)
    if (stat?.isSymbolicLink()) {
      const target = await realpath(current).catch(() => null)
      const inside = target === null ? ".." : relative(root, target)
      if (inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) throw usageError(`Refusing symbolic link outside HOME at ${current}. Move it inside HOME, then run mehen setup --json again.`)
    }
  }
}

export async function textFile(home: string, path: string): Promise<string | null> {
  await safePath(home, path)
  return await readFile(path, "utf8").catch((error: unknown) => { if ((error as { code?: string }).code === "ENOENT") return null; throw error })
}

export class FileChanged extends Error {}
export async function unchanged(home: string, path: string, expected: string | null): Promise<void> {
  if (await textFile(home, path) !== expected) throw new FileChanged(`${path} changed while setup ran; run mehen setup --json again.`)
}
export async function atomicText(home: string, path: string, text: string, expected?: string | null, beforeRename?: () => Promise<void>): Promise<void> {
  await safePath(home, path)
  if ((await info(path))?.isSymbolicLink()) path = resolve(home, relative(await realpath(home), await realpath(path)))
  const mode = await stat(path).then(s => s.mode & 0o777, () => 0o600)
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const temp = `${path}.${randomUUID()}.tmp`
  try {
    await writeFile(temp, text, { mode, flag: "wx" })
    await chmod(temp, mode)
    await beforeRename?.()
    if (expected !== undefined) await unchanged(home, path, expected)
    await safePath(home, path)
    await rename(temp, path)
  } finally { await rm(temp, { force: true }) }
}
