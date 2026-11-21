import { mkdir, symlink, writeFile } from "node:fs/promises"
import { join } from "node:path"

// A Homebrew prefix as brew lays one out: the keg, opt/mehen linked to it,
// and bin/mehen linked to the keg's binary.
export async function brewPrefix(root: string, version = "0.5.0", options: { opt?: boolean | string; bin?: boolean; cellar?: string } = {}): Promise<{ prefix: string; keg: string; opt: string; bin: string }> {
  const prefix = join(root, "homebrew")
  const cellar = options.cellar ?? join(prefix, "Cellar")
  const keg = join(cellar, "mehen", version, "bin", "mehen")
  await mkdir(join(cellar, "mehen", version, "bin"), { recursive: true })
  await writeFile(keg, "#!/bin/sh\necho mehen\n", { mode: 0o755 })
  await mkdir(join(prefix, "opt"), { recursive: true })
  await mkdir(join(prefix, "bin"), { recursive: true })
  const optVersion = typeof options.opt === "string" ? options.opt : version
  if (options.opt !== false) {
    if (optVersion !== version) await mkdir(join(cellar, "mehen", optVersion, "bin"), { recursive: true })
    await symlink(join(cellar, "mehen", optVersion), join(prefix, "opt", "mehen"))
  }
  if (options.bin !== false) await symlink(keg, join(prefix, "bin", "mehen"))
  return { prefix, keg, opt: join(prefix, "opt", "mehen", "bin", "mehen"), bin: join(prefix, "bin", "mehen") }
}
