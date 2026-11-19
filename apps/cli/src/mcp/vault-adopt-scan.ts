import { isAbsolute } from "node:path"
import { z } from "zod"
import { OutputGuard } from "../adopt/output-guard.ts"
import { scanReport, scanToFile } from "../adopt/scan.ts"
import { usageError } from "../errors.ts"
import { plain, tool } from "./shared.ts"

// The scan `mehen adopt scan` runs, for an agent: names, kinds and proposed
// homes only. Every value read stays in this call's memory and the result
// passes the same output guard as the command.
export const vaultAdoptScan = tool({
  name: "vault_adopt_scan",
  title: "Find credentials to adopt",
  description:
    "Find the credentials already on this machine (repo .env files, .local-secrets, service units, settings and login files) and propose a home for each, the first step of moving them into the vault. " +
    "Returns the counts, each folder with its proposed home and counts, and the files that did not parse with the folders holding them, never a value, and the path of the 0600 scan file, which lists every name found. Writes only that file and sends nothing. " +
    "The next steps run as commands a human sees: mehen adopt plan, then mehen adopt submit.",
  input: z.object({
    roots: z.array(z.string()).max(32).optional().describe("absolute folders to scan instead of the defaults (~/code, ~/.config, ~/.local-secrets, the service units folder and the known login files)"),
    defaults: z.boolean().optional().describe("scan the default places when no roots are given; default true"),
    depth: z.number().int().min(1).max(32).optional().describe("how many folders deep to walk under each root; default 6"),
  }),
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  async call(args, deps) {
    const roots = args.roots ?? []
    const relative = roots.filter((r) => !isAbsolute(r))
    if (relative.length) throw usageError(`roots must be absolute paths: ${relative.join(", ")}.`)
    if (args.defaults === false && roots.length === 0) throw usageError("With defaults false, give at least one root to scan.")
    const guard = new OutputGuard()
    try {
      const { result, path } = await scanToFile(deps.env, { roots, defaults: args.defaults ?? true, depth: args.depth ?? 6, include: [], exclude: [], out: null }, guard)
      const structured = scanReport(result, path)
      guard.assertClean(JSON.stringify(structured))
      return plain(structured)
    } catch (error) {
      throw guard.error(error)
    }
  },
})
