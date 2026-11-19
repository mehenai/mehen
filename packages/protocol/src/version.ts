// Release versions: semver ordering for the CLI's updater and the vault's
// minimum and recommended CLI versions. Moved here from apps/cli so both
// sides compare versions with one function.

const RELEASE_VERSION = /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$/

// Semver ordering, including numeric prerelease identifiers. The release
// version is the package version; the build commit is separate provenance.
export function compareVersions(a: string, b: string): number {
  if (!RELEASE_VERSION.test(a) || !RELEASE_VERSION.test(b)) throw new Error("Invalid release version.")
  const parts = (v: string) => {
    const [core, ...pre] = v.split("-")
    return { core: core!.split(".").map(BigInt), pre: pre.length ? pre.join("-").split(".") : null }
  }
  const left = parts(a)
  const right = parts(b)
  for (let i = 0; i < 3; i++) if (left.core[i] !== right.core[i]) return left.core[i]! > right.core[i]! ? 1 : -1
  if (left.pre === null || right.pre === null) return left.pre === right.pre ? 0 : left.pre === null ? 1 : -1
  for (let i = 0; i < Math.max(left.pre.length, right.pre.length); i++) {
    const l = left.pre[i]
    const r = right.pre[i]
    if (l === r) continue
    if (l === undefined || r === undefined) return l === undefined ? -1 : 1
    const ln = /^\d+$/.test(l)
    const rn = /^\d+$/.test(r)
    if (ln && rn) return BigInt(l) > BigInt(r) ? 1 : -1
    if (ln !== rn) return ln ? -1 : 1
    return l > r ? 1 : -1
  }
  return 0
}
