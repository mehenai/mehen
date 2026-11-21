// The binaries a release publishes, apart from release.ts and its imports so
// the CLI's tests can hold them to the file names an installed mehen accepts
// (apps/cli/src/release-client.ts).

export type ReleaseOs = "darwin" | "linux"
export type ReleaseArch = "arm64" | "x64" | "universal"

// One binary of a release: where it is built, and the platform it is for.
export type ReleaseBinary = { name: string; os: ReleaseOs; arch: ReleaseArch }

export const RELEASE_BINARIES: readonly ReleaseBinary[] = [
  { name: "mehen-darwin-arm64", os: "darwin", arch: "arm64" },
  { name: "mehen-darwin-x64", os: "darwin", arch: "x64" },
  { name: "mehen-linux-x64", os: "linux", arch: "x64" },
  { name: "mehen-linux-arm64", os: "linux", arch: "arm64" },
  { name: "mehen-se", os: "darwin", arch: "universal" },
]
