// A Bun macro (imported `with { type: "macro" }`): runs when the importing
// module is transpiled, under bun run, bun test and bun build --compile, and
// leaves the minified browser bundle of one card entry as a string literal.
// Bun.build inside a macro deadlocks, so it shells out to bun build.
export function browserScript(entry: string): string {
  const path = new URL(entry, import.meta.url).pathname
  const run = Bun.spawnSync([process.execPath, "build", path, "--target=browser", "--format=iife", "--minify"], { stdout: "pipe", stderr: "pipe" })
  if (run.exitCode !== 0) throw new Error(`bun build ${entry} failed: ${run.stderr.toString()}`)
  return run.stdout.toString()
}
