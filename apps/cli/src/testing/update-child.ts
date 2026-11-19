// The updater in a child process that kills itself with SIGKILL at one named
// step, so src/update.test.ts can assert what a real kill leaves behind: no
// finally block, no lock release, no cleanup runs.
//
//   bun src/testing/update-child.ts '<json: { binary, killAt, env, current }>'

import { installation } from "../install-state.ts"
import { type UpdateStep, update } from "../update.ts"

const input = JSON.parse(process.argv[2] ?? "{}") as { binary: string; killAt: UpdateStep; env: Record<string, string>; current: string }
await update({
  env: input.env,
  install: installation(input.binary),
  by: "auto",
  current: input.current,
  commit: "0ld0000",
  build: "release",
  platform: "linux",
  arch: "x64",
  wait: false,
  onStep: (step) => {
    if (step === input.killAt) process.kill(process.pid, "SIGKILL")
  },
})
process.stdout.write("finished\n")
