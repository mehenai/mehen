// Runs `mehen run` in its own process against a fake vault, so run.test.ts can
// send it a real signal. Usage: bun signal-harness.ts <project dir>

import { FakeVaultApi, runCreated } from "../fake-vault-api.ts"
import { runCommand } from "../run.ts"

const dir = process.argv[2]
if (dir === undefined) throw new Error("usage: signal-harness.ts <project dir>")

const api = new FakeVaultApi()
  .on("POST", "/v1/runs", () =>
    runCreated({
      vars: [{ name: "OPENAI_API_KEY", delivery: "placeholder", value: "sk-proj-jvph000000000000000000000000", item: "openai", hosts: ["api.mehen.test"] }],
      interceptHosts: ["api.mehen.test"],
    }),
  )
  .on("DELETE", "/v1/runs/run_test1", () => {
    console.log("vault: run_test1 ended")
    return {}
  })

// The handlers go in before "child up": the test signals as soon as it reads
// that line, and a signal before them would end the child with 143.
const child = [
  'for (const s of ["SIGINT", "SIGTERM"]) process.on(s, () => { console.log("child got " + s); process.exit(42) })',
  'console.log("child up " + process.env.NODE_EXTRA_CA_CERTS + " " + process.pid)',
  "setInterval(() => {}, 1000)",
].join(";")

// Says on stderr which signals reached the harness, so a failed test can tell
// a signal that never arrived from one mehen run did not pass on.
for (const s of ["SIGINT", "SIGTERM"] as const) process.on(s, () => console.error(`harness got ${s}`))

const code = await runCommand(["--", process.execPath, "-e", child], {
  api,
  config: { vault: "https://vault.test", tenant: "ten_test", device: "dev_test" },
  stdout: process.stdout,
  stderr: process.stderr,
  cwd: dir,
  env: { PATH: process.env.PATH },
})
console.log(`mehen exit ${code}`)
process.exit(code)
