#!/usr/bin/env node
// npm create mehen: sets Mehen up on this machine (mehen up), with any
// options given after it passed on.
import { run } from "@mehenai/cli/lib.mjs"

const args = process.argv.slice(2)
process.exitCode = await run(args.length === 0 || args[0].startsWith("-") ? ["up", ...args] : args)
