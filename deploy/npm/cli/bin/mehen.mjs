#!/usr/bin/env node
import { run } from "../lib.mjs"

process.exitCode = await run(process.argv.slice(2))
