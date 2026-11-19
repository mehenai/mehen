import { launchChrome } from "./apps/vault/scripts/chrome.ts"
const chrome = process.argv[2] ?? "/usr/bin/google-chrome"
for (let i = 0; i < 3; i++) {
  const t = Date.now()
  try {
    const c = await launchChrome(chrome)
    console.log(`launchChrome ${i}: ${Date.now() - t} ms (TMPDIR=${process.env.TMPDIR ?? "unset"})`)
    await c.close()
  } catch (e) { console.log(`launchChrome ${i}: FAILED after ${Date.now() - t} ms: ${(e as Error).message}`) }
}
