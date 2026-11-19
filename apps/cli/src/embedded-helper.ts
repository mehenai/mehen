// The Secure Enclave helper a darwin build carries. scripts/build.ts writes
// src/generated/embedded-helper.ts immediately before bundling each target
// (an embedded file for darwin with a built helper, null otherwise) and
// deletes it after the build; a source run or a test has no generated
// module and therefore no embedded helper. The committed
// src/generated/embedded-helper.d.ts keeps tsc green either way.

let embedded: Promise<string | null> | undefined

// The helper's path inside the binary's embedded file system (read it with
// Bun.file), or null when this build carries none.
export function embeddedHelperPath(): Promise<string | null> {
  embedded ??= import("./generated/embedded-helper.ts").then(
    (module) => module.EMBEDDED_HELPER,
    () => null,
  )
  return embedded
}
