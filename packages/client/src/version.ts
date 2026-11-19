// Kept equal to package.json's version by a test.
export const CLIENT_VERSION = "0.1.0"

// Always sent, so the vault can tell this library from the mehen CLI (whose
// `mehen/<version>` agent its version gate reads) and label it.
export const CLIENT_PRODUCT = `mehen-client/${CLIENT_VERSION}`
