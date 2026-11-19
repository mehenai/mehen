// The module scripts/build.ts writes beside this file before compiling and
// deletes after the build (src/local-host.ts): the local vault host, bundled
// with the vault engine. Never commit the .js.
import type { LocalHost } from "../../../local/src/types.ts"

export declare const BOOTSTRAP_FILE: LocalHost["BOOTSTRAP_FILE"]
export declare const INSTANCE_FILE: LocalHost["INSTANCE_FILE"]
export declare const startLocalVault: LocalHost["startLocalVault"]
