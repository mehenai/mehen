export const FETCH_BODY_LIMIT = 256 * 1024
// Many MCP hosts time a tool call out after a minute or two (Codex at 60 s
// unless tool_timeout_sec says otherwise): a wait that returns `timeout`
// with next.command well inside that is safer than one the host kills.
export const WAIT_DEFAULT_SECONDS = 45
export const WAIT_MAX_SECONDS = 600
export const PROGRESS_INTERVAL_MS = 10_000
