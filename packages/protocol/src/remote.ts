// A git remote as the vault stores it: host and path, lower case, without
// a scheme, user, port or ".git". The vault, the project page and the
// tests share this one reading, so what a human confirms with a passkey is
// exactly what gets bound.

// "git@github.com:Owner/Repo.git", "https://github.com/owner/repo",
// "ssh://git@github.com/owner/repo" all become "github.com/owner/repo".
// Null when it is not a remote at all.
export function normaliseRemote(raw: string): string | null {
  const text = raw.trim()
  let host: string
  let path: string
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    let url: URL
    try {
      url = new URL(text)
    } catch {
      return null
    }
    host = url.hostname
    path = url.pathname
  } else {
    const scp = /^(?:[^@/\s]+@)?([^:/\s]+):(?!\/)(.+)$/.exec(text)
    if (scp) {
      host = scp[1] as string
      path = scp[2] as string
    } else {
      const slash = text.indexOf("/")
      if (slash <= 0) return null
      host = text.slice(0, slash)
      path = text.slice(slash)
    }
  }
  host = host.toLowerCase()
  if (!/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(host)) return null
  const segments = path
    .replace(/^\/+/, "")
    .replace(/\/+$/, "")
    .replace(/\.git$/i, "")
    .toLowerCase()
    .split("/")
  if (segments.length === 0 || segments.some((s) => !/^[a-z0-9._~-]+$/.test(s) || s === "." || s === "..")) return null
  return `${host}/${segments.join("/")}`
}
