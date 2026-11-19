const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"])

// The vault's origin from the URL a host configured. https only, apart from
// plain http on a loopback address for a vault running locally; never a
// path, query, fragment or userinfo, because every route and link lives at
// the origin itself.
export function vaultOrigin(vaultUrl: string): string {
  let url: URL
  try {
    url = new URL(vaultUrl)
  } catch {
    throw new TypeError(`The vault URL ${JSON.stringify(vaultUrl)} is not a URL.`)
  }
  const secure = url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname))
  if (!secure) throw new TypeError("The vault URL must be https (plain http only on localhost).")
  if (url.username !== "" || url.password !== "") throw new TypeError("The vault URL must not carry a user name or password.")
  if ((url.pathname !== "/" && url.pathname !== "") || url.search !== "" || url.hash !== "") throw new TypeError("The vault URL is the vault's origin alone, with no path, query or fragment.")
  return url.origin
}

// A link the vault handed over, resolved against the vault's origin (the
// vault may send a path such as /account) and accepted only on exactly that
// origin: the same scheme, host and port, and no userinfo. The absolute URL,
// or null for a link anywhere else.
export function vaultLink(origin: string, value: string): string | null {
  let url: URL
  try {
    url = new URL(value, origin)
  } catch {
    return null
  }
  return url.origin === origin && url.username === "" && url.password === "" ? url.href : null
}
