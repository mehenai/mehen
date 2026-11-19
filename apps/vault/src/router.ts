// A small router: method plus a path pattern with :params. Patterns are
// matched segment by segment against the parsed pathname, never with
// regular expressions built from input.

export type Params = Record<string, string>

export type Route<H> = { method: string; path: string; handler: H }

export function matchPath(pattern: string, path: string): Params | null {
  const want = pattern.split("/")
  const got = path.split("/")
  if (want.length !== got.length) return null
  const params: Params = {}
  for (let i = 0; i < want.length; i++) {
    const w = want[i] as string
    const g = got[i] as string
    if (w.startsWith(":")) {
      if (g === "") return null
      let value: string
      try {
        value = decodeURIComponent(g)
      } catch {
        return null
      }
      params[w.slice(1)] = value
    } else if (w !== g) return null
  }
  return params
}

export function findRoute<H>(routes: Route<H>[], method: string, path: string): { route: Route<H>; params: Params } | "method" | null {
  let pathMatched = false
  for (const route of routes) {
    const params = matchPath(route.path, path)
    if (!params) continue
    pathMatched = true
    if (route.method === method || (route.method === "GET" && method === "HEAD")) return { route, params }
  }
  return pathMatched ? "method" : null
}
