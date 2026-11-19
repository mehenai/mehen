import { POLICY_FLOOR } from "../src/policy-safety.ts"

// Exercise every deny entry, including aliases, through its real restrictive matcher.
export const denyDestinationFixtures = [...POLICY_FLOOR.filter((floor) => floor.action === "deny").flatMap((floor) => {
  const pattern = floor.rule.paths?.[0]
  if (!pattern) throw new Error(`Missing deny path for ${floor.id}`)
  const path = pattern.replaceAll("**", "entry").replaceAll("*", "example")
  const spacePath = pattern.includes("*") ? pattern.replace(/\*\*?/, "a%20b").replaceAll("**", "entry").replaceAll("*", "example") : `${path};value=a%20b`
  return [["non-ASCII query", `${path}?q=caf%C3%A9`], ["percent-space segment", spacePath], ["matrix segment", `${path};value=x`]].map(([variant, route]) => ({
    name: `${floor.id} ${floor.host} ${variant}`, method: floor.rule.methods?.[0] ?? "POST", host: floor.host, route: route!,
  }))
}), ...["hooks%20", "hooks%C2%A0", "%EF%BD%88ooks"].map((segment) => ({
  name: `github folded deny ${segment}`, method: "POST", host: "api.github.com", route: `/repos/example/example/${segment}`,
}))]

export const standardDestinationFixtures = [
  ["literal percent query", "api.example.com", "/v1/search?q=50%25"],
  ["literal percent path", "api.example.com", "/v1/files/100%25.txt"],
  ["SQL LIKE percent", "api.example.com", "/v1/search?filter=name%20like%20%27%25foo%25%27"],
  ["nested literal percent", "api.example.com", "/v1/search?next=%2Fa%3Fq%3D50%2525"],
  ...["method", "Method", "http_method", "httpMethod", "payment_method"].map((name) => [`ordinary parameter ${name}`, "api.example.com", `/v1/search?${name}=x`]),
  ["Flickr method", "api.flickr.com", "/services/rest/?method=flickr.photos.search&format=json"],
  ["Last.fm method", "ws.audioscrobbler.com", "/2.0/?method=artist.getinfo&artist=Cher"],
].map(([name, host, route]) => ({ name: name!, host: host!, route: route! }))

export const destinationShapeFixtures = [
  ["percent-space", "api.example.com", "/v1/files/my%20doc.txt"],
  ["percent-at", "api.example.com", "/users/alice%40example.com"],
  ["percent-plus", "api.example.com", "/v1/a%2Bb"],
  ["matrix", "api.example.com", "/v1/files/a;b"],
  ["long path", "api.example.com", `/v1/${"a".repeat(257)}`],
  ["accented query", "api.example.com", "/v1/search?q=caf%C3%A9"],
  ["Drive CJK query", "www.googleapis.com", "/drive/v3/files?q=name%20contains%20%27%E6%97%A5%E6%9C%AC%27"],
  ["OData accented filter", "graph.microsoft.com", "/v1.0/users?$filter=displayName%20eq%20%27J%C3%BCrgen%27"],
  ["Persian ZWNJ", "api.example.com", `/api/search?q=${encodeURIComponent("می\u200cخواهم")}`],
  ["ASCII ZWNJ", "api.example.com", "/api/search?q=a%E2%80%8Cb"],
  ["emoji ZWJ", "api.example.com", `/api/search?q=${encodeURIComponent("👩\u200d💻")}`],
  ["soft hyphen", "api.example.com", "/api/search?q=co%C2%ADoperate"],
].map(([name, host, route]) => ({ name: name!, host: host!, route: route!, prefix: `/${route!.split("/")[1]}` }))
