// The one place the vault talks to the outside world: relayed requests,
// OAuth code exchanges, refreshes and identity probes all go through
// `upstreamFetch`, so tests can stand in a mock provider.

export type UpstreamFetch = (request: Request) => Promise<Response>

const realFetch: UpstreamFetch = (request) => fetch(request)

let current: UpstreamFetch = realFetch

export function setUpstreamFetch(next: UpstreamFetch | null): void {
  current = next ?? realFetch
}

export function upstreamFetch(request: Request): Promise<Response> {
  return current(request)
}
