// The Workers rate limiting binding on one machine: a fixed window per key,
// with the limits the hosted vault declares in wrangler.jsonc.

export class LocalRateLimit {
  private readonly windows = new Map<string, { start: number; count: number }>()
  private readonly limitPerPeriod: number
  private readonly periodMs: number
  private readonly now: () => number

  constructor(limit: number, periodSeconds: number, now: () => number = Date.now) {
    this.limitPerPeriod = limit
    this.periodMs = periodSeconds * 1000
    this.now = now
  }

  async limit({ key }: { key: string }): Promise<{ success: boolean }> {
    const now = this.now()
    const window = this.windows.get(key)
    if (!window || now - window.start >= this.periodMs) {
      if (this.windows.size > 10_000) this.sweep(now)
      this.windows.set(key, { start: now, count: 1 })
      return { success: true }
    }
    window.count++
    return { success: window.count <= this.limitPerPeriod }
  }

  private sweep(now: number): void {
    for (const [key, window] of this.windows) if (now - window.start >= this.periodMs) this.windows.delete(key)
  }
}

// The hosted limits (apps/vault/wrangler.jsonc ratelimits).
export function localRateLimits() {
  return {
    RATE_LIMITER: new LocalRateLimit(120, 60),
    AUTH_RATE_LIMITER: new LocalRateLimit(20, 60),
    PLATFORM_IP_RATE_LIMITER: new LocalRateLimit(6000, 60),
    DEVICE_IP_RATE_LIMITER: new LocalRateLimit(6000, 60),
    DEVICE_RATE_LIMITER: new LocalRateLimit(600, 60),
  }
}
