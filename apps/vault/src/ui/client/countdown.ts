// The countdown ring's maths, with no DOM so the server tests can check it:
// seconds left to a dash offset and to the warn and danger tones.

const RING_CIRCUMFERENCE = +(2 * Math.PI * 9).toFixed(2)

export const RING_WARN_SECONDS = 180
export const RING_DANGER_SECONDS = 60

export function ringOffset(fraction: number): number {
  const clamped = Math.min(1, Math.max(0, fraction))
  return +(RING_CIRCUMFERENCE * (1 - clamped)).toFixed(2)
}

export type RingState = { left: number; fraction: number; tone: "warn" | "danger" | null; expired: boolean }

export function ringState(expiresAt: number, totalSeconds: number, now: number): RingState {
  const left = Math.max(0, Math.ceil((expiresAt - now) / 1000))
  const fraction = totalSeconds > 0 ? Math.min(1, left / totalSeconds) : 0
  const tone = left <= RING_DANGER_SECONDS ? "danger" : left <= RING_WARN_SECONDS ? "warn" : null
  return { left, fraction, tone, expired: left === 0 }
}

export function ringText(left: number): string {
  if (left >= 2 * 86_400) return `${Math.floor(left / 86_400)} days`
  if (left >= 3600) return `${Math.floor(left / 3600)} h ${Math.floor((left % 3600) / 60)} min`
  if (left >= 60) return `${Math.floor(left / 60)} min`
  return `${left} s`
}
