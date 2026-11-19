export function blobBytes(value: unknown): Uint8Array<ArrayBuffer> {
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer)
  if (Array.isArray(value) && value.every((b) => typeof b === "number")) return Uint8Array.from(value as number[])
  throw new Error("expected a blob column")
}
