// @peculiar/x509 pulls in tsyringe, which refuses to load without the three
// Reflect metadata functions it calls. This is the smallest stand-in for the
// reflect-metadata package, so the CLI needs no extra dependency. Import it
// before @peculiar/x509.

type MetadataTarget = object
type MetadataReflect = typeof Reflect & {
  getMetadata?: (key: unknown, target: MetadataTarget) => unknown
  getOwnMetadata?: (key: unknown, target: MetadataTarget) => unknown
  defineMetadata?: (key: unknown, value: unknown, target: MetadataTarget) => void
}

const reflect = Reflect as MetadataReflect

if (reflect.getMetadata === undefined) {
  const store = new WeakMap<MetadataTarget, Map<unknown, unknown>>()
  const own = (key: unknown, target: MetadataTarget): unknown => store.get(target)?.get(key)
  reflect.getOwnMetadata = own
  reflect.getMetadata = (key, target) => {
    for (let at: MetadataTarget | null = target; at !== null; at = Object.getPrototypeOf(at) as MetadataTarget | null) {
      const value = own(key, at)
      if (value !== undefined) return value
    }
    return undefined
  }
  reflect.defineMetadata = (key, value, target) => {
    let entries = store.get(target)
    if (entries === undefined) {
      entries = new Map()
      store.set(target, entries)
    }
    entries.set(key, value)
  }
}
