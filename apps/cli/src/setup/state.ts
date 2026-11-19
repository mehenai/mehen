export type OwnedFile = { hash: string; existed: boolean; prefix?: string; backup?: string; createdDirs?: string[] }
export type State = Record<string, OwnedFile>
