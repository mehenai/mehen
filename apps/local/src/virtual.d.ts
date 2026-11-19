declare module "mehen-local:migrations" {
  export const MIGRATIONS: { name: string; sql: string }[]
}

declare module "mehen-local:assets" {
  export const ASSETS: Record<string, string>
}

declare module "mehen-local:vault" {
  type Handler = {
    fetch(request: Request, env: unknown, ctx: unknown): Promise<Response>
    scheduled(controller: unknown, env: unknown, ctx: unknown): Promise<void>
  }
  const worker: Handler
  export default worker
  // Constructed by the local namespaces with their own state and env.
  export const WorkspaceVault: new (state: unknown, env: unknown) => object
  export const PlatformVault: new (state: unknown, env: unknown) => object
}
