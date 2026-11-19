// Workspace-backed project, run and lease routes for proof-signed machines.
import { LeaseRequest, ProjectCreate, RunCreate, VarSet } from "@mehen/protocol/api"
import { json, parseJson } from "../http.ts"
import type { Route } from "../router.ts"
import { type Handler, deviceRequest } from "./context.ts"

export const projectsRoutes: Route<Handler>[] = [
  {
    method: "POST",
    path: "/v1/projects",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("projects.create", parseJson(ProjectCreate, device.body)), 201)
    },
  },
  {
    method: "GET",
    path: "/v1/projects",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("projects.find", { remote: rc.url.searchParams.get("remote") ?? "" }))
    },
  },
  {
    method: "GET",
    path: "/v1/projects/:id",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("projects.get", { id: rc.params["id"] }))
    },
  },
  {
    method: "PUT",
    path: "/v1/projects/:id/vars/:name",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      const body = parseJson(VarSet, device.body)
      return json(await device.call("projects.setVar", { ...body, project: rc.params["id"], name: rc.params["name"] }))
    },
  },
  {
    method: "POST",
    path: "/v1/runs",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("runs.create", parseJson(RunCreate, device.body)), 201)
    },
  },
  {
    method: "POST",
    path: "/v1/runs/:id/renew",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("runs.renew", { run: rc.params["id"] }))
    },
  },
  {
    method: "DELETE",
    path: "/v1/runs/:id",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("runs.end", { run: rc.params["id"] }))
    },
  },
  {
    method: "POST",
    path: "/v1/lease",
    handler: async (rc) => {
      const device = await deviceRequest(rc)
      return json(await device.call("runs.lease", parseJson(LeaseRequest, device.body)))
    },
  },
]
