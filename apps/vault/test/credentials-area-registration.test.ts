import {expect,it} from "vitest"
import {AREAS} from "../src/vault/registry.ts"
it("initialises credential and project registration without undefined migration cycles",()=>{
 const invalid=AREAS.flatMap(area=>area.migrations.flatMap((migration,index)=>typeof migration === "string"?[]:[`${area.name} migration ${index}`]))
 expect(invalid).toEqual([])
})

it("registers the pushes area once, after the areas whose tables it reads", () => {
 const names = AREAS.map((area) => area.name)
 expect(names.filter((name) => name === "pushes")).toHaveLength(1)
 for (const before of ["items", "approvals", "access"]) expect(names.indexOf(before)).toBeLessThan(names.indexOf("pushes"))
})

it("preserves prototype-backed vault context services instead of spreading ctx", () => {
  const sources = import.meta.glob<string>("../src/vault/**/*.ts", { query: "?raw", import: "default", eager: true })
  const copies = Object.entries(sources).filter(([, source]) => /\{\s*\.\.\.ctx\b/.test(source)).map(([path]) => path)
  expect(copies).toEqual([])
})
