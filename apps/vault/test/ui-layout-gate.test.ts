// The gallery layout gate fails closed (scripts/ui-layout-gate.ts): a probe
// that threw, answered nothing or answered for another page, a navigation
// that failed, and a run that measured fewer states than it has, or none,
// are refusals, never an empty set of findings.

import { describe, expect, it } from "vitest"
import { type LayoutBaselineEntry, type LayoutFinding, acceptProbe, checkMeasured, checkNavigation, compareBaseline } from "../scripts/ui-layout-gate.ts"

const WHERE = "people-owner at 390 px, light"
const ISSUE = { kind: "scrolls", px: 44, selector: "table.sources", element: 'table.sources "From"' } as const

describe("acceptProbe", () => {
  it("returns the findings of a well-formed answer for the page asked for", () => {
    expect(acceptProbe(WHERE, "people-owner", { result: { value: { entry: "people-owner", issues: [ISSUE] } } })).toEqual([ISSUE])
    expect(acceptProbe(WHERE, "people-owner", { result: { value: { entry: "people-owner", issues: [] } } })).toEqual([])
  })

  it("refuses a probe that threw, on a page the baseline does not name", () => {
    expect(() => acceptProbe(WHERE, "people-owner", { result: {}, exceptionDetails: { text: "Uncaught", exception: { description: "TypeError: x is null" } } })).toThrow(/threw on people-owner at 390 px, light: TypeError/)
  })

  it("refuses an absent or malformed answer", () => {
    expect(() => acceptProbe(WHERE, "people-owner", {})).toThrow(/no answer/)
    expect(() => acceptProbe(WHERE, "people-owner", { result: { value: [] as unknown } })).toThrow()
    expect(() => acceptProbe(WHERE, "people-owner", { result: { value: { entry: "people-owner" } } })).toThrow(/malformed/)
    expect(() => acceptProbe(WHERE, "people-owner", { result: { value: { entry: "people-owner", issues: [{ kind: "wobbly", px: 1, selector: "p", element: "p" }] } } })).toThrow(/malformed/)
    expect(() => acceptProbe(WHERE, "people-owner", { result: { value: { entry: "people-owner", issues: [{ ...ISSUE, px: Number.NaN }] } } })).toThrow(/malformed/)
  })

  it("refuses a page that is not the gallery entry asked for, such as a browser error page", () => {
    expect(() => acceptProbe(WHERE, "people-owner", { result: { value: { entry: null, issues: [] } } })).toThrow(/is not the gallery page people-owner/)
    expect(() => acceptProbe(WHERE, "people-owner", { result: { value: { entry: "people-admin", issues: [] } } })).toThrow(/is not the gallery page people-owner/)
  })
})

describe("checkNavigation", () => {
  it("refuses a navigation Chrome reports as failed", () => {
    expect(() => checkNavigation(WHERE, { errorText: "net::ERR_FILE_NOT_FOUND" })).toThrow(/did not load: net::ERR_FILE_NOT_FOUND/)
    expect(() => checkNavigation(WHERE, {})).not.toThrow()
  })
})

describe("checkMeasured", () => {
  it("accepts exactly one measurement per state, width and scheme", () => {
    expect(() => checkMeasured(2570, 257, 5, 2)).not.toThrow()
  })

  it("refuses a run that measured fewer or more", () => {
    expect(() => checkMeasured(2569, 257, 5, 2)).toThrow(/measured 2569 of 2570/)
    expect(() => checkMeasured(0, 257, 5, 2)).toThrow(/measured 0 of 2570/)
    expect(() => checkMeasured(2571, 257, 5, 2)).toThrow()
  })

  it("refuses an empty gallery, whatever the baseline holds", () => {
    expect(() => checkMeasured(0, 0, 5, 2)).toThrow(/nothing to measure/)
  })
})

describe("compareBaseline", () => {
  const finding: LayoutFinding = { ...ISSUE, id: "ws-project-owner", width: 390, scheme: "light", shot: "ws-project-owner-390-light.png" }
  const entry: LayoutBaselineEntry = { id: "ws-project-owner", width: 390, scheme: "light", kind: "scrolls", selector: "table.sources", lane: "CP", cause: "five columns" }

  it("passes a finding the baseline lists, whatever its px", () => {
    expect(compareBaseline([{ ...finding, px: 7 }], [entry])).toEqual({ fresh: [], gone: [] })
  })

  it("fails a finding the baseline does not list and an entry that no longer occurs", () => {
    const other: LayoutFinding = { ...finding, id: "ws-project-guest" }
    expect(compareBaseline([other], [entry])).toEqual({ fresh: [other], gone: [entry] })
  })
})
