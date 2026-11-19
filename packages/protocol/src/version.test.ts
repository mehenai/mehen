import { expect, test } from "bun:test"
import { compareVersions } from "./version.ts"

test("semver comparison includes prereleases and numeric identifiers", () => {
  for (const [left, right] of [["0.10.0", "0.9.9"], ["1.0.0", "1.0.0-rc.1"], ["1.0.0-rc.10", "1.0.0-rc.2"], ["1.0.0-rc.1", "1.0.0-1"], ["1.0.0-rc.1", "1.0.0-rc"], ["0.3.0", "0.2.0"]]) {
    expect(compareVersions(left!, right!)).toBe(1)
    expect(compareVersions(right!, left!)).toBe(-1)
  }
  expect(compareVersions("1.2.3", "1.2.3")).toBe(0)
  expect(compareVersions("1.2.3-rc.1", "1.2.3-rc.1")).toBe(0)
})

test("a two-digit patch compares as a number: 0.3.10 is above 0.3.9", () => {
  expect(compareVersions("0.3.10", "0.3.9")).toBe(1)
  expect(compareVersions("0.3.9", "0.3.10")).toBe(-1)
})

test("two two-digit patches compare as numbers: 0.3.11 is above 0.3.10", () => {
  expect(compareVersions("0.3.11", "0.3.10")).toBe(1)
  expect(compareVersions("0.3.10", "0.3.11")).toBe(-1)
})

test("two two-digit patches compare as numbers: 0.3.12 is above 0.3.11", () => {
  expect(compareVersions("0.3.12", "0.3.11")).toBe(1)
  expect(compareVersions("0.3.11", "0.3.12")).toBe(-1)
})

test("0.3.13 is above 0.3.12", () => {
  expect(compareVersions("0.3.13", "0.3.12")).toBe(1)
  expect(compareVersions("0.3.12", "0.3.13")).toBe(-1)
})

test("0.3.14 is above 0.3.13", () => {
  expect(compareVersions("0.3.14", "0.3.13")).toBe(1)
  expect(compareVersions("0.3.13", "0.3.14")).toBe(-1)
})

test("0.3.15 is above 0.3.14", () => {
  expect(compareVersions("0.3.15", "0.3.14")).toBe(1)
  expect(compareVersions("0.3.14", "0.3.15")).toBe(-1)
})

test("0.3.16 is above 0.3.15", () => {
  expect(compareVersions("0.3.16", "0.3.15")).toBe(1)
  expect(compareVersions("0.3.15", "0.3.16")).toBe(-1)
})

test("0.3.17 is above 0.3.16", () => {
  expect(compareVersions("0.3.17", "0.3.16")).toBe(1)
  expect(compareVersions("0.3.16", "0.3.17")).toBe(-1)
})

test("0.3.18 is above 0.3.17", () => {
  expect(compareVersions("0.3.18", "0.3.17")).toBe(1)
  expect(compareVersions("0.3.17", "0.3.18")).toBe(-1)
})

test("0.3.19 is above 0.3.18", () => {
  expect(compareVersions("0.3.19", "0.3.18")).toBe(1)
  expect(compareVersions("0.3.18", "0.3.19")).toBe(-1)
})

test("anything that is not a release version is refused", () => {
  for (const bad of ["../bad", "1.2", "v1.2.3", "1.2.3-", "1.2.3 ", ""]) {
    expect(() => compareVersions(bad, "1.2.3")).toThrow("Invalid release version")
    expect(() => compareVersions("1.2.3", bad)).toThrow("Invalid release version")
  }
})
