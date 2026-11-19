// page-reads.ts: one GET page request and the reads it dispatches share one
// answer to each directory lookup; a second request asks D1 again, so a
// session ended between two requests is refused on the next; and a request
// that is not a GET or HEAD neither reads nor fills the memo.
import { describe, expect, it } from "vitest"
import { pageRead, withPageReads } from "../../src/page-reads.ts"
import { journey } from "./workspace-journey.ts"

const get = new Request("https://vault.test/w/x/")
const post = new Request("https://vault.test/api/x", { method: "POST" })

describe("page reads", () => {
  it("reads each key once within one page request, and afresh in the next", async () => {
    let reads = 0
    const read = async () => ++reads
    expect(await withPageReads(get, async () => [await pageRead(get, "a", read), await pageRead(get, "a", read), await pageRead(get, "b", read)])).toEqual([1, 1, 2])
    expect(await withPageReads(get, () => pageRead(get, "a", read))).toBe(3)
    expect(await pageRead(get, "a", read)).toBe(4)
  })
  it("never reads from or fills the memo for a request that is not a GET or HEAD", async () => {
    let reads = 0
    const read = async () => ++reads
    expect(await withPageReads(get, async () => [await pageRead(get, "a", read), await pageRead(post, "a", read), await pageRead(post, "b", read), await pageRead(get, "b", read)])).toEqual([1, 2, 3, 4])
    expect(await withPageReads(post, async () => [await pageRead(post, "a", read), await pageRead(post, "a", read)])).toEqual([5, 6])
  })
  it("forgets a read that failed, so the next asks again", async () => {
    let reads = 0
    const read = async () => { if (++reads === 1) throw new Error("D1 unavailable"); return reads }
    expect(await withPageReads(get, async () => [await pageRead(get, "a", read).catch(() => "failed"), await pageRead(get, "a", read), await pageRead(get, "a", read)])).toEqual(["failed", 2, 2])
  })
  it("refuses the next page once the session has ended, and a write reads the session afresh", async () => {
    const f = await journey()
    await f.recoverySetup(f.alex)
    await f.createWorkspace(f.alex, "northwind", "Northwind")
    const page = (path: string) => f.request(path, f.alex, undefined, { accept: "text/html" })
    expect((await page("/w/northwind/")).status).toBe(200)
    expect(await (await f.request("/api/account/sessions/end-all", f.alex, {})).json()).toEqual({ pending: false })
    const after = await page("/w/northwind/")
    expect(after.status).toBe(302)
    expect(after.headers.get("location")).toBe("/signin?next=%2Fw%2Fnorthwind%2F")
    expect((await f.request("/api/account/sessions/end-all", f.alex, {})).status).toBe(401)
  }, 60_000)
})
