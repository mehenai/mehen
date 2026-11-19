// Every write to the access graph in the vault, the rows that decide who
// manages a credential's home, runs the management guard first, so an
// expired manage share lapses the mandates it took management from before
// anything can hide that or stand in for it (settleShareExpiries in
// apps/vault/src/vault/areas/mandates-workspace.ts). Read from the source:
// each sql.exec whose statement writes the graph must have a call to a guard
// before it in its own function or one enclosing it, and the functions that
// write the graph are listed here, so a new writer fails until it is guarded
// and named.

import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { join, relative, resolve } from "node:path"
import ts from "typescript"

const ROOT = resolve(import.meta.dir, "..", "..")
const SOURCE = join(ROOT, "apps", "vault", "src")

// Writes that can change who manages an existing credential's home: team
// membership, a team deleted, any share, a member made or their role or
// status changed, a credential made, deleted or moved, a project deleted.
// A team or project made empty, a rename and a member's gate generation
// change nobody's management, and are left out.
const GRAPH_WRITES: readonly RegExp[] = [
  /\b(INSERT(\s+OR\s+\w+)?\s+INTO|DELETE\s+FROM|UPDATE)\s+(team_members|project_shares)\b/i,
  /\bDELETE\s+FROM\s+(teams|projects|items)\b/i,
  /\bINSERT(\s+OR\s+\w+)?\s+INTO\s+(members|items)\b/i,
  /\bUPDATE\s+members\s+SET\b.*\b(role|status)\s*=/is,
  /\bUPDATE\s+items\s+SET\b.*\bhome_kind\s*=/is,
]
// beforeManagementChange runs every guard; accessChanged runs it before the
// access change hooks; settleShareExpiries is the mandates guard itself.
const GUARDS = new Set(["beforeManagementChange", "accessChanged", "settleShareExpiries"])

// The functions that write the graph, by file and the name of the nearest
// named function, method or property around the write.
const WRITERS = [
  "vault/areas/items-workspace.ts#items.delete",
  "vault/areas/items-workspace.ts#items.rehome",
  "vault/areas/items-workspace.ts#offboardCredentials",
  "vault/areas/items-workspace.ts#storeCredential",
  "vault/areas/items.ts#deleteItem",
  "vault/areas/items.ts#putItem",
  "vault/areas/managed.ts#removeItem",
  "vault/areas/projects-workspace.ts#projects.delete",
  "vault/areas/workspace-members.ts#access.members.role",
  "vault/areas/workspace-members.ts#access.team.members",
  "vault/areas/workspace-members.ts#access.team.update",
  "vault/areas/workspace-members.ts#workspaceMemberOps",
  "vault/areas/workspace-runtime.ts#activateInvitedMember",
  "vault/areas/workspace-runtime.ts#installIdentity",
  "vault/areas/workspace-runtime.ts#newMember",
  "vault/areas/workspace-runtime.ts#setProjectShare",
]

type Write = { file: string; writer: string; line: number; sql: string; guarded: boolean }

function sourceFiles(): string[] {
  return [...new Bun.Glob("**/*.ts").scanSync(SOURCE)].filter((path) => !path.endsWith(".test.ts") && !path.startsWith("ui/")).sort()
}

const functionLike = (node: ts.Node): boolean => ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node)
const nameText = (name: ts.PropertyName | ts.BindingName | undefined): string | null => (name && (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) ? name.text : null)

// The nearest named function, method (not a bare handler) or property.
function writerName(node: ts.Node): string {
  for (let at: ts.Node | undefined = node.parent; at; at = at.parent) {
    if ((ts.isFunctionDeclaration(at) || ts.isVariableDeclaration(at) || ts.isPropertyAssignment(at)) && nameText(at.name)) return nameText(at.name) as string
    if (ts.isMethodDeclaration(at) && nameText(at.name) && nameText(at.name) !== "handler") return nameText(at.name) as string
  }
  return "<top level>"
}

// Whether a guard is called before `at` inside one of its enclosing functions.
function guardedBefore(at: ts.Node): boolean {
  for (let scope: ts.Node | undefined = at.parent; scope; scope = scope.parent) {
    if (!functionLike(scope)) continue
    let found = false
    const visit = (node: ts.Node): void => {
      if (found || node.getStart() >= at.getStart()) return
      if (ts.isCallExpression(node)) {
        const callee = node.expression
        const name = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : null
        if (name !== null && GUARDS.has(name) && node.getEnd() <= at.getStart()) found = true
      }
      ts.forEachChild(node, visit)
    }
    ts.forEachChild(scope, visit)
    if (found) return true
  }
  return false
}

function graphWrites(): Write[] {
  const writes: Write[] = []
  for (const path of sourceFiles()) {
    const file = ts.createSourceFile(path, readFileSync(join(SOURCE, path), "utf8"), ts.ScriptTarget.Latest, true)
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "exec" && node.arguments[0]) {
        const sql = node.arguments[0].getText(file)
        if (GRAPH_WRITES.some((pattern) => pattern.test(sql))) {
          writes.push({ file: relative(SOURCE, file.fileName === path ? join(SOURCE, path) : file.fileName), writer: writerName(node), line: file.getLineAndCharacterOfPosition(node.getStart()).line + 1, sql: sql.slice(0, 80), guarded: guardedBefore(node) })
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(file)
  }
  return writes
}

describe("the access graph's writers", () => {
  const writes = graphWrites()

  test("are the ones listed", () => {
    expect([...new Set(writes.map((w) => `${w.file}#${w.writer}`))].sort()).toEqual(WRITERS)
  })

  test("each run the management guard before they write", () => {
    expect(writes.filter((w) => !w.guarded).map((w) => `${w.file}:${w.line} (${w.writer}) ${w.sql}`)).toEqual([])
  })

  test("finds an unguarded writer", () => {
    const source = `function grant(ctx) { ctx.sql.exec("INSERT INTO team_members(team,member) VALUES (?,?)", "t", "m") }\nfunction guarded(ctx) { beforeManagementChange(ctx); ctx.sql.exec("DELETE FROM project_shares WHERE id=?", "s") }\nfunction late(ctx) { ctx.sql.exec("UPDATE members SET role=? WHERE id=?", "admin", "m"); accessChanged(ctx, "m", "role") }`
    const file = ts.createSourceFile("probe.ts", source, ts.ScriptTarget.Latest, true)
    const found: [string, boolean][] = []
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "exec") found.push([writerName(node), guardedBefore(node)])
      ts.forEachChild(node, visit)
    }
    visit(file)
    expect(found).toEqual([["grant", false], ["guarded", true], ["late", false]])
  })
})
