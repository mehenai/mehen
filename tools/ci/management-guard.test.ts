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
// membership or any column of it, a team deleted, any share or any column
// of one, a member made or their role or status changed, a credential made,
// deleted or moved (either home column on its own), a project deleted. A
// team or project made empty, a rename and a member's gate generation
// change nobody's management, and are left out.
const INSERT = String.raw`(INSERT(\s+OR\s+\w+)?|REPLACE)\s+INTO`
const GRAPH_WRITES: readonly RegExp[] = [
  new RegExp(String.raw`\b(${INSERT}|DELETE\s+FROM|UPDATE(\s+OR\s+\w+)?)\s+(team_members|project_shares)\b`, "i"),
  /\bDELETE\s+FROM\s+(teams|projects|items)\b/i,
  new RegExp(String.raw`\b${INSERT}\s+(members|items)\b`, "i"),
  /\bUPDATE(\s+OR\s+\w+)?\s+members\s+SET\b.*\b(role|status)\s*=/is,
  /\bUPDATE(\s+OR\s+\w+)?\s+items\s+SET\b.*\b(home_kind|home_id)\s*=/is,
]
export const writesGraph = (sql: string): boolean => GRAPH_WRITES.some((pattern) => pattern.test(sql))
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

// Whether a statement is a plain call to a guard, as `guard(ctx)` or
// `runtime.guard(ctx)`, so it runs whenever the statement does.
function guardStatement(statement: ts.Statement): boolean {
  if (!ts.isExpressionStatement(statement) || !ts.isCallExpression(statement.expression)) return false
  const callee = statement.expression.expression
  const name = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : null
  return name !== null && GUARDS.has(name)
}
// Whether a guard surely runs before `at`: as an earlier statement of the
// block that holds it, or of a block enclosing that one, in its own
// function. A guard in a branch or loop body that does not also hold the
// write, or in a nested function or callback, does not count, and the walk
// stops at the write's function.
function guardedBefore(at: ts.Node): boolean {
  let child: ts.Node = at
  for (let parent: ts.Node | undefined = at.parent; parent; child = parent, parent = parent.parent) {
    if (ts.isBlock(parent) || ts.isSourceFile(parent) || ts.isCaseClause(parent) || ts.isDefaultClause(parent)) {
      const statements: readonly ts.Statement[] = parent.statements
      const index = statements.indexOf(child as ts.Statement)
      if (statements.slice(0, index).some(guardStatement)) return true
    }
    if (functionLike(parent)) return false
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
        if (writesGraph(sql)) {
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

  // Each probe function writes once; whether the check counts it guarded.
  test.each([
    ["grant", false, `function grant(ctx) { ctx.sql.exec("INSERT INTO team_members(team,member) VALUES (?,?)", "t", "m") }`],
    ["guarded", true, `function guarded(ctx) { beforeManagementChange(ctx); ctx.sql.exec("DELETE FROM project_shares WHERE id=?", "s") }`],
    ["late", false, `function late(ctx) { ctx.sql.exec("UPDATE members SET role=? WHERE id=?", "admin", "m"); accessChanged(ctx, "m", "role") }`],
    ["conditional", false, `function conditional(ctx, x) { if (x) beforeManagementChange(ctx); ctx.sql.exec("DELETE FROM items WHERE id=?", "i") }`],
    ["neverRun", false, `function neverRun(ctx) { if (false) { beforeManagementChange(ctx) } ctx.sql.exec("DELETE FROM items WHERE id=?", "i") }`],
    ["unusedCallback", false, `function unusedCallback(ctx) { const unused = () => beforeManagementChange(ctx); ctx.sql.exec("DELETE FROM items WHERE id=?", "i") }`],
    ["inCallback", false, `function inCallback(ctx, list) { list.forEach(() => beforeManagementChange(ctx)); ctx.sql.exec("DELETE FROM items WHERE id=?", "i") }`],
    ["returningBranch", false, `function returningBranch(ctx, x) { if (x) { beforeManagementChange(ctx); return } ctx.sql.exec("DELETE FROM items WHERE id=?", "i") }`],
    ["loopBody", false, `function loopBody(ctx, list) { for (const x of list) { beforeManagementChange(ctx) } ctx.sql.exec("DELETE FROM items WHERE id=?", "i") }`],
    ["otherCase", false, `function otherCase(ctx, x) { switch (x) { case 1: beforeManagementChange(ctx); break; case 2: ctx.sql.exec("DELETE FROM items WHERE id=?", "i") } }`],
    ["outerFunction", false, `function outerFunction(ctx) { beforeManagementChange(ctx); run(() => { ctx.sql.exec("DELETE FROM items WHERE id=?", "i") }) }`],
    ["enclosingBlock", true, `function enclosingBlock(ctx, x) { beforeManagementChange(ctx); if (x) { for (const y of x) ctx.sql.exec("DELETE FROM items WHERE id=?", y) } }`],
    ["sameCase", true, `function sameCase(ctx, x) { switch (x) { case 1: settleShareExpiries(ctx); ctx.sql.exec("DELETE FROM items WHERE id=?", "i") } }`],
    ["inTransaction", true, `function inTransaction(ctx) { return ctx.storage.transactionSync(() => { runtime.accessChanged(ctx, null, "x"); ctx.sql.exec("DELETE FROM teams WHERE id=?", "t") }) }`],
  ])("a probe write in %s counts as guarded: %p", (name, guarded, source) => {
    const file = ts.createSourceFile("probe.ts", source, ts.ScriptTarget.Latest, true)
    const found: [string, boolean][] = []
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "exec") found.push([writerName(node), guardedBefore(node)])
      ts.forEachChild(node, visit)
    }
    visit(file)
    expect(found).toEqual([[name, guarded]])
  })

  test.each([
    "INSERT INTO team_members(team,member) VALUES (?,?)",
    "INSERT OR IGNORE INTO team_members(team,member) VALUES (?,?)",
    "REPLACE INTO team_members(team,member) VALUES (?,?)",
    "UPDATE team_members SET team=? WHERE team=? AND member=?",
    "DELETE FROM team_members WHERE member=?",
    "INSERT INTO project_shares VALUES (?,?,?,?,?)",
    "UPDATE project_shares SET value=? WHERE id=?",
    "UPDATE project_shares SET subject_id=? WHERE id=?",
    "UPDATE OR REPLACE project_shares SET project=? WHERE id=?",
    "DELETE FROM project_shares WHERE id=?",
    "DELETE FROM teams WHERE id=?",
    "DELETE FROM projects WHERE id=?",
    "INSERT INTO members(id,account,name,role,status,joined_at) VALUES (?,?,?,?,?,?)",
    "INSERT OR REPLACE INTO members(id) VALUES (?)",
    "UPDATE members SET role=? WHERE id=?",
    "UPDATE members SET role=pending_role,pending_role=NULL WHERE id=?",
    "UPDATE members SET status='removed' WHERE id=?",
    "UPDATE members SET revision=revision+1, status = ? WHERE id=?",
    "INSERT INTO items (id,slug) VALUES (?,?)",
    "DELETE FROM items WHERE id=?",
    "UPDATE items SET home_kind=?,home_id=? WHERE id=?",
    "UPDATE items SET home_id=? WHERE id=?",
    "UPDATE items SET home_kind='workspace' WHERE id=?",
  ])("writes the graph: %s", (sql) => {
    expect(writesGraph(sql)).toBe(true)
  })

  test.each([
    "INSERT INTO teams VALUES (?,?,?,?,?)",
    "UPDATE teams SET name=?,slug=? WHERE id=?",
    "INSERT INTO projects(id,slug) VALUES (?,?)",
    "UPDATE members SET pending_role=NULL,pending_since=NULL WHERE id=?",
    "UPDATE members SET gate_generation=gate_generation+1,revision=revision+1",
    "UPDATE members SET check_sequence=? WHERE id=?",
    "UPDATE items SET policy=? WHERE slug=?",
    "UPDATE items SET dependency_revision=dependency_revision+1 WHERE id=?",
    "SELECT home_id FROM items WHERE id=?",
  ])("does not write the graph: %s", (sql) => {
    expect(writesGraph(sql)).toBe(false)
  })
})
