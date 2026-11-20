// A command line as the guard reads it: simple commands with their words,
// the operators between them and the subshells around them. Quotes and
// backslash escapes are read as the shell reads them, and $HOME, ${HOME}
// and a leading ~ become the home folder, once, here. Nothing is ever run:
// a word whose value depends on something only the shell knows (another
// variable, a substitution) is marked dynamic, a glob or a brace keeps the
// pattern the shell would expand, and the rules decide what an unknown word
// means where it stands.

export type Word = {
  text: string
  // The value depends on a variable, a substitution or similar.
  dynamic: boolean
  // An unquoted *, ? or [ that the shell would expand against files.
  glob: boolean
  // An unquoted {a,b} or {1..3} that the shell would expand.
  brace: boolean
  // The word as a pattern: what was quoted, escaped with a backslash.
  pattern: string
  // The variables it expands, by name.
  vars: string[]
  // A process substitution, <(...) or >(...), standing for a file only the
  // shell names; its commands are read on their own.
  process?: boolean
}

// The reserved words after which (( still starts an arithmetic command.
const ARITHMETIC_AFTER = new Set(["if", "elif", "while", "until", "then", "do", "else", "!", "for", "time", "{"])

// A variable whose name says it holds a key.
export const KEY_VARIABLE = /^[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Za-z0-9_]*$/i

export type Op = "start" | ";" | "&&" | "||" | "|" | "&"

export type ShellNode =
  // `op` joins it to the command before, `next` to the one after; `heredoc`
  // says its input is a here-document or a here-string.
  | { kind: "command"; words: Word[]; inputs: Word[]; op: Op; next: Op | null; heredoc: boolean }
  // A subshell (a list element), or a command or process substitution
  // inside a word (`sub`): what changes inside it ends with it.
  // `process` marks a process substitution, <(...) or >(...).
  | { kind: "open"; op: Op; sub: boolean; process?: boolean }
  | { kind: "close" }
  // A construct outside the grammar the guard reads, with why; `runs` when
  // it may run a command the guard cannot see.
  | { kind: "unknown"; why: string; runs?: boolean }

// Past these the guard does not try to read a command, and says so.
export const MAX_COMMAND_LENGTH = 65_536
export const MAX_NESTING = 32

const OPERATOR_CHARS = " \t\n;&|()<>"
const PATTERN_CHARS = "\\*?[]{},"
// A brace word longer than this is not expanded: it is treated as only
// known when the shell runs it.
const MAX_BRACE_WORD = 4096

export function escapePattern(text: string): string {
  let out = ""
  for (const c of text) out += PATTERN_CHARS.includes(c) ? `\\${c}` : c
  return out
}

// A word the guard made itself, not one the shell would expand.
export function literal(text: string, dynamic = false): Word {
  return { text, dynamic, glob: false, brace: false, pattern: escapePattern(text), vars: [] }
}

const NAME = /[A-Za-z_][A-Za-z0-9_]*/y
const TILDE = /~([A-Za-z0-9_.-]*)/y

class Parser {
  i = 0
  private heredocs: { delimiter: string; strip: boolean; quoted: boolean }[] = []
  private depth: number
  // Found while skipping here-documents, reported with the rest.
  pending: ShellNode[] = []

  constructor(
    private readonly s: string,
    private readonly home: string,
    depth: number,
  ) {
    this.depth = depth
  }

  parse(): ShellNode[] {
    return [...this.list(null), ...this.pending]
  }

  // Commands until `end` (a closing parenthesis) or the end.
  private list(end: string | null): ShellNode[] {
    const nodes: ShellNode[] = []
    if (++this.depth > MAX_NESTING) {
      this.i = this.s.length
      this.depth--
      return [{ kind: "unknown", why: `it is nested too deeply (more than ${MAX_NESTING} levels)`, runs: true }]
    }
    let op: Op = "start"
    let words: Word[] = []
    let inputs: Word[] = []
    let heredoc = false
    const flush = (next: Op | null = null) => {
      if (words.length || inputs.length || heredoc) nodes.push({ kind: "command", words, inputs, op, next, heredoc })
      words = []
      inputs = []
      heredoc = false
    }
    const operator = (next: Op) => {
      flush(next)
      op = next
    }
    while (this.i < this.s.length) {
      const c = this.s[this.i] as string
      if (c === " " || c === "\t") {
        this.i++
        continue
      }
      if (end !== null && c === end) {
        this.i++
        flush()
        this.depth--
        return nodes
      }
      if (c === "\\" && this.s[this.i + 1] === "\n") {
        this.i += 2
        continue
      }
      if (c === "#") {
        while (this.i < this.s.length && this.s[this.i] !== "\n") this.i++
        continue
      }
      if (c === "\n") {
        this.i++
        operator(";")
        this.skipHeredocs()
        continue
      }
      if (c === ";") {
        this.i += this.s[this.i + 1] === ";" ? 2 : 1
        operator(";")
        continue
      }
      if (c === "&") {
        if (this.s[this.i + 1] === "&") {
          this.i += 2
          operator("&&")
        } else if (this.s[this.i + 1] === ">") {
          this.i += this.s[this.i + 2] === ">" ? 3 : 2
          this.skipBlanks()
          this.word(nodes)
        } else {
          this.i++
          operator("&")
        }
        continue
      }
      if (c === "|") {
        if (this.s[this.i + 1] === "|") {
          this.i += 2
          operator("||")
        } else {
          this.i += this.s[this.i + 1] === "&" ? 2 : 1
          operator("|")
        }
        continue
      }
      if (c === "(" && this.s[this.i + 1] === "(" && words.every((w) => !w.dynamic && ARITHMETIC_AFTER.has(w.text))) {
        // (( ... )) where a command starts, after `if`, `while`, `for` and
        // the like: an arithmetic command, which reads variables by name.
        // It runs no program; the word stands for it, with the names it
        // reads. When bash would not read it as arithmetic, it is subshells.
        const end = this.arithmeticEnd(this.i + 2)
        if (end !== -1) {
          const word: Word = { text: "((", dynamic: false, glob: false, brace: false, pattern: "((", vars: [] }
          this.arithmetic(word, nodes, this.i + 2, end)
          words.push(word)
          continue
        }
      }
      if (c === "(") {
        this.i++
        if (words.length) {
          nodes.push({ kind: "unknown", why: this.s[this.i] === ")" ? "a function definition" : "a parenthesis in the middle of a command" })
          if (this.s[this.i] === ")") this.i++
          words = []
          continue
        }
        flush()
        nodes.push({ kind: "unknown", why: "a subshell" })
        nodes.push({ kind: "open", op, sub: false })
        nodes.push(...this.list(")"))
        nodes.push({ kind: "close" })
        op = ";"
        continue
      }
      if (c === ")") {
        this.i++
        nodes.push({ kind: "unknown", why: "an unmatched parenthesis" })
        continue
      }
      if ((c === "<" || c === ">") && this.s[this.i + 1] === "(") {
        this.i += 2
        nodes.push({ kind: "open", op: "start", sub: true, process: true }, ...this.list(")"), { kind: "close" })
        words.push({ text: "", dynamic: true, glob: false, brace: false, pattern: "", vars: [], process: true })
        continue
      }
      if (c === "<" || c === ">") {
        if (this.redirect(nodes, (word) => inputs.push(word))) heredoc = true
        continue
      }
      const start = this.i
      const word = this.word(nodes)
      // 2>file, 0<file: the digits are a file descriptor, not a word.
      if (/^\d+$/.test(word.text) && !word.dynamic && this.i === start + word.text.length && (this.s[this.i] === "<" || this.s[this.i] === ">")) continue
      words.push(word)
    }
    flush()
    if (end !== null) nodes.push({ kind: "unknown", why: "an unclosed parenthesis" })
    this.depth--
    return nodes
  }

  // One redirection; true when it gives the command a here-document or a
  // here-string as its input.
  private redirect(nodes: ShellNode[], input: (word: Word) => void): boolean {
    const s = this.s
    if (s.startsWith("<<<", this.i)) {
      nodes.push({ kind: "unknown", why: "a here-string" })
      this.i += 3
      this.skipBlanks()
      const key = this.word(nodes).vars.find((v) => KEY_VARIABLE.test(v))
      if (key) nodes.push({ kind: "unknown", why: `a here-string that expands $${key}`, runs: true })
      return true
    }
    if (s.startsWith("<<", this.i)) {
      this.i += 2
      const strip = s[this.i] === "-"
      if (strip) this.i++
      this.skipBlanks()
      const raw = this.i
      const delimiter = this.word(nodes)
      this.heredocs.push({ delimiter: delimiter.text, strip, quoted: /['"\\]/.test(s.slice(raw, this.i)) })
      return true
    }
    const reading = s[this.i] === "<"
    this.i++
    if (s[this.i] === ">" || s[this.i] === "|" || s[this.i] === "&") this.i++
    this.skipBlanks()
    if (s[this.i] === "-" && (this.i + 1 >= s.length || OPERATOR_CHARS.includes(s[this.i + 1] as string))) {
      this.i++
      return false
    }
    const target = this.word(nodes)
    // <&3, >&2: a file descriptor, not a file.
    if (/^\d+$/.test(target.text) && s[this.i - target.text.length - 1] === "&") return false
    if (reading) input(target)
    return false
  }

  // The bodies of the here-documents started on the line just ended. An
  // unquoted one that runs a command is not followed.
  private skipHeredocs(): void {
    for (const { delimiter, strip, quoted } of this.heredocs) {
      while (this.i < this.s.length) {
        const eol = this.s.indexOf("\n", this.i)
        const line = this.s.slice(this.i, eol === -1 ? this.s.length : eol)
        this.i = eol === -1 ? this.s.length : eol + 1
        if ((strip ? line.replace(/^\t+/, "") : line) === delimiter) break
        if (quoted) continue
        if (/\$\(|`/.test(line)) this.pending.push({ kind: "unknown", why: "a here-document that runs a command", runs: true })
        // An unquoted body expands its variables, and prints them to
        // whatever reads it.
        for (const match of line.matchAll(/\$\{?[#!]?([A-Za-z_][A-Za-z0-9_]*)/g)) {
          if (KEY_VARIABLE.test(match[1] as string)) this.pending.push({ kind: "unknown", why: `a here-document that expands $${match[1]}`, runs: true })
        }
      }
    }
    this.heredocs = []
  }

  private skipBlanks(): void {
    while (this.s[this.i] === " " || this.s[this.i] === "\t") this.i++
  }

  // Whether an unquoted { at `at` opens a brace expansion: a matching }
  // with a top-level comma or `..`, before a blank, an operator, a quote
  // or an expansion. One scan per run of braces, so the whole is linear:
  // a { inside a run already scanned is decided by that scan.
  private braceScanEnd = -1
  private braceScan(at: number, word: Word): void {
    if (at < this.braceScanEnd) return
    const s = this.s
    let depth = 0
    let separator = false
    let j = at
    for (; j < s.length; j++) {
      const c = s[j] as string
      if (OPERATOR_CHARS.includes(c)) break
      if (c === "'" || c === '"' || c === "$" || c === "`" || c === "\\") {
        // A brace with quoting or an expansion inside: only the shell
        // knows what it makes.
        if (depth > 0) word.dynamic = true
        break
      }
      if (c === "{") depth++
      else if (c === "}") {
        depth--
        if (depth === 0) {
          if (separator) word.brace = true
          j++
          break
        }
      } else if (depth === 1 && (c === "," || (c === "." && s[j + 1] === "."))) separator = true
    }
    this.braceScanEnd = j
  }

  // Whether the bracket expression opening at this [ holds a POSIX class,
  // [:alpha:], [=a=] or [.a.], scanned to its closing ] and no further; a
  // [ inside a run already scanned is decided by that scan, so the whole
  // line is read once.
  private bracketScanEnd = -1
  private bracketScan(nodes: ShellNode[]): void {
    if (this.i < this.bracketScanEnd) return
    const s = this.s
    let j = this.i + 1
    if (s[j] === "!" || s[j] === "^") j++
    if (s[j] === "]") j++
    for (; j < s.length; j++) {
      const c = s[j] as string
      // An escaped character, ] among them, is a member and never the end.
      if (c === "\\") {
        j++
        continue
      }
      if (c === "]" || OPERATOR_CHARS.includes(c) || c === "'" || c === '"') break
      if (c === "[" && (s[j + 1] === ":" || s[j + 1] === "=" || s[j + 1] === ".")) {
        nodes.push({ kind: "unknown", why: "a POSIX character class in a glob" })
        break
      }
    }
    this.bracketScanEnd = j
  }

  // One word, with what substitutions inside it run pushed to `nodes`.
  private word(nodes: ShellNode[]): Word {
    const s = this.s
    const word: Word = { text: "", dynamic: false, glob: false, brace: false, pattern: "", vars: [] }
    const add = (text: string, quoted: boolean) => {
      word.text += text
      word.pattern += quoted ? escapePattern(text) : text
    }
    const start = this.i
    while (this.i < s.length) {
      const c = s[this.i] as string
      if (OPERATOR_CHARS.includes(c)) break
      if (c === "\\") {
        if (s[this.i + 1] === "\n") this.i += 2
        else {
          add(s[this.i + 1] ?? "", true)
          this.i += 2
        }
        continue
      }
      if (c === "'") {
        const close = s.indexOf("'", this.i + 1)
        if (close === -1) {
          add(s.slice(this.i + 1), true)
          word.dynamic = true
          this.i = s.length
          break
        }
        add(s.slice(this.i + 1, close), true)
        this.i = close + 1
        continue
      }
      if (c === '"') {
        this.i++
        this.doubleQuoted(word, nodes, add)
        continue
      }
      if (c === "$") {
        this.dollar(word, nodes, add)
        continue
      }
      if (c === "`") {
        this.backtick(word, nodes)
        continue
      }
      if (c === "~" && this.i === start) {
        TILDE.lastIndex = this.i
        const name = TILDE.exec(s)?.[1] ?? ""
        const after = s[this.i + 1 + name.length]
        if (after === undefined || after === "/" || OPERATOR_CHARS.includes(after)) {
          if (name === "") add(this.home, true)
          else {
            add(`~${name}`, true)
            word.dynamic = true
          }
          this.i += 1 + name.length
          continue
        }
      }
      if (c === "*" || c === "?" || c === "[") word.glob = true
      if (c === "[") this.bracketScan(nodes)
      if ("?*+@!".includes(c) && s[this.i + 1] === "(") nodes.push({ kind: "unknown", why: "an extended glob" })
      if (c === "{") this.braceScan(this.i, word)
      add(c, false)
      this.i++
    }
    if (word.brace && word.text.length > MAX_BRACE_WORD) word.dynamic = true
    return word
  }

  private doubleQuoted(word: Word, nodes: ShellNode[], add: (text: string, quoted: boolean) => void): void {
    const s = this.s
    while (this.i < s.length) {
      const c = s[this.i] as string
      if (c === '"') {
        this.i++
        return
      }
      if (c === "\\") {
        const next = s[this.i + 1]
        if (next === "\n") this.i += 2
        else if (next === "$" || next === "`" || next === '"' || next === "\\") {
          add(next, true)
          this.i += 2
        } else {
          add(c, true)
          this.i++
        }
        continue
      }
      if (c === "$") {
        this.dollar(word, nodes, add)
        continue
      }
      if (c === "`") {
        this.backtick(word, nodes)
        continue
      }
      add(c, true)
      this.i++
    }
    word.dynamic = true
  }

  // Where (( or $(( ends, by bash's rule: the ) that matches the second (
  // must be followed at once by another ), or bash reads the text as a
  // subshell (or a command substitution holding one) instead. Quotes and
  // escapes are skipped as bash skips them. -1 when it is not arithmetic.
  private arithmeticEnd(from: number): number {
    const s = this.s
    let depth = 1
    for (let j = from; j < s.length; j++) {
      const c = s[j] as string
      if (c === "\\") j++
      else if (c === "'") {
        const close = s.indexOf("'", j + 1)
        if (close === -1) return -1
        j = close
      } else if (c === '"') {
        let k = j + 1
        for (; k < s.length && s[k] !== '"'; k++) if (s[k] === "\\") k++
        if (k >= s.length) return -1
        j = k
      } else if (c === "(") depth++
      else if (c === ")" && --depth === 0) return s[j + 1] === ")" ? j : -1
    }
    return -1
  }

  // (( ... )) or $(( ... )), its text from `from` to `end`, the first of
  // the two closing parentheses. A command substitution inside it is not
  // followed, and is refused. Arithmetic reads a variable by its bare
  // name, so every name in it counts as one the word expands.
  private arithmetic(word: Word, nodes: ShellNode[], from: number, end: number): void {
    nodes.push({ kind: "unknown", why: "arithmetic" })
    const body = this.s.slice(from, end)
    // A nested $(( that bash would not read as arithmetic is a command
    // substitution, as is any other $( or a backtick.
    let substitution = body.includes("`")
    for (let at = this.s.indexOf("$(", from); !substitution && at !== -1 && at < end; at = this.s.indexOf("$(", at + 2)) {
      substitution = this.s[at + 2] !== "(" || this.arithmeticEnd(at + 3) === -1
    }
    if (substitution) nodes.push({ kind: "unknown", why: "a command substitution inside $(( ))", runs: true })
    for (const name of body.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []) word.vars.push(name)
    this.i = end + 2
  }

  // $[ ... ]: bash's old spelling of arithmetic, read to its matching ].
  private legacyArithmetic(word: Word, nodes: ShellNode[]): void {
    const s = this.s
    nodes.push({ kind: "unknown", why: "arithmetic" })
    let depth = 1
    let j = this.i + 2
    for (; j < s.length && depth > 0; j++) {
      const c = s[j] as string
      if (c === "[") depth++
      else if (c === "]") depth--
      else if (c === "`" || (c === "$" && s[j + 1] === "(")) nodes.push({ kind: "unknown", why: "a command substitution inside $[ ]", runs: true })
    }
    if (depth > 0) nodes.push({ kind: "unknown", why: "an unclosed $[", runs: true })
    for (const name of s.slice(this.i + 2, j).match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []) word.vars.push(name)
    this.i = j
    word.dynamic = true
  }

  private dollar(word: Word, nodes: ShellNode[], add: (text: string, quoted: boolean) => void): void {
    const s = this.s
    const next = s[this.i + 1]
    if (next === "(") {
      if (s[this.i + 2] === "(") {
        const end = this.arithmeticEnd(this.i + 3)
        if (end !== -1) {
          this.arithmetic(word, nodes, this.i + 3, end)
          word.dynamic = true
          return
        }
      }
      this.i += 2
      nodes.push({ kind: "open", op: "start", sub: true }, ...this.list(")"), { kind: "close" })
      word.dynamic = true
      return
    }
    if (next === "[") return this.legacyArithmetic(word, nodes)
    if (next === "{") {
      // ${NAME} alone is in the grammar; anything with an operator is not,
      // and one that holds a command substitution runs a command the
      // guard does not follow.
      let depth = 0
      let close = -1
      for (let j = this.i + 1; j < s.length; j++) {
        const d = s[j]
        if (d === "\\") j++
        else if (d === "{") depth++
        else if (d === "}" && --depth === 0) {
          close = j
          break
        }
      }
      const body = close === -1 ? s.slice(this.i + 2) : s.slice(this.i + 2, close)
      this.i = close === -1 ? s.length : close + 1
      const named = /^[#!]?([A-Za-z_][A-Za-z0-9_]*)/.exec(body)?.[1]
      if (named) word.vars.push(named)
      if (body === "HOME") add(this.home, true)
      else {
        word.dynamic = true
        if (!/^([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])$/.test(body)) nodes.push({ kind: "unknown", why: "a ${...} with an operator", runs: /\$\(|`/.test(body) || close === -1 })
      }
      return
    }
    NAME.lastIndex = this.i + 1
    const name = NAME.exec(s)?.[0]
    if (name) {
      word.vars.push(name)
      this.i += 1 + name.length
      if (name === "HOME") add(this.home, true)
      else word.dynamic = true
      return
    }
    if (next !== undefined && "@*#?$!-0123456789".includes(next)) {
      this.i += 2
      word.dynamic = true
      return
    }
    if (next === "'" || next === '"') {
      // $'...' and $"...": quoting outside the grammar.
      nodes.push({ kind: "unknown", why: next === "'" ? "$'...' quoting" : "$\"...\" quoting" })
      this.i++
      word.dynamic = true
      return
    }
    add("$", true)
    this.i++
  }

  private backtick(word: Word, nodes: ShellNode[]): void {
    let close = this.i + 1
    while (close < this.s.length && this.s[close] !== "`") close += this.s[close] === "\\" ? 2 : 1
    const inner = this.s.slice(this.i + 1, close).replace(/\\([`$\\])/g, "$1")
    this.i = Math.min(close + 1, this.s.length)
    nodes.push({ kind: "open", op: "start", sub: true }, ...new Parser(inner, this.home, this.depth).parse(), { kind: "close" })
    word.dynamic = true
  }
}

// The command as bash reads it once its line continuations are gone: a
// backslash before a newline is removed with the newline, except inside
// single quotes or $'...', in a comment, and in the body of a quoted
// here-document, as bash does. So `$\<newline>{!v}` is `${!v}` and
// `$\<newline>OPENAI_API_KEY` expands the key.
export function logicalText(s: string): string {
  let out = ""
  let i = 0
  let wordStart = true
  const docs: { delimiter: string; strip: boolean; quoted: boolean }[] = []
  // Copies a quoted run whose opening is `open` characters long, to its
  // closing quote: backslash escapes the next character when `escapes`,
  // and drops with a newline when `continuations`.
  const copyQuoted = (open: number, close: string, escapes: boolean, continuations: boolean) => {
    out += s.slice(i, i + open)
    i += open
    while (i < s.length && s[i] !== close) {
      if (escapes && s[i] === "\\") {
        if (!(continuations && s[i + 1] === "\n")) out += s.slice(i, i + 2)
        i += 2
        continue
      }
      out += s[i]
      i++
    }
    if (i < s.length) {
      out += s[i]
      i++
    }
  }
  while (i < s.length) {
    const c = s[i] as string
    if (c === "\\") {
      // A continuation vanishes, so whether a word starts here is as it was
      // before it; an escaped character is part of a word.
      if (s[i + 1] !== "\n") {
        out += s.slice(i, i + 2)
        wordStart = false
      }
      i += 2
      continue
    }
    if (c === "'") {
      copyQuoted(1, "'", false, false)
      wordStart = false
      continue
    }
    if (c === "$" && s[i + 1] === "'") {
      copyQuoted(2, "'", true, false)
      wordStart = false
      continue
    }
    if (c === '"') {
      copyQuoted(1, '"', true, true)
      wordStart = false
      continue
    }
    if (c === "#" && wordStart) {
      const eol = s.indexOf("\n", i)
      const end = eol === -1 ? s.length : eol
      out += s.slice(i, end)
      i = end
      continue
    }
    if (c === "<" && s[i + 1] === "<" && s[i + 2] !== "<") {
      // A here-document: its delimiter word, quoted if any part of it is.
      let j = i + 2
      const strip = s[j] === "-"
      if (strip) j++
      while (s[j] === " " || s[j] === "\t") j++
      const start = j
      while (j < s.length && !/[\s;&|<>()]/.test(s[j] as string)) {
        if (s[j] === "'" || s[j] === '"') {
          const close = s.indexOf(s[j] as string, j + 1)
          j = close === -1 ? s.length : close + 1
        } else j += s[j] === "\\" ? 2 : 1
      }
      const raw = s.slice(start, j)
      docs.push({ delimiter: raw.replace(/\\(.)/gs, "$1").replace(/['"]/g, ""), strip, quoted: /['"\\]/.test(raw) })
      out += s.slice(i, j)
      i = j
      wordStart = false
      continue
    }
    if (c === "\n") {
      out += c
      i++
      wordStart = true
      // The bodies of the here-documents this line opened, line by line: a
      // quoted one as written, an unquoted one with its continuations gone.
      for (const doc of docs) {
        while (i < s.length) {
          let line = ""
          let ended = false
          while (i < s.length) {
            if (s[i] === "\n") {
              i++
              ended = true
              break
            }
            if (!doc.quoted && s[i] === "\\") {
              if (s[i + 1] !== "\n") line += s.slice(i, i + 2)
              i += 2
              continue
            }
            line += s[i]
            i++
          }
          out += ended ? `${line}\n` : line
          if ((doc.strip ? line.replace(/^\t+/, "") : line) === doc.delimiter) break
        }
      }
      docs.length = 0
      continue
    }
    out += c
    i++
    wordStart = /[\s;&|()]/.test(c)
  }
  return out
}

export function parseShell(command: string, home: string): ShellNode[] {
  if (command.length > MAX_COMMAND_LENGTH) return [{ kind: "unknown", why: `it is too long for the guard to read (more than ${MAX_COMMAND_LENGTH} characters)`, runs: true }]
  // A command another shell runs (bash -c, eval, env -S) loses its own
  // continuations too.
  return new Parser(logicalText(command), home, 0).parse()
}
