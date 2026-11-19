// A command line as the guard reads it: simple commands with their words,
// the operators between them and the subshells around them. Quotes and
// backslash escapes are read as the shell reads them, and $HOME, ${HOME}
// and a leading ~ become the home folder, once, here. Nothing is ever run:
// a word whose value depends on something only the shell knows (another
// variable, a substitution, a glob, a brace) is marked, and the rules decide
// what an unknown word means where it stands.

export type Word = {
  text: string
  // The value depends on a variable, a substitution or similar.
  dynamic: boolean
  // An unquoted *, ? or [ that the shell would expand.
  glob: boolean
}

export type Op = "start" | ";" | "&&" | "||" | "|" | "&"

export type ShellNode =
  // `op` joins it to the command before, `next` to the one after.
  | { kind: "command"; words: Word[]; inputs: Word[]; op: Op; next: Op | null }
  // A subshell, a command or process substitution: what changes inside it
  // (the folder, the directory stack) ends with it.
  | { kind: "open"; op: Op }
  | { kind: "close" }
  // Something the guard does not read, with why.
  | { kind: "unknown"; why: string }

const OPERATOR_CHARS = " \t\n;&|()<>"

class Parser {
  i = 0
  private heredocs: { delimiter: string; strip: boolean }[] = []

  constructor(
    private readonly s: string,
    private readonly home: string,
  ) {}

  parse(): ShellNode[] {
    return this.list(null)
  }

  // Commands until `end` (a closing parenthesis or backtick) or the end.
  private list(end: string | null): ShellNode[] {
    const nodes: ShellNode[] = []
    let op: Op = "start"
    let words: Word[] = []
    let inputs: Word[] = []
    const flush = (next: Op | null = null) => {
      if (words.length || inputs.length) nodes.push({ kind: "command", words, inputs, op, next })
      words = []
      inputs = []
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
        return nodes
      }
      if (c === "\\" && this.s[this.i + 1] === "\n") {
        this.i += 2
        continue
      }
      if (c === "#" ) {
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
      if (c === "(") {
        this.i++
        if (words.length) {
          // name() { ... }: a function definition; its body is read as
          // commands like any other.
          if (this.s[this.i] === ")") {
            this.i++
            words = []
            continue
          }
          nodes.push({ kind: "unknown", why: "a parenthesis in the middle of a command" })
          continue
        }
        flush()
        nodes.push({ kind: "open", op })
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
      if (c === "<" || c === ">") {
        this.redirect(nodes, (word) => inputs.push(word))
        continue
      }
      const start = this.i
      const word = this.word(nodes)
      // 2>file, 0<file: the digits are a file descriptor, not a word.
      if (/^\d+$/.test(word.text) && !word.dynamic && this.i === start + word.text.length && (this.s[this.i] === "<" || this.s[this.i] === ">")) continue
      words.push(word)
    }
    flush()
    if (end !== null) nodes.push({ kind: "unknown", why: `an unclosed ${end === ")" ? "parenthesis" : "backtick"}` })
    return nodes
  }

  private redirect(nodes: ShellNode[], input: (word: Word) => void): void {
    const s = this.s
    if (s.startsWith("<<<", this.i)) {
      this.i += 3
      this.skipBlanks()
      this.word(nodes)
      return
    }
    if (s.startsWith("<<", this.i)) {
      this.i += 2
      const strip = s[this.i] === "-"
      if (strip) this.i++
      this.skipBlanks()
      const raw = this.i
      const delimiter = this.word(nodes)
      const quoted = /['"\\]/.test(s.slice(raw, this.i))
      this.heredocs.push({ delimiter: delimiter.text, strip })
      if (!quoted) this.unquotedHeredoc = true
      return
    }
    if (s.startsWith("<(", this.i) || s.startsWith(">(", this.i)) {
      const reading = s[this.i] === "<"
      this.i += 2
      nodes.push({ kind: "open", op: "start" }, ...this.list(")"), { kind: "close" })
      if (reading) return
      return
    }
    const reading = s[this.i] === "<"
    this.i++
    if (s[this.i] === ">" || s[this.i] === "|" || s[this.i] === "&") this.i++
    this.skipBlanks()
    if (s[this.i] === "-" && (this.i + 1 >= s.length || OPERATOR_CHARS.includes(s[this.i + 1] as string))) {
      this.i++
      return
    }
    const target = this.word(nodes)
    // <&3, >&2: a file descriptor, not a file.
    if (/^\d+$/.test(target.text) && s[this.i - target.text.length - 1] === "&") return
    if (reading) input(target)
  }

  private unquotedHeredoc = false

  // The bodies of the here-documents started on the line just ended.
  private skipHeredocs(): void {
    for (const { delimiter, strip } of this.heredocs) {
      while (this.i < this.s.length) {
        const eol = this.s.indexOf("\n", this.i)
        const line = this.s.slice(this.i, eol === -1 ? this.s.length : eol)
        this.i = eol === -1 ? this.s.length : eol + 1
        if (this.unquotedHeredoc && /\$\(|`/.test(line)) this.pending.push({ kind: "unknown", why: "a here-document that runs a command" })
        if ((strip ? line.replace(/^\t+/, "") : line) === delimiter) break
      }
    }
    this.heredocs = []
    this.unquotedHeredoc = false
  }

  // Found while skipping, reported with the next command.
  pending: ShellNode[] = []

  private skipBlanks(): void {
    while (this.s[this.i] === " " || this.s[this.i] === "\t") this.i++
  }

  // One word, with what substitutions inside it run pushed to `nodes`.
  private word(nodes: ShellNode[]): Word {
    const s = this.s
    const word: Word = { text: "", dynamic: false, glob: false }
    const start = this.i
    while (this.i < s.length) {
      const c = s[this.i] as string
      if (OPERATOR_CHARS.includes(c)) break
      if (c === "\\") {
        if (s[this.i + 1] === "\n") this.i += 2
        else {
          word.text += s[this.i + 1] ?? ""
          this.i += 2
        }
        continue
      }
      if (c === "'") {
        const close = s.indexOf("'", this.i + 1)
        if (close === -1) {
          word.text += s.slice(this.i + 1)
          word.dynamic = true
          this.i = s.length
          break
        }
        word.text += s.slice(this.i + 1, close)
        this.i = close + 1
        continue
      }
      if (c === '"') {
        this.i++
        this.doubleQuoted(word, nodes)
        continue
      }
      if (c === "$") {
        this.dollar(word, nodes)
        continue
      }
      if (c === "`") {
        this.backtick(word, nodes)
        continue
      }
      if (c === "~" && this.i === start) {
        const name = /^~([A-Za-z0-9_.-]*)/.exec(s.slice(this.i))?.[1] ?? ""
        const after = s[this.i + 1 + name.length]
        if (after === undefined || after === "/" || OPERATOR_CHARS.includes(after)) {
          if (name === "") word.text += this.home
          else {
            word.text += `~${name}`
            word.dynamic = true
          }
          this.i += 1 + name.length
          continue
        }
      }
      if (c === "*" || c === "?" || c === "[") word.glob = true
      if (c === "{" && /^\{[^{}\s]*(,|\.\.)[^{}\s]*\}/.test(s.slice(this.i))) word.dynamic = true
      word.text += c
      this.i++
    }
    return word
  }

  private doubleQuoted(word: Word, nodes: ShellNode[]): void {
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
          word.text += next
          this.i += 2
        } else {
          word.text += c
          this.i++
        }
        continue
      }
      if (c === "$") {
        this.dollar(word, nodes)
        continue
      }
      if (c === "`") {
        this.backtick(word, nodes)
        continue
      }
      word.text += c
      this.i++
    }
    word.dynamic = true
  }

  private dollar(word: Word, nodes: ShellNode[]): void {
    const s = this.s
    const next = s[this.i + 1]
    if (next === "(") {
      if (s[this.i + 2] === "(") {
        const close = s.indexOf("))", this.i + 3)
        this.i = close === -1 ? s.length : close + 2
        word.dynamic = true
        return
      }
      this.i += 2
      nodes.push({ kind: "open", op: "start" }, ...this.list(")"), { kind: "close" })
      word.dynamic = true
      return
    }
    if (next === "{") {
      const close = s.indexOf("}", this.i + 2)
      const name = close === -1 ? "" : s.slice(this.i + 2, close)
      this.i = close === -1 ? s.length : close + 1
      if (name === "HOME") word.text += this.home
      else word.dynamic = true
      return
    }
    const name = /^[A-Za-z_][A-Za-z0-9_]*/.exec(s.slice(this.i + 1))?.[0]
    if (name) {
      this.i += 1 + name.length
      if (name === "HOME") word.text += this.home
      else word.dynamic = true
      return
    }
    if (next !== undefined && "@*#?$!-0123456789".includes(next)) {
      this.i += 2
      word.dynamic = true
      return
    }
    if (next === "'" || next === '"') {
      // $'...' and $"...": quoting the guard reads no further into.
      this.i++
      word.dynamic = true
      return
    }
    word.text += "$"
    this.i++
  }

  private backtick(word: Word, nodes: ShellNode[]): void {
    let close = this.i + 1
    while (close < this.s.length && this.s[close] !== "`") close += this.s[close] === "\\" ? 2 : 1
    const inner = this.s.slice(this.i + 1, close).replace(/\\([`$\\])/g, "$1")
    this.i = Math.min(close + 1, this.s.length)
    nodes.push({ kind: "open", op: "start" }, ...parseShell(inner, this.home), { kind: "close" })
    word.dynamic = true
  }

  // The nodes, with anything found while skipping here-documents.
  result(nodes: ShellNode[]): ShellNode[] {
    return [...nodes, ...this.pending]
  }
}

export function parseShell(command: string, home: string): ShellNode[] {
  const parser = new Parser(command, home)
  return parser.result(parser.parse())
}
