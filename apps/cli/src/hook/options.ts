// The options of each program the guard reads, as an allowlist: whether an
// option takes a value, and whether that value is a file the program reads.
// An option not listed is outside the grammar; since these programs read
// files, a line that uses one is refused. Taken from each program's GNU
// manual (coreutils, grep, sed, gawk, diffutils, binutils) and jq's, and
// checked against the BSD and macOS manuals: an option that takes a value
// on one and none on the other (sed -l) is left out, so it refuses.

import { type Word, literal } from "./shell.ts"

// flag: no value. value: a value that is not a file. file: a file it
// reads. optional: a value only when attached (-i.bak, --color=auto).
// program/programFile: the program's script, so the first operand is not
// one (grep -e, sed -f). value2/file2: two values, the second a file
// (jq --rawfile name file). rest: later operands are arguments, not files.
export type Arity = "flag" | "value" | "file" | "optional" | "program" | "programFile" | "value2" | "file2" | "rest"

export type OptionSpec = {
  short: Record<string, Arity>
  long: Record<string, Arity>
  // -NUM, as head, tail and diff take it. A +NUM word is a file operand
  // (tail and uniq once took it as an option, and still may, but it names a
  // file to every one of them when one exists).
  digits?: boolean
  // What the operands are: files read; a program, then files; nothing
  // read; files read except the last, which is written (cp).
  operands: "files" | "program-then-files" | "none" | "sources"
}

export type ParsedOptions = { operands: Word[]; files: Word[]; unknown: string | null; programGiven: boolean; target: boolean }

// A record's own entry for a key the command line chose: never one it
// inherits from Object.prototype (`--constructor`, `toString`).
export function own<T>(record: Record<string, T>, key: string): T | undefined {
  return Object.hasOwn(record, key) ? record[key] : undefined
}

function arities(letters: string, arity: Arity): Record<string, Arity> {
  return Object.fromEntries([...letters].map((c) => [c, arity]))
}

function names(list: string, arity: Arity): Record<string, Arity> {
  return Object.fromEntries(list.split(" ").filter(Boolean).map((n) => [n, arity]))
}

const COMMON_LONG = names("help version", "flag")

function spec(short: Record<string, Arity>, long: Record<string, Arity>, operands: OptionSpec["operands"], digits = false): OptionSpec {
  return { short, long: { ...COMMON_LONG, ...long }, operands, digits }
}

const GREP = spec(
  { ...arities("EFGPiyvwxcLloqsbHhnTZzaIrRU", "flag"), ...arities("mABCdD", "value"), e: "program", f: "programFile" },
  {
    ...names("extended-regexp fixed-strings basic-regexp perl-regexp ignore-case no-ignore-case invert-match word-regexp line-regexp count files-without-match files-with-matches only-matching quiet silent no-messages byte-offset with-filename no-filename line-number initial-tab null null-data text recursive dereference-recursive line-buffered no-group-separator binary", "flag"),
    ...names("max-count after-context before-context context directories devices exclude include exclude-dir label binary-files group-separator", "value"),
    ...names("color colour", "optional"),
    regexp: "program",
    file: "programFile",
    "exclude-from": "file",
  },
  "program-then-files",
  true,
)

export const OPTION_SPECS: Record<string, OptionSpec> = {
  cat: spec(arities("AbeEnstTuv", "flag"), names("show-all number-nonblank show-ends number squeeze-blank show-tabs show-nonprinting", "flag"), "files"),
  head: spec({ ...arities("qvz", "flag"), ...arities("cn", "value") }, { ...names("quiet silent verbose zero-terminated", "flag"), ...names("bytes lines", "value") }, "files", true),
  tail: spec({ ...arities("fFqvz", "flag"), ...arities("cns", "value") }, { ...names("retry quiet silent verbose zero-terminated", "flag"), ...names("bytes lines pid sleep-interval max-unchanged-stats", "value"), follow: "optional" }, "files", true),
  grep: GREP,
  egrep: GREP,
  fgrep: GREP,
  sort: spec(
    { ...arities("bdfgiMhnRrVcCmsuz", "flag"), ...arities("kStTo", "value") },
    {
      ...names("ignore-leading-blanks dictionary-order ignore-case general-numeric-sort ignore-nonprinting month-sort human-numeric-sort numeric-sort random-sort reverse version-sort merge stable unique zero-terminated debug", "flag"),
      check: "optional",
      ...names("key field-separator output buffer-size temporary-directory parallel sort batch-size compress-program", "value"),
      ...names("files0-from random-source", "file"),
    },
    "files",
  ),
  uniq: spec({ ...arities("cdDiuz", "flag"), ...arities("fsw", "value") }, { ...names("count repeated ignore-case unique zero-terminated", "flag"), ...names("all-repeated group", "optional"), ...names("skip-fields skip-chars check-chars", "value") }, "files", true),
  cut: spec({ ...arities("nsz", "flag"), ...arities("bcdf", "value") }, { ...names("complement only-delimited zero-terminated", "flag"), ...names("bytes characters delimiter fields output-delimiter", "value") }, "files"),
  diff: spec(
    { ...arities("abBdeEfilnNpqrstTuvwyZH", "flag"), ...arities("CUDIFxWS", "value"), X: "file" },
    {
      ...names("normal brief report-identical-files ed rcs side-by-side left-column suppress-common-lines show-c-function expand-tabs initial-tab suppress-blank-empty new-file unidirectional-new-file ignore-case ignore-tab-expansion ignore-trailing-space ignore-space-change ignore-all-space ignore-blank-lines text strip-trailing-cr recursive minimal speed-large-files no-dereference", "flag"),
      ...names("context unified color", "optional"),
      ...names("width show-function-line label tabsize line-format old-line-format new-line-format unchanged-line-format old-group-format new-group-format changed-group-format unchanged-group-format ignore-matching-lines starting-file exclude palette horizon-lines ifdef", "value"),
      ...names("exclude-from from-file to-file", "file"),
    },
    "files",
    true,
  ),
  cmp: spec({ ...arities("bls", "flag"), ...arities("in", "value") }, { ...names("print-bytes verbose quiet silent", "flag"), ...names("ignore-initial bytes", "value") }, "files"),
  od: spec({ ...arities("bcdfilosxv", "flag"), ...arities("AjNSt", "value"), w: "optional" }, { ...names("output-duplicates traditional", "flag"), ...names("strings width", "optional"), ...names("address-radix skip-bytes read-bytes format endian", "value") }, "files"),
  hexdump: spec({ ...arities("bcCdovx", "flag"), ...arities("ens", "value"), f: "file", L: "optional" }, { ...names("one-byte-octal one-byte-char canonical two-bytes-decimal two-bytes-octal two-bytes-hex no-squeezing", "flag"), color: "optional", ...names("format length skip", "value"), "format-file": "file" }, "files"),
  base64: spec({ ...arities("di", "flag"), w: "value" }, { ...names("decode ignore-garbage", "flag"), wrap: "value" }, "files"),
  strings: spec({ ...arities("adfow", "flag"), ...arities("ntTesU", "value") }, { ...names("all data print-file-name include-all-whitespace", "flag"), ...names("bytes radix target encoding output-separator unicode", "value") }, "files", true),
  tr: spec(arities("cCdst", "flag"), names("complement delete squeeze-repeats truncate-set1", "flag"), "none"),
  cp: spec(
    { ...arities("abdfHilLnPpRrsTuvxZ", "flag"), t: "value" },
    {
      ...names("archive attributes-only copy-contents dereference force interactive link no-clobber no-dereference parents recursive remove-destination strip-trailing-slashes symbolic-link no-target-directory verbose one-file-system", "flag"),
      ...names("backup preserve reflink update context", "optional"),
      ...names("no-preserve sparse suffix target-directory", "value"),
    },
    "sources",
  ),
  sed: spec(
    { ...arities("nrEsuz", "flag"), i: "optional", e: "program", f: "programFile" },
    { ...names("null-data zero-terminated quiet silent posix regexp-extended separate sandbox unbuffered debug follow-symlinks", "flag"), "in-place": "optional", "line-length": "value", expression: "program", file: "programFile" },
    "program-then-files",
  ),
  awk: spec({ ...arities("vF", "value"), f: "programFile", e: "program" }, { ...names("assign field-separator", "value"), file: "programFile", source: "program" }, "program-then-files"),
  jq: spec(
    { ...arities("nrjascCMSeRhV", "flag"), L: "value", f: "programFile" },
    {
      ...names("tab seq stream stream-errors raw-output join-output ascii-output slurp compact-output color-output monochrome-output sort-keys exit-status null-input raw-input raw-output0 unbuffered", "flag"),
      indent: "value",
      ...names("arg argjson", "value2"),
      ...names("slurpfile rawfile", "file2"),
      "from-file": "programFile",
      ...names("args jsonargs", "rest"),
    },
    "program-then-files",
  ),
}

function valueAt(args: Word[], i: number, word: Word, attached: string): [Word | undefined, number] {
  return attached ? [literal(attached, word.dynamic), i] : [args[i + 1], i + 1]
}

// Splits a program's words into options and operands by its spec. GNU
// programs take options after operands too, so every word is looked at
// until `--`. A word only the shell knows is an operand.
export function parseOptions(spec: OptionSpec, args: Word[]): ParsedOptions {
  const out: ParsedOptions = { operands: [], files: [], unknown: null, programGiven: false, target: false }
  let ended = false
  let rest = false
  const take = (arity: Arity, name: string, value: Word | undefined) => {
    if (arity === "file" || arity === "programFile") if (value) out.files.push(value)
    if (arity === "program" || arity === "programFile") out.programGiven = true
    if (name === "t" || name === "target-directory") out.target = true
  }
  for (let i = 0; i < args.length; i++) {
    const word = args[i] as Word
    const text = word.text
    if (ended || rest || word.dynamic || word.process || text === "-" || !text.startsWith("-")) {
      out.operands.push(word)
      continue
    }
    if (text === "--") {
      ended = true
      continue
    }
    if (spec.digits && /^-\d+$/.test(text)) continue
    if (text.startsWith("--")) {
      const eq = text.indexOf("=")
      const name = text.slice(2, eq === -1 ? undefined : eq)
      const arity = own(spec.long, name)
      if (arity === undefined) {
        out.unknown ??= `--${name}`
        continue
      }
      if (arity === "flag" || arity === "optional") continue
      if (arity === "rest") {
        rest = true
        continue
      }
      let value: Word | undefined
      if (eq !== -1) value = literal(text.slice(eq + 1), word.dynamic)
      else value = args[++i]
      if (arity === "value2" || arity === "file2") {
        const second = args[++i]
        if (arity === "file2" && second) out.files.push(second)
        continue
      }
      take(arity, name, value)
      continue
    }
    for (let j = 1; j < text.length; j++) {
      const flag = text[j] as string
      const arity = own(spec.short, flag)
      if (arity === undefined) {
        out.unknown ??= `-${flag}`
        break
      }
      if (arity === "flag") continue
      if (arity === "optional") break
      const [value, next] = valueAt(args, i, word, text.slice(j + 1))
      i = next
      take(arity, flag, value)
      break
    }
  }
  return out
}
