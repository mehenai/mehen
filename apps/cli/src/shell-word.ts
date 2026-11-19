// One argument as a POSIX shell reads it back: plain when it is safe,
// otherwise in single quotes.
export function shellWord(arg: string): string {
  return /^[A-Za-z0-9_./:@,=+%-]+$/.test(arg) ? arg : `'${arg.replaceAll("'", "'\\''")}'`
}
