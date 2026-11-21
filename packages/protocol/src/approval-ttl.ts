// How long the vault keeps an approval pending: an identical ask reuses an
// open one only until then. The vault sets every approval's expiry from it,
// and mehen's replay cache bounds how long a held request can be saved by
// it, so both import it from here.
export const APPROVAL_TTL_MS = 3_600_000
