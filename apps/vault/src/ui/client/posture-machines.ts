// The How careful card's On these machines rows, with no DOM and no
// imports, so the server (posture-card.ts) and the browser
// (client/pages/posture.ts) draw them by one rule. A row is drawn for a
// level when that level would cover its machine now (the vault's eligible
// levels), or when the stored posture names it, then with a note that it
// is not covered.
export function postureRowShown(row: { levels: readonly string[]; stored: boolean }, level: "routine" | "trust"): { shown: boolean; uncovered: boolean } {
  const covered = row.levels.includes(level)
  return { shown: covered || row.stored, uncovered: row.stored && !covered }
}
