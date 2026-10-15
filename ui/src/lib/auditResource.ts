// Fingerprints and generated IDs are unreadable in full; the audit detail pane
// and the cell tooltip keep the complete value.
export function shortResourceId(id: string): string {
  return id.length > 16 ? `${id.slice(0, 12)}…` : id;
}
