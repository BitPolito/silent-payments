// Seeded variation is for an educational puzzle, never for cryptographic keys.
export function investigation(seed) {
  let state = seed >>> 0 || 1
  const random = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) / 4294967296 }
  const owners = ['bob', 'bob', 'bob', 'other', 'other', 'other', 'other', 'other']
  for (let i = owners.length - 1; i > 0; i--) { const j = Math.floor(random() * (i + 1)); [owners[i], owners[j]] = [owners[j], owners[i]] }
  return owners.map((owner, id) => ({ id, owner, amount: [12000, 8000, 12000, 21000][Math.floor(random() * 4)], destination: `K${String(id + 1).padStart(2, '0')}` }))
}
export function publicOutputs(rows, mode) {
  return rows.map(({ id, owner, amount, destination }) => ({ id, amount, destination: mode === 'reuse' && owner === 'bob' ? 'BOB-A' : destination }))
}
export function evaluateGuess(rows, guesses) {
  const selected = new Set(guesses)
  return {
    correct: rows.filter((row) => row.owner === 'bob' && selected.has(row.id)).length,
    missed: rows.filter((row) => row.owner === 'bob' && !selected.has(row.id)).length,
    mistaken: rows.filter((row) => row.owner !== 'bob' && selected.has(row.id)).length,
  }
}
