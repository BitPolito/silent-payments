export const STRATEGIES = ['reuse', 'fresh', 'silent']
export const MAX_PAYMENTS = 6
const amounts = [12000, 8000, 21000, 5000, 34000, 13000]

// Deliberately symbolic: this model explains equality, never derives Bitcoin keys.
export function paymentModel(strategy, count, selected = 0) {
  const mode = STRATEGIES.includes(strategy) ? strategy : 'reuse'
  const size = Math.max(1, Math.min(MAX_PAYMENTS, Math.floor(count) || 1))
  const rows = amounts.slice(0, size).map((amount, index) => ({
    id: index, amount, destination: mode === 'reuse' ? 'A' : `${mode === 'silent' ? 'P' : 'A'}${index + 1}`,
  }))
  const destination = rows[selected]?.destination ?? rows[0].destination
  return { rows, unique: new Set(rows.map((row) => row.destination)).size, matching: rows.filter((row) => row.destination === destination).map((row) => row.id) }
}
