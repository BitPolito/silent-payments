/** Output ordering is not significant; every duplicate still consumes one match. */
export function compareMultiset(expected, actual, key = (value) => value) {
  const available = new Map()
  actual.forEach((value, index) => {
    const identity = key(value)
    if (!available.has(identity)) available.set(identity, [])
    available.get(identity).push({ value, index })
  })
  const used = new Set()
  const rows = expected.map((value) => {
    const match = available.get(key(value))?.shift()
    if (match) used.add(match.index)
    return { expected: value, actual: match?.value, status: match ? 'matched' : 'missing' }
  })
  actual.forEach((value, index) => {
    if (!used.has(index)) rows.push({ actual: value, status: 'unexpected' })
  })
  return rows
}

export function compareReferenceResult(result, direction) {
  const actual = result.outputs || []
  if (direction === 'send') {
    const supplied = result.expected_outputs || []
    const alternatives = Array.isArray(supplied[0]) ? supplied : [supplied]
    const comparisons = alternatives.map((expected, index) => ({ expected, index, rows: compareMultiset(expected, actual) }))
    // A full match wins; otherwise explain the closest permitted alternative.
    const selected = comparisons.reduce((best, next) =>
      next.rows.filter((row) => row.status !== 'matched').length < best.rows.filter((row) => row.status !== 'matched').length ? next : best)
    return { ...selected, actual, alternatives: alternatives.length, addresses: [] }
  }
  const expected = result.expected_outputs || []
  const expectedAddresses = result.expected_addresses || []
  const actualAddresses = result.addresses || []
  return {
    expected, actual, alternatives: 1, index: 0,
    rows: compareMultiset(expected, actual, (output) => JSON.stringify([output.pub_key, output.priv_key_tweak])),
    addresses: Array.from({ length: Math.max(expectedAddresses.length, actualAddresses.length) }, (_, index) => ({
      expected: expectedAddresses[index], actual: actualAddresses[index],
      status: expectedAddresses[index] === actualAddresses[index] ? 'matched' : expectedAddresses[index] === undefined ? 'unexpected' : actualAddresses[index] === undefined ? 'missing' : 'different',
    })),
  }
}
