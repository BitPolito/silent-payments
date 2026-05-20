/**
 * @param {(k: string) => string} tr
 * @param {string} scenarioId
 */
export function edgeLegendItems(tr, scenarioId) {
  const items = []
  for (let i = 1; i <= 8; i++) {
    const key = `edgeLegend_${scenarioId}_${i}`
    const text = tr(key)
    if (text === key) break
    items.push(text)
  }
  return items
}

/**
 * @param {object | null | undefined} sendResult
 * @param {string} storyKind
 */
export function explainSendOutcome(sendResult, storyKind) {
  if (!sendResult) return { ok: null, isExpectedEmpty: false }
  const isExpectedEmpty =
    storyKind === 'no_send_outputs' ||
    storyKind === 'zero_key_sum' ||
    sendResult.note === 'zero key sum'
  const ok = !!sendResult.test_passed || (isExpectedEmpty && !sendResult.error)
  return { ok, isExpectedEmpty, note: sendResult.note }
}
