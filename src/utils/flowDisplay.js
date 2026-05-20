/**
 * @param {string} addr
 * @returns {{ prefix: string, kind: 'silent' | 'other' }}
 */
export function silentAddressKind(addr) {
  if (typeof addr !== 'string') return { prefix: '', kind: 'other' }
  if (addr.startsWith('tsp1')) return { prefix: 'tsp1', kind: 'silent' }
  if (addr.startsWith('sp1')) return { prefix: 'sp1', kind: 'silent' }
  if (addr.startsWith('bc1') || addr.startsWith('tb1')) return { prefix: addr.slice(0, 3), kind: 'other' }
  return { prefix: '', kind: 'other' }
}

/**
 * @param {string} hex
 */
export function scriptTypeLabel(hex) {
  if (!hex) return ''
  const h = hex.toLowerCase()
  if (h.startsWith('76a914') && h.endsWith('88ac') && h.length === 50) return 'P2PKH'
  if (h.startsWith('5120') && h.length === 44) return 'P2TR'
  if (h.startsWith('0014') && h.length === 44) return 'P2WPKH'
  if (h.startsWith('a914') && h.endsWith('87')) return 'P2SH'
  return 'script'
}

/**
 * @param {string} txid
 */
export function formatTxidShort(txid) {
  if (!txid || txid.length < 16) return txid || '—'
  return `${txid.slice(0, 8)}…${txid.slice(-8)}`
}

/**
 * @param {object | null | undefined} sendResult
 * @param {string} storyKind
 */
export function isSendStepComplete(sendResult, storyKind) {
  if (!sendResult) return false
  if (sendResult.test_passed) return true
  if (storyKind === 'no_send_outputs' && Array.isArray(sendResult.outputs) && sendResult.outputs.length === 0) {
    return !sendResult.error
  }
  return false
}

/**
 * @param {object | null | undefined} sendResult
 * @param {string} storyKind
 */
export function canRunReceiveCheck(sendResult, storyKind) {
  if (!sendResult) return false
  return isSendStepComplete(sendResult, storyKind)
}
