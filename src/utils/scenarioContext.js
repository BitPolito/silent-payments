/**
 * @param {string} kind
 * @param {string} phase
 */
export function shouldShowVectorAside(kind, phase) {
  if (!kind || kind === 'linked') return false
  const phasesByKind = {
    extra_tx_outputs: ['bridge', 'receive'],
    no_send_outputs: ['send', 'bridge'],
    zero_key_sum: ['send', 'bridge'],
    decoupled: ['bridge', 'receive'],
    receive_only: [],
    send_only: ['send'],
    empty: ['overview'],
  }
  return (phasesByKind[kind] || []).includes(phase)
}

/**
 * @param {object | undefined} caseData
 */
export function getScenarioContext(caseData) {
  const sending = caseData?.sending
  const receiving = caseData?.receiving
  const story = caseData?.story || {}

  const silentOutputs = story.send_outputs || []
  const txOutputs = story.receive_tx_outputs || receiving?.outputs || []
  const extraOutputs =
    story.kind === 'extra_tx_outputs'
      ? txOutputs.filter((o) => !silentOutputs.includes(o))
      : []

  const aliceInputs = sending?.vin || []
  const senderKeyInputs = aliceInputs.filter((v) => v.has_sender_key).length

  const bobShareAddresses = sending?.recipients?.length ? sending.recipients : []
  const bobReceiveOnChain = silentOutputs.length ? silentOutputs : []

  return {
    bobAddresses: bobShareAddresses,
    bobShareAddresses,
    bobReceiveOnChain,
    aliceInputs,
    aliceSenderKeyCount: senderKeyInputs,
    bobScanKey: receiving?.scan_priv_key || '',
    bobSpendKey: receiving?.spend_priv_key || '',
    silentOutputs,
    txOutputs,
    extraOutputs,
    storyKind: story.kind || 'linked',
    hasSending: !!sending,
    hasReceiving: !!receiving,
    inputCount: aliceInputs.length,
    silentCount: silentOutputs.length,
    txOutputCount: txOutputs.length,
    extraCount: extraOutputs.length,
    vectorTitle: caseData?.title || '',
  }
}

/**
 * @param {string[]} liveOutputs
 * @param {string[]} fallback
 */
export function resolveAliceOutputs(liveOutputs, fallback) {
  if (liveOutputs?.length) return liveOutputs
  return fallback || []
}

/**
 * @param {(k: string) => string} tr
 * @param {string} key
 * @param {number} n
 */
export function trCount(tr, key, n) {
  return tr(key).replace('{n}', String(n))
}
