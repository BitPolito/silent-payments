/**
 * Quick check for formatApiError mapping (run: node scripts/verify-formatApiError.mjs)
 */
import assert from 'node:assert/strict'

function tr(key) {
  const en = {
    apiError: 'Request failed',
    apiOffline: 'API offline (dev)',
    apiOfflineProd: 'API offline (prod)',
    apiNotJson: 'Not JSON (dev)',
    apiNotJsonProd: 'Not JSON (prod)',
  }
  return en[key] ?? key
}

function formatApiError(error, tr, prod = false) {
  if (!error) return tr('apiError')
  if (error instanceof Error && error.name === 'AbortError') return ''
  const code = error.code
  const message = error instanceof Error ? error.message : String(error)
  if (code === 'NETWORK' || message === 'NETWORK') {
    return prod ? tr('apiOfflineProd') : tr('apiOffline')
  }
  if (code === 'NOT_JSON' || message === 'NOT_JSON') {
    return prod ? tr('apiNotJsonProd') : tr('apiNotJson')
  }
  if (message && message !== 'API_ERROR') return message
  return tr('apiError')
}

assert.equal(formatApiError({ code: 'NETWORK', message: 'NETWORK' }, tr, false), 'API offline (dev)')
assert.equal(formatApiError({ code: 'NETWORK', message: 'NETWORK' }, tr, true), 'API offline (prod)')
assert.equal(formatApiError({ code: 'NOT_JSON', message: 'NOT_JSON' }, tr, true), 'Not JSON (prod)')
assert.equal(formatApiError(new Error('Pattern is required'), tr), 'Pattern is required')
assert.equal(formatApiError(Object.assign(new Error('x'), { name: 'AbortError' }), tr), '')
console.log('formatApiError: all assertions passed')
