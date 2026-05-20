/**
 * @param {Response} response
 */
export async function parseApiResponse(response) {
  const text = await response.text()
  const contentType = response.headers.get('content-type') || ''

  if (text.trim().startsWith('<') && !contentType.includes('application/json')) {
    const err = new Error('NOT_JSON')
    err.code = 'NOT_JSON'
    throw err
  }

  let data = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      const err = new Error('NOT_JSON')
      err.code = 'NOT_JSON'
      throw err
    }
  }

  if (!response.ok) {
    const raw = data?.error ?? data?.message ?? text ?? response.statusText
    const message = typeof raw === 'string' ? raw : JSON.stringify(raw)
    const err = new Error(message || 'API_ERROR')
    err.code = 'API_ERROR'
    throw err
  }

  return data ?? {}
}

/**
 * Map fetch/parse errors to a user-facing message (locale via `tr`).
 * @param {unknown} error
 * @param {(key: string) => string} tr
 */
export function formatApiError(error, tr) {
  if (!error) return tr('apiError')
  if (error instanceof Error && error.name === 'AbortError') return ''
  const code = /** @type {{ code?: string }} */ (error).code
  const message = error instanceof Error ? error.message : String(error)
  if (code === 'NETWORK' || message === 'NETWORK') {
    return import.meta.env.PROD ? tr('apiOfflineProd') : tr('apiOffline')
  }
  if (code === 'NOT_JSON' || message === 'NOT_JSON') {
    return import.meta.env.PROD ? tr('apiNotJsonProd') : tr('apiNotJson')
  }
  if (message && message !== 'API_ERROR') return message
  return tr('apiError')
}

/**
 * @param {string} url
 * @param {RequestInit} [init]
 */
export async function fetchApi(url, init) {
  let response
  try {
    response = await fetch(url, init)
  } catch (e) {
    if (e?.name === 'AbortError') throw e
    const err = new Error('NETWORK')
    err.code = 'NETWORK'
    throw err
  }
  return parseApiResponse(response)
}

/**
 * Random silent payment address (optional testnet).
 * @param {{ testnet?: boolean }} params
 * @param {RequestInit} [init]
 */
export async function fetchSpAddress({ testnet = false } = {}, init) {
  let response
  try {
    response = await fetch('/api/get_sp_address', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ testnet: !!testnet }),
      ...init,
    })
  } catch (e) {
    if (e?.name === 'AbortError') throw e
    const err = new Error('NETWORK')
    err.code = 'NETWORK'
    throw err
  }
  if (response.status === 405 || response.status === 404 || response.status === 501) {
    const q = testnet ? '?testnet=1' : ''
    return fetchApi(`/api/get_sp_address${q}`, { ...init, method: 'GET' })
  }
  return parseApiResponse(response)
}

/**
 * Vanity search — POST on current API; GET fallback for older backends without POST.
 * @param {{ pattern: string, mode: string, testnet: boolean }} params
 * @param {RequestInit} [init]
 */
export async function fetchVanityAddress(params, init) {
  const pattern = params.pattern.trim().toLowerCase()
  const mode = params.mode || 'contains'

  let response
  try {
    response = await fetch('/api/vanity_address', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pattern,
        mode,
        testnet: !!params.testnet,
      }),
      ...init,
    })
  } catch (e) {
    if (e?.name === 'AbortError') throw e
    const err = new Error('NETWORK')
    err.code = 'NETWORK'
    throw err
  }

  if (response.status === 404 || response.status === 405 || response.status === 501) {
    const enc = encodeURIComponent(pattern)
    const testnetNum = params.testnet ? 1 : 0
    return fetchApi(`/api/vanity_address/${enc}/${mode}/0/${testnetNum}/0`, {
      ...init,
      method: 'GET',
    })
  }

  return parseApiResponse(response)
}

/** Lightweight ping — does not generate keys. Tries several /api routes (all go through the Vite proxy in dev). */
export async function checkApiHealth(signal) {
  const probes = ['/api/health', '/api/test_case/0']
  /** @type {Error | undefined} */
  let lastError
  for (const url of probes) {
    try {
      return await fetchApi(url, { signal })
    } catch (e) {
      if (e?.name === 'AbortError') throw e
      if (e?.code === 'NETWORK') throw e
      lastError = e
    }
  }
  const err = new Error('NETWORK')
  err.code = 'NETWORK'
  throw lastError?.code === 'NETWORK' ? lastError : err
}
