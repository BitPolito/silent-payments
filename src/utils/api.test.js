import { describe, it, expect, vi } from 'vitest'
import { parseApiResponse, formatApiError, fetchSpAddress } from './api'
const tr = (key) => key

describe('actual API utilities', () => {
  it('maps network, JSON, cancellation and server errors', () => {
    expect(formatApiError(Object.assign(new Error('NETWORK'), { code: 'NETWORK' }), tr)).toBe('apiOffline')
    expect(formatApiError(Object.assign(new Error('NOT_JSON'), { code: 'NOT_JSON' }), tr)).toBe('apiNotJson')
    expect(formatApiError(Object.assign(new Error(), { name: 'AbortError' }), tr)).toBe('')
    expect(formatApiError(new Error('Pattern is required'), tr)).toBe('Pattern is required')
  })
  it('parses JSON and rejects HTML and structured failures', async () => {
    await expect(parseApiResponse(new Response('{"ok":true}'))).resolves.toEqual({ ok: true })
    await expect(parseApiResponse(new Response('<html/>'))).rejects.toMatchObject({ code: 'NOT_JSON' })
    await expect(parseApiResponse(new Response('{"error":"Timed out","code":"SEARCH_TIMEOUT"}', {status:504}))).rejects.toMatchObject({code:'SEARCH_TIMEOUT'})
  })
  it('supports legacy generation fallback', async () => {
    const mock = vi.fn().mockResolvedValueOnce(new Response('', {status:405})).mockResolvedValueOnce(new Response('{"addresses":["example"]}'))
    vi.stubGlobal('fetch',mock)
    await fetchSpAddress({testnet:true})
    expect(mock.mock.calls[1][0]).toBe('/api/get_sp_address?testnet=1')
    vi.unstubAllGlobals()
  })
})
