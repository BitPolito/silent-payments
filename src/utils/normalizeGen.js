/**
 * Normalize generate / vanity API payloads for the UI.
 * @param {unknown} data
 */
export function normalizeGenResponse(data) {
  if (!data || typeof data !== 'object') return null

  const raw = /** @type {Record<string, unknown>} */ (data)
  let addresses = raw.addresses
  if (typeof addresses === 'string') addresses = [addresses]
  if (!Array.isArray(addresses) || !addresses[0]) return null

  const addr = String(addresses[0])
  const km = raw.key_material
  /** @type {{ scan_priv_key?: string, spend_priv_key?: string } | null} */
  let keyMaterial = null
  if (km && typeof km === 'object') {
    const k = /** @type {Record<string, unknown>} */ (km)
    keyMaterial = {
      scan_priv_key: k.scan_priv_key != null ? String(k.scan_priv_key) : undefined,
      spend_priv_key: k.spend_priv_key != null ? String(k.spend_priv_key) : undefined,
    }
  }

  const network =
    raw.network === 'testnet' || raw.network === 'mainnet'
      ? raw.network
      : addr.toLowerCase().startsWith('tsp1')
        ? 'testnet'
        : 'mainnet'

  const validKey = (key) => typeof key === 'string' && /^[0-9a-f]{64}$/.test(key) &&
    BigInt(`0x${key}`) > 0n && BigInt(`0x${key}`) < 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
  if (!keyMaterial || !validKey(keyMaterial.scan_priv_key) || !validKey(keyMaterial.spend_priv_key)) return null
  if (network === 'testnet' ? !/^tsp1qq[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{111}$/.test(addr) : !/^sp1qq[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{111}$/.test(addr)) return null

  return {
    ...raw,
    addresses: [addr],
    key_material: keyMaterial,
    elapsed: raw.elapsed,
    network,
    qr_png_base64: raw.qr_png_base64 ? String(raw.qr_png_base64) : undefined,
    message: raw.message,
  }
}

/**
 * @param {string} address
 */
export function qrImageUrl(address) {
  return `/api/qr_code?address=${encodeURIComponent(address)}`
}
