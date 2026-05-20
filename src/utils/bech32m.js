/** BIP-352 silent payment addresses use the bech32m character set (32 symbols). */
export const BECH32M_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

/** Fallback when /api/health limits are not loaded yet (matches typical local API default). */
export const BECH32M_MAX_PATTERN_FALLBACK = 5

/** Default vanity pattern when opening the modal. */
export const DEFAULT_VANITY_PATTERN = 'caffe'

/** BIP-352 v0 fixed prefix (witness version 0 → `sp1qq…` / `tsp1qq…`). */
export const SP_VANITY_FIXED_MAINNET = 'sp1qq'
export const SP_VANITY_FIXED_TESTNET = 'tsp1qq'

/**
 * @param {boolean} [testnet]
 */
export function vanityFixedPrefix(testnet = false) {
  return testnet ? SP_VANITY_FIXED_TESTNET : SP_VANITY_FIXED_MAINNET
}

/**
 * Human-readable groupings — excludes b, i, o and digit 1 (not in bech32m).
 * Letters a→z, then digits 0–9 (only those present in the charset).
 */
export const BECH32M_LETTERS = 'acdefghijklmnpqrstuvwxyz'
export const BECH32M_DIGITS = '023456789'

const CHARSET_RE = /^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/

/**
 * @param {string} s
 */
export function isBech32m(s) {
  return s.length > 0 && CHARSET_RE.test(s.toLowerCase())
}

/**
 * Strip invalid characters, lowercase, cap length.
 * @param {string} raw
 * @param {number} [maxLen]
 */
export function parsePatternInput(raw, maxLen = BECH32M_MAX_PATTERN_FALLBACK) {
  const lower = raw.toLowerCase()
  /** @type {string[]} */
  const removed = []
  let out = ''
  for (const ch of lower) {
    if (BECH32M_CHARSET.includes(ch)) out += ch
    else if (ch.trim() && !removed.includes(ch)) removed.push(ch)
  }
  const truncated = out.length > maxLen
  if (truncated) out = out.slice(0, maxLen)
  return { value: out, removed, truncated }
}

/**
 * @param {string} value normalized pattern
 * @param {(k: string) => string} tr
 * @param {number} [maxLen]
 */
export function patternValidationError(value, tr, maxLen = BECH32M_MAX_PATTERN_FALLBACK) {
  if (!value) return ''
  if (value.length > maxLen) return tr('patternLong').replace('{n}', String(maxLen))
  if (!isBech32m(value)) return tr('invalidPattern')
  return ''
}

/**
 * Characters in `word` that are not allowed (for explanatory messages).
 * @param {string} word
 */
export function invalidCharsInWord(word) {
  const bad = new Set()
  for (const ch of word.toLowerCase()) {
    if (ch.trim() && !BECH32M_CHARSET.includes(ch)) bad.add(ch)
  }
  return [...bad]
}

/**
 * Pattern used for vanity search (empty input → default, capped by server limit).
 * @param {string} pattern
 * @param {number} maxLen
 */
export function effectiveVanityPattern(pattern, maxLen = BECH32M_MAX_PATTERN_FALLBACK) {
  const raw = pattern.trim() || DEFAULT_VANITY_PATTERN
  return raw.slice(0, maxLen)
}

/**
 * Illustrative preview for "contains" search: fixed prefix … pattern … (pattern is not necessarily adjacent).
 * @param {boolean} testnet
 * @param {string} pattern raw user pattern (may be empty → default)
 * @param {number} maxLen
 */
export function vanityContainsPreview(testnet, pattern, maxLen = BECH32M_MAX_PATTERN_FALLBACK) {
  const prefix = vanityFixedPrefix(testnet)
  const raw = (pattern?.trim() ? pattern : DEFAULT_VANITY_PATTERN).toLowerCase()
  const seg = raw.slice(0, maxLen)
  return `${prefix}…${seg}…`
}

/** Index where the user-chosen vanity pattern may appear. */
export function vanitySearchStart(address, testnet = false) {
  if (!address) return 0
  const lower = address.toLowerCase()
  const fixed = vanityFixedPrefix(testnet)
  if (lower.startsWith(fixed)) return fixed.length
  const short = testnet ? 'tsp1q' : 'sp1q'
  if (lower.startsWith(short)) return short.length
  const sep = lower.indexOf('1')
  return sep !== -1 ? sep + 2 : 0
}

/**
 * Character range of `pattern` inside a bech32m address (for UI highlight).
 * @param {string} address
 * @param {string} pattern
 * @param {'contains' | 'prefix' | 'suffix'} [mode]
 * @param {boolean} [testnet]
 * @returns {{ start: number, end: number } | null}
 */
export function vanityPatternRange(address, pattern, mode = 'contains', testnet = false) {
  if (!address || !pattern) return null
  const addr = address.toLowerCase()
  const pat = pattern.toLowerCase()
  const searchStart = vanitySearchStart(address, testnet)

  if (mode === 'suffix' && addr.endsWith(pat)) {
    return { start: address.length - pat.length, end: address.length }
  }

  const slice = addr.slice(searchStart)

  if (mode === 'prefix') {
    if (slice.startsWith(pat)) {
      return { start: searchStart, end: searchStart + pat.length }
    }
    return null
  }

  const rel = slice.indexOf(pat)
  if (rel === -1) return null
  return { start: searchStart + rel, end: searchStart + rel + pat.length }
}
