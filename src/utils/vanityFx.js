/** @typedef {import('../fx/presets').FxPresetId} FxPresetId */

/** @param {string} pattern @returns {FxPresetId | null} */
export function resolveVanityFx(pattern) {
  if (pattern.trim().toLowerCase() === 'mucca') return 'a'
  return null
}
