/** @typedef {'a'} FxPresetId */

/** @type {Record<FxPresetId, {
 *   sources: string[]
 *   sizeMin: number
 *   sizeRange: number
 *   giantChance: number
 *   giantScale: number
 *   invertOnDark: boolean
 *   tintLight: string
 *   tintDark: string
 * }>} */
export const FX_PRESETS = {
  a: {
    sources: ['/bitpolito/icon-cow-1.svg', '/bitpolito/icon-cow-2.svg'],
    sizeMin: 64,
    sizeRange: 48,
    giantChance: 0.06,
    giantScale: 1.35,
    invertOnDark: true,
    tintLight: 'rgba(0, 28, 224, 0.06)',
    tintDark: 'rgba(0, 8, 80, 0.3)',
  },
}

const PRELOAD_URLS = [...new Set(Object.values(FX_PRESETS).flatMap((p) => p.sources))]

let preloaded = false

export function preloadFxAssets() {
  if (preloaded || typeof window === 'undefined') return
  preloaded = true
  for (const src of PRELOAD_URLS) {
    const img = new Image()
    img.decoding = 'async'
    img.src = src
  }
}
