/** @type {Record<FxPresetId, { sources: string[] }>} */
export const FX_PRESETS = {
  a: { sources: ['/bitpolito/icon-cow-1.svg', '/bitpolito/icon-cow-2.svg'] },
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
