import { useEffect, useState } from 'react'
import { fetchApi } from '../utils/api'
import { BECH32M_MAX_PATTERN_FALLBACK } from '../utils/bech32m'

const PROD_DEFAULTS = {
  maxPattern: 5,
  environment: 'vercel',
  timeoutSec: 55,
}

/** Until /api/health loads, assume local defaults (avoid flashing a tiny cap in dev). */
const DEV_DEFAULTS = {
  maxPattern: BECH32M_MAX_PATTERN_FALLBACK,
  environment: 'local',
  timeoutSec: 600,
}

/** @param {Record<string, unknown>} data */
function limitsFromHealth(data) {
  const fallback = import.meta.env.PROD ? PROD_DEFAULTS : DEV_DEFAULTS
  return {
    maxPattern: Number(data.vanity_max_pattern) || fallback.maxPattern,
    environment: String(data.vanity_environment || fallback.environment),
    timeoutSec: Number(data.vanity_timeout_sec) || fallback.timeoutSec,
  }
}

/** Loads server-side vanity limits (Vercel vs local) from /api/health. */
export function useVanityLimits(open) {
  const [limits, setLimits] = useState(() => (import.meta.env.PROD ? PROD_DEFAULTS : DEV_DEFAULTS))

  useEffect(() => {
    if (!open) return
    const ac = new AbortController()
    fetchApi('/api/health', { signal: ac.signal })
      .then((data) => setLimits(limitsFromHealth(data)))
      .catch(() => setLimits(import.meta.env.PROD ? PROD_DEFAULTS : DEV_DEFAULTS))
    return () => ac.abort()
  }, [open])

  const isLocalApi = limits.environment === 'local'

  return { ...limits, isLocalApi }
}
