import { useEffect, useState } from 'react'
import { checkApiHealth } from '../utils/api'

/**
 * @param {boolean} enabled
 */
export function useApiOnline(enabled) {
  const [status, setStatus] = useState(/** @type {'idle' | 'checking' | 'online' | 'offline'} */ ('idle'))

  useEffect(() => {
    if (!enabled) {
      setStatus('idle')
      return
    }
    let cancelled = false
    const ac = new AbortController()

    const probe = () => {
      setStatus('checking')
      checkApiHealth(ac.signal)
        .then(() => {
          if (!cancelled) setStatus('online')
        })
        .catch(() => {
          if (!cancelled) setStatus('offline')
        })
    }

    probe()
    const retry = window.setTimeout(() => {
      if (!cancelled) probe()
    }, 1500)

    return () => {
      cancelled = true
      ac.abort()
      window.clearTimeout(retry)
    }
  }, [enabled])

  return status
}
