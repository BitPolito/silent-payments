import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchApi } from '../../utils/api'
export function useExperiment(tool) {
  const controller = useRef(null)
  const requestId = useRef(0)
  const [state, setState] = useState({ data: null, error: '', busy: false })
  const [metadata, setMetadata] = useState(null)
  const cancel = useCallback(() => { requestId.current++; controller.current?.abort() }, [])
  useEffect(() => {
    const abort = new AbortController()
    fetchApi('/api/experiments', { signal: abort.signal }).then((data) => { if (!abort.signal.aborted) setMetadata(data) }).catch(() => {})
    return () => { abort.abort(); cancel() }
  }, [cancel])
  function clear() { cancel(); setState({ data: null, error: '', busy: false }) }
  async function run(payload) {
    controller.current?.abort()
    const id = ++requestId.current
    const abort = new AbortController()
    controller.current = abort
    setState({ data: null, error: '', busy: true })
    try {
      const data = await fetchApi(`/api/experiments/${tool}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: abort.signal })
      if (!abort.signal.aborted && id === requestId.current) setState({ data, error: '', busy: false })
    } catch (error) {
      if (!abort.signal.aborted && id === requestId.current) setState({ data: null, error: error.code || 'NETWORK', busy: false })
    }
  }
  return { ...state, metadata, run, clear }
}
