import { useEffect, useRef, useState } from 'react'
import { useLocale } from '../i18n/useLocale'
import { fetchApi, formatApiError } from '../utils/api'
import DemoRunResults from '../components/protocol/DemoRunResults'

export default function ReferenceCases() {
  const { tr } = useLocale()
  const [cases, setCases] = useState([])
  const [id, setId] = useState(0)
  const [direction, setDirection] = useState('send')
  const [subcase, setSubcase] = useState(0)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const abort = useRef(null)
  useEffect(() => {
    const controller = new AbortController()
    fetchApi('/api/reference_cases', { signal: controller.signal })
      .then((data) => { if (!controller.signal.aborted) setCases(data) })
      .catch((e) => { if (!controller.signal.aborted) setError(e.message) })
    return () => { controller.abort(); abort.current?.abort() }
  }, [])
  const reset = () => { abort.current?.abort(); setBusy(false); setResult(null); setError('') }
  const run = async () => {
    reset()
    const controller = new AbortController()
    abort.current = controller
    setBusy(true)
    try {
      const data = await fetchApi(`/api/single_test/${direction}/${id}?case_index=${subcase}`, { signal: controller.signal })
      if (!controller.signal.aborted) setResult(data)
    } catch (e) {
      if (!controller.signal.aborted) setError(formatApiError(e, tr))
    } finally { if (!controller.signal.aborted) setBusy(false) }
  }
  const count = cases.find((c) => c.id === id)?.case_counts[direction === 'send' ? 'sending' : 'receiving'] ?? 0
  return <section className="space-y-3">
    <p className="text-xs">{tr('referenceIntro')}</p>
    <label className="block text-sm">{tr('referenceCase')}
      <select aria-label={tr('referenceCase')} className="mt-1 w-full rounded border p-2 text-bp-blue" value={id} onChange={(e) => { reset(); setId(Number(e.target.value)); setSubcase(0) }}>
        {cases.map((c) => <option key={c.id} value={c.id}>{c.id}: {c.comment}</option>)}
      </select>
    </label>
    <label className="block text-sm">{tr('referenceDirection')}
      <select aria-label={tr('referenceDirection')} className="ml-2 rounded border p-2 text-bp-blue" value={direction} onChange={(e) => { reset(); setDirection(e.target.value); setSubcase(0) }}>
        <option value="send">{tr('referenceSend')}</option><option value="receive">{tr('referenceReceive')}</option>
      </select>
    </label>
    <label className="block text-sm">{tr('referenceSubcase')}
      <select aria-label={tr('referenceSubcase')} className="ml-2 rounded border p-2 text-bp-blue" value={subcase} onChange={(e) => { reset(); setSubcase(Number(e.target.value)) }}>
        {Array.from({ length: count }, (_, i) => <option key={i} value={i}>{i + 1} / {count}</option>)}
      </select>
    </label>
    <button className="sp-btn-solid" disabled={busy || !count} onClick={run}>{busy ? tr('loadingScenario') : tr('referenceRun')}</button>
    {error && <p role="alert">{error}</p>}
    {result && <div data-testid="reference-result">
      <p role="status" className="font-bold">{result.test_passed ? tr('passed') : tr('failed')}{result.expected_failure ? ` · ${tr('referenceExpectedFailure')}: ${result.note}` : ''}</p>
      <DemoRunResults tr={tr} testType={direction} testResults={result} compact />
      <details className="mt-3"><summary>{tr('referenceActual')}</summary><pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(result, null, 2)}</pre></details>
    </div>}
  </section>
}
