import { useEffect, useRef, useState } from 'react'
import { useLocale } from '../i18n/useLocale'
import { fetchApi, formatApiError } from '../utils/api'
import lessons from '../utils/referenceTeaching.json'
import provenance from '../../api/core/test/provenance.json'
import { referenceURL, validateReferenceLink, writeReferenceSelection } from '../utils/referenceLinks'
import DemoRunResults from '../components/protocol/DemoRunResults'

function ReferenceLesson({ selection, upstream }) {
  const { tr, locale } = useLocale()
  const { id, direction, subcase } = selection
  const lesson = lessons[id][locale]
  const [data, setData] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const [inputsOpen, setInputsOpen] = useState(false)
  const abort = useRef(null)
  useEffect(() => {
    const controller = new AbortController()
    fetchApi(`/api/test_case/${id}?case_index=${subcase}`, { signal: controller.signal })
      .then((value) => { if (!controller.signal.aborted) setData(value) })
      .catch((err) => { if (!controller.signal.aborted) setError(err) })
    return () => { controller.abort(); abort.current?.abort() }
  }, [id, subcase])
  const run = async () => {
    abort.current?.abort()
    const controller = new AbortController()
    abort.current = controller
    setBusy(true)
    setResult(null)
    setError(null)
    try {
      const value = await fetchApi(`/api/single_test/${direction}/${id}?case_index=${subcase}`, { signal: controller.signal })
      if (!controller.signal.aborted) setResult(value)
    } catch (err) {
      if (!controller.signal.aborted) setError(err)
    } finally { if (!controller.signal.aborted) setBusy(false) }
  }
  const inputs = data?.[direction === 'send' ? 'sending' : 'receiving']
  return <div className="min-w-0 space-y-4" data-testid="reference-lesson">
    <header className="space-y-2">
      <h3 className="text-lg font-bold">{lesson.title}</h3>
      <p>{lesson.demonstrates}</p>
      <p className="text-sm"><strong>{tr('teachWhy')}: </strong>{lesson.why}</p>
    </header>
    <section className="sp-surface space-y-2 rounded-lg p-3">
      <h4 className="font-bold">{tr('teachInputs')}</h4>
      {!data ? <p>{tr(error ? 'teachRequestError' : 'loadingScenario')}</p> : <dl className="grid grid-cols-2 gap-2 text-sm">
        {[[tr('teachInputCount'), inputs?.vin?.length ?? 0],
          [tr(direction === 'send' ? 'teachRecipientCount' : 'teachTransactionCount'), (inputs?.recipients || inputs?.outputs || []).length],
          ...(direction === 'receive' ? [[tr('teachLabelCount'), inputs?.labels?.length ?? 0]] : [])].map(([label, count]) => <div key={label}><dt>{label}</dt><dd className="font-mono font-bold">{count}</dd></div>)}
      </dl>}
      <p className="text-xs">{tr('teachFixture')}</p>
      <details onToggle={(event) => setInputsOpen(event.currentTarget.open)}><summary>{tr('teachTechnical')}</summary>
        <p className="my-2 text-sm">{upstream}</p>
        <p className="text-xs">BIP-352 v{provenance.spec_version} · <a className="underline" href={`https://github.com/bitcoin/bips/blob/${provenance.commit}/bip-0352.mediawiki`} target="_blank" rel="noopener noreferrer">{tr('teachSource')}</a></p>
        {data && inputsOpen && <RawJSON value={data} />}
      </details>
    </section>
    <section className="sp-surface space-y-2 rounded-lg p-3">
      <h4 className="font-bold">{tr('teachExpected')}</h4>
      <p>{lesson[direction === 'send' ? 'sending' : 'receiving']}</p>
      <p className="text-xs">{tr('teachNotRun')}</p>
    </section>
    <section className="space-y-2">
      <h4 className="font-bold">{tr('teachRun')}</h4>
      <button className="sp-btn-solid" disabled={busy || !data || !inputs} onClick={run}>{busy ? tr('loadingScenario') : tr('referenceRun')}</button>
    </section>
    {error && <p role="alert"><strong>{tr('teachRequestError')}: </strong>{formatApiError(error, tr)}</p>}
    {result && <section className="min-w-0 space-y-3" data-testid="reference-result">
      <h4 className="font-bold">{tr('teachActual')}</h4>
      <DemoRunResults tr={tr} testType={direction} testResults={result} />
      <details onToggle={(event) => setRawOpen(event.currentTarget.open)}><summary>{tr('teachRaw')}</summary>{rawOpen && <RawJSON value={result} />}</details>
    </section>}
  </div>
}

function RawJSON({ value }) {
  return <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(value, null, 2)}</pre>
}

export default function ReferenceCases({ initialSearch = window.location.search }) {
  const { tr, locale } = useLocale()
  const [loaded, setLoaded] = useState(null)
  const [loadError, setLoadError] = useState(null)
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState(false)
  useEffect(() => {
    const controller = new AbortController()
    fetchApi('/api/reference_cases', { signal: controller.signal })
      .then((cases) => {
        if (controller.signal.aborted) return
        const resolved = validateReferenceLink(initialSearch, cases)
        writeReferenceSelection(resolved.selection)
        setLoaded({ cases, ...resolved })
      })
      .catch((err) => { if (!controller.signal.aborted) setLoadError(err) })
    return () => controller.abort()
  }, [initialSearch])
  if (loadError) return <p role="alert">{tr('teachRequestError')}: {formatApiError(loadError, tr)}</p>
  if (!loaded) return <p>{tr('loadingScenario')}</p>
  const { cases, selection, invalid } = loaded
  const group = cases.find((entry) => entry.id === selection.id)
  const count = group.case_counts[selection.direction === 'send' ? 'sending' : 'receiving']
  const change = (next) => {
    const nextGroup = cases.find((entry) => entry.id === next.id)
    if (!nextGroup.case_counts[next.direction === 'send' ? 'sending' : 'receiving']) next.direction = next.direction === 'send' ? 'receive' : 'send'
    writeReferenceSelection(next)
    setLoaded({ cases, selection: next, invalid: false })
    setCopied(false)
    setCopyError(false)
  }
  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(referenceURL(selection).href)
      setCopied(true)
      setCopyError(false)
    } catch { setCopyError(true) }
  }
  const selectClass = 'mt-1 w-full rounded border border-bp-200 bg-white p-2 text-bp-blue dark:border-bp-500 dark:bg-bp-800 dark:text-bp-canvas'
  return <section className="min-w-0 space-y-4">
    <p className="text-xs">{tr('referenceIntro')}</p>
    <p className="text-sm">{tr('teachWait')}</p>
    {invalid && <p role="alert">{tr('teachInvalidLink')}</p>}
    <label className="block text-sm">{tr('referenceCase')}
      <select aria-label={tr('referenceCase')} className={selectClass} value={selection.id} onChange={(event) => change({ ...selection, id: Number(event.target.value), subcase: 0 })}>
        {cases.map((entry) => <option key={entry.id} value={entry.id}>{entry.id}: {lessons[entry.id][locale].title}</option>)}
      </select>
    </label>
    <div className="grid grid-cols-2 gap-3">
      <label className="block text-sm">{tr('referenceDirection')}
        <select aria-label={tr('referenceDirection')} className={selectClass} value={selection.direction} onChange={(event) => change({ ...selection, direction: event.target.value, subcase: 0 })}>
          <option value="send" disabled={!group.case_counts.sending}>{tr('referenceSend')}</option><option value="receive" disabled={!group.case_counts.receiving}>{tr('referenceReceive')}</option>
        </select>
      </label>
      <label className="block text-sm">{tr('referenceSubcase')}
        <select aria-label={tr('referenceSubcase')} className={selectClass} value={selection.subcase} onChange={(event) => change({ ...selection, subcase: Number(event.target.value) })}>
          {Array.from({ length: count }, (_, index) => <option key={index} value={index}>{index + 1} / {count}</option>)}
        </select>
      </label>
    </div>
    <button className="sp-btn-solid" onClick={copyLink}>{tr('teachCopyLink')}</button>
    {copied && <span role="status" className="ml-2 text-xs">{tr('copied')}</span>}
    {copyError && <p role="alert">{tr('teachLinkError')}</p>}
    <ReferenceLesson key={`${selection.id}-${selection.direction}-${selection.subcase}`} selection={selection} upstream={group.comment} />
  </section>
}
