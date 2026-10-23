import { useRef, useState } from 'react'
import CopyableText from '../CopyableText'
import { compareReferenceResult } from '../../utils/referenceComparison'

const STATUS_KEYS = { matched: 'teachMatched', missing: 'teachMissing', unexpected: 'teachUnexpected', different: 'teachDifferent' }

function ValuePair({ title, expected, actual, tr, deduplicate = false }) {
  if (deduplicate && expected === actual) return <CopyableText label={title} value={actual} />
  return <div className="min-w-0">
    <h5 className="text-xs font-bold">{title}</h5>
    <div className="grid min-w-0 gap-2 sm:grid-cols-2">
      <CopyableText label={tr('expected')} value={expected} />
      <CopyableText label={tr('received')} value={actual} />
    </div>
  </div>
}

export default function DemoRunResults({ tr, testType, testResults, compact, walkthrough = false }) {
  const [page, setPage] = useState(0)
  const resultRef = useRef(null)
  const changePage = (next) => {
    setPage(next)
    resultRef.current?.focus({ preventScroll: true })
    resultRef.current?.scrollIntoView({ block: 'start', behavior: 'auto' })
  }
  if (!testResults) return null
  const comparison = compareReferenceResult(testResults, testType)
  const totalPages = Math.max(1, Math.ceil(comparison.rows.length / 50))
  const currentPage = Math.min(page, totalPages - 1)
  const status = testResults.test_passed ? testResults.expected_failure ? 'teachRejected' : 'teachMatches' : 'teachMismatch'
  const missing = comparison.rows.filter((row) => row.status === 'missing').length
  const unexpected = comparison.rows.filter((row) => row.status === 'unexpected').length
  const counts = (
    <dl className="sp-result-counts grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
      {[[tr('teachExpectedCount'), comparison.expected.length], [tr('teachActualCount'), comparison.actual.length], [tr('teachMissingCount'), missing], [tr('teachUnexpectedCount'), unexpected]].map(([label, count]) =>
        <div key={label}><dt>{label}</dt><dd className="font-mono font-bold">{count}</dd></div>)}
    </dl>
  )
  const values = <>
      {comparison.alternatives > 1 && <p className="text-xs">{tr('teachAlternative').replace('{n}', comparison.index + 1).replace('{total}', comparison.alternatives)}</p>}
      {comparison.addresses.map((row, index) => <section key={index} className="sp-surface space-y-2 rounded-lg p-3" data-testid="address-comparison">
        <p className="text-xs font-bold">{tr(STATUS_KEYS[row.status])}</p>
        <ValuePair title={`${tr('teachAddress')} ${index + 1}`} expected={row.expected} actual={row.actual} tr={tr} deduplicate={walkthrough} />
      </section>)}
      {comparison.rows.slice(currentPage * 50, (currentPage + 1) * 50).map((row, index) => <section key={currentPage * 50 + index} className="sp-surface min-w-0 space-y-2 rounded-lg p-3" data-testid="output-comparison">
        <h4 className="text-sm font-bold">{tr('teachOutput')} {currentPage * 50 + index + 1} · {tr(STATUS_KEYS[row.status])}</h4>
        {testType === 'send'
          ? <ValuePair title={tr('teachKey')} expected={row.expected} actual={row.actual} tr={tr} deduplicate={walkthrough} />
          : <>
            <ValuePair title={tr('teachKey')} expected={row.expected?.pub_key} actual={row.actual?.pub_key} tr={tr} deduplicate={walkthrough} />
            <ValuePair title={tr('teachTweak')} expected={row.expected?.priv_key_tweak} actual={row.actual?.priv_key_tweak} tr={tr} deduplicate={walkthrough} />
            {row.actual?.signature && (walkthrough
              ? <section><CopyableText label={tr('teachSignature')} value={row.actual.signature} /><p className="sp-description mt-2 text-xs">{tr('teachSignatureNote')}</p></section>
              : <details><summary>{tr('teachSignature')}</summary><p className="text-xs">{tr('teachSignatureNote')}</p><CopyableText value={row.actual.signature} /></details>)}
          </>}
      </section>)}
      {totalPages > 1 && <nav aria-label={tr('teachPage').replace('{n}', currentPage + 1).replace('{total}', totalPages)} className="flex flex-wrap items-center gap-3">
        <button className="sp-btn-solid" disabled={currentPage === 0} onClick={() => changePage(currentPage - 1)}>{tr('teachPrevious')}</button>
        <span className="text-sm">{tr('teachPage').replace('{n}', currentPage + 1).replace('{total}', totalPages)}</span>
        <button className="sp-btn-solid" disabled={currentPage + 1 >= totalPages} onClick={() => changePage(currentPage + 1)}>{tr('teachNext')}</button>
      </nav>}
  </>
  return <div ref={resultRef} tabIndex={-1} role="region" aria-label={tr('uiResultPage')} className="min-w-0 space-y-3 scroll-mt-32" data-testid="comparison">
    <p role="status" className="sp-result-status" data-failed={!testResults.test_passed || undefined}>{tr(status)}</p>
    {testResults.error && <p role="alert">{testResults.error}</p>}
    {testResults.test_passed && !testResults.expected_failure && comparison.actual.length === 0 && <p>{tr('teachEmpty')}</p>}
    {(!walkthrough || !testResults.test_passed) && counts}
    {!compact && values}
  </div>
}
