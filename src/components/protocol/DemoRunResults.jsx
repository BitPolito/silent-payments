import { useState } from 'react'
import CopyableText from '../CopyableText'
import { compareReferenceResult } from '../../utils/referenceComparison'

const STATUS_KEYS = { matched: 'teachMatched', missing: 'teachMissing', unexpected: 'teachUnexpected', different: 'teachDifferent' }

function ValuePair({ title, expected, actual, tr }) {
  return <div className="min-w-0">
    <h5 className="text-xs font-bold">{title}</h5>
    <div className="grid min-w-0 gap-2 sm:grid-cols-2">
      <div className="min-w-0"><p className="text-xs">{tr('expected')}</p><CopyableText value={expected} /></div>
      <div className="min-w-0"><p className="text-xs">{tr('received')}</p><CopyableText value={actual} /></div>
    </div>
  </div>
}

export default function DemoRunResults({ tr, testType, testResults, compact }) {
  const [page, setPage] = useState(0)
  if (!testResults) return null
  const comparison = compareReferenceResult(testResults, testType)
  const totalPages = Math.max(1, Math.ceil(comparison.rows.length / 50))
  const currentPage = Math.min(page, totalPages - 1)
  const status = testResults.test_passed ? testResults.expected_failure ? 'teachRejected' : 'teachMatches' : 'teachMismatch'
  const missing = comparison.rows.filter((row) => row.status === 'missing').length
  const unexpected = comparison.rows.filter((row) => row.status === 'unexpected').length
  return <div className="min-w-0 space-y-3" data-testid="comparison">
    <p role="status" className="font-bold">{tr(status)}</p>
    {testResults.error && <p role="alert">{testResults.error}</p>}
    {testResults.test_passed && !testResults.expected_failure && comparison.actual.length === 0 && <p>{tr('teachEmpty')}</p>}
    <dl className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
      {[[tr('teachExpectedCount'), comparison.expected.length], [tr('teachActualCount'), comparison.actual.length], [tr('teachMissingCount'), missing], [tr('teachUnexpectedCount'), unexpected]].map(([label, count]) =>
        <div key={label}><dt>{label}</dt><dd className="font-mono font-bold">{count}</dd></div>)}
    </dl>
    {!compact && <>
      {comparison.alternatives > 1 && <p className="text-xs">{tr('teachAlternative').replace('{n}', comparison.index + 1).replace('{total}', comparison.alternatives)}</p>}
      {comparison.addresses.map((row, index) => <section key={index} className="sp-surface space-y-2 rounded-lg p-3" data-testid="address-comparison">
        <p className="text-xs font-bold">{tr(STATUS_KEYS[row.status])}</p>
        <ValuePair title={`${tr('teachAddress')} ${index + 1}`} expected={row.expected} actual={row.actual} tr={tr} />
      </section>)}
      {comparison.rows.slice(currentPage * 50, (currentPage + 1) * 50).map((row, index) => <section key={currentPage * 50 + index} className="sp-surface min-w-0 space-y-2 rounded-lg p-3" data-testid="output-comparison">
        <h4 className="text-sm font-bold">{tr('teachOutput')} {currentPage * 50 + index + 1} · {tr(STATUS_KEYS[row.status])}</h4>
        {testType === 'send'
          ? <ValuePair title={tr('teachKey')} expected={row.expected} actual={row.actual} tr={tr} />
          : <>
            <ValuePair title={tr('teachKey')} expected={row.expected?.pub_key} actual={row.actual?.pub_key} tr={tr} />
            <ValuePair title={tr('teachTweak')} expected={row.expected?.priv_key_tweak} actual={row.actual?.priv_key_tweak} tr={tr} />
            {row.actual?.signature && <details><summary>{tr('teachSignature')}</summary><p className="text-xs">{tr('teachSignatureNote')}</p><CopyableText value={row.actual.signature} /></details>}
          </>}
      </section>)}
      {totalPages > 1 && <nav aria-label={tr('teachPage').replace('{n}', currentPage + 1).replace('{total}', totalPages)} className="flex flex-wrap items-center gap-3">
        <button className="sp-btn-solid" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>{tr('teachPrevious')}</button>
        <span className="text-sm">{tr('teachPage').replace('{n}', currentPage + 1).replace('{total}', totalPages)}</span>
        <button className="sp-btn-solid" disabled={currentPage + 1 >= totalPages} onClick={() => setPage(currentPage + 1)}>{tr('teachNext')}</button>
      </nav>}
    </>}
  </div>
}
