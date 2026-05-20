import CopyableText from '../CopyableText'

function CompareRow({ title, expectedLabel, receivedLabel, expected, got, match, matchOk, matchFail }) {
  return (
    <div className="rounded-lg border border-bp-200 bg-white p-3 dark:border-bp-500/30 dark:bg-bp-800/40">
      <p className="text-[11px] font-bold uppercase tracking-wide text-bp-500 dark:text-bp-300">{title}</p>
      <div className="mt-2 grid gap-2 sm:grid-cols-2">
        <div>
          <p className="text-[10px] font-bold text-bp-600 dark:text-bp-200">{expectedLabel}</p>
          <CopyableText value={expected} className="mt-1 bg-bp-50 dark:bg-bp-700/50" />
        </div>
        <div>
          <p className="text-[10px] font-bold text-bp-600 dark:text-bp-200">{receivedLabel}</p>
          <CopyableText value={got} className="mt-1 bg-bp-50 dark:bg-bp-700/50" />
        </div>
      </div>
      <p className="mt-2 text-xs font-bold text-bp-blue dark:text-bp-canvas">
        {match ? `✓ ${matchOk}` : `✗ ${matchFail}`}
      </p>
    </div>
  )
}

function sendExpectedOutputs(expected_outputs) {
  if (!expected_outputs?.length) return []
  return Array.isArray(expected_outputs[0]) ? expected_outputs[0] : expected_outputs
}

/**
 * @param {{
 *   tr: (k: string) => string
 *   testType: 'send' | 'receive'
 *   testResults: object
 *   compact?: boolean
 * }} props
 */
export default function DemoRunResults({ tr, testType, testResults, compact }) {
  if (!testResults) return null
  const passed = !!testResults.test_passed
  const isSend = testType === 'send'
  const matchOk = tr('passed')
  const matchFail = tr('failed')

  if (compact) {
    return (
      <div className="flex flex-col gap-1">
        <p className={`sp-demo-verify ${passed ? 'is-ok' : 'is-fail'}`}>
          {passed ? tr('demoVerifyOk') : tr('demoVerifyFail')}
          {testResults.note === 'zero key sum' ? ` · ${tr('zeroKeyNote')}` : ''}
        </p>
        {testResults.error ? (
          <p className="sp-demo-error text-[11px] leading-relaxed">{testResults.error}</p>
        ) : null}
      </div>
    )
  }

  return (
    <div className="sp-demo-results">
      <p className="sp-demo-results-title">{tr('demoVerifyTitle')}</p>
      {testResults.error ? (
        <p className="mt-1 text-xs font-medium text-bp-700 dark:text-bp-200">{testResults.error}</p>
      ) : null}
      {isSend ? (
        <div className="mt-2 flex flex-col gap-2">
          {sendExpectedOutputs(testResults.expected_outputs).map((hex, i) => {
            const got = testResults.outputs?.[i] ?? '—'
            return (
              <CompareRow
                key={`${hex}-${i}`}
                title={`${tr('outputN')} ${i + 1}`}
                expectedLabel={tr('expected')}
                receivedLabel={tr('received')}
                expected={hex}
                got={got}
                match={got === hex}
                matchOk={matchOk}
                matchFail={matchFail}
              />
            )
          })}
        </div>
      ) : (
        <div className="mt-2 flex flex-col gap-3">
          <CompareRow
            title={tr('address')}
            expectedLabel={tr('expected')}
            receivedLabel={tr('received')}
            expected={testResults.expected_addresses?.[0] ?? '—'}
            got={testResults.addresses?.[0] ?? '—'}
            match={testResults.addresses?.[0] === testResults.expected_addresses?.[0]}
            matchOk={matchOk}
            matchFail={matchFail}
          />
          {testResults.expected_outputs?.map((exp, i) => {
            const got = testResults.outputs?.[i]
            return (
              <div key={i} className="flex flex-col gap-2">
                <CompareRow
                  title={`${tr('outputN')} ${i + 1} · ${tr('recvPk')}`}
                  expectedLabel={tr('expected')}
                  receivedLabel={tr('received')}
                  expected={exp.pub_key}
                  got={got?.pub_key ?? '—'}
                  match={got?.pub_key === exp.pub_key}
                  matchOk={matchOk}
                  matchFail={matchFail}
                />
                <CompareRow
                  title={`${tr('outputN')} ${i + 1} · ${tr('recvTweak')}`}
                  expectedLabel={tr('expected')}
                  receivedLabel={tr('received')}
                  expected={exp.priv_key_tweak}
                  got={got?.priv_key_tweak ?? '—'}
                  match={got?.priv_key_tweak === exp.priv_key_tweak}
                  matchOk={matchOk}
                  matchFail={matchFail}
                />
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
