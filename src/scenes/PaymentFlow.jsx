import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import DemoRunResults from '../components/protocol/DemoRunResults'
import WalkthroughLesson from '../components/protocol/WalkthroughLesson'
import WalkthroughVisual from '../components/protocol/WalkthroughVisual'
import { FLOW_ICONS } from '../assets/flowIcons'
import FlowProgress from '../components/flow/FlowProgress'
import { DataBlock, SilentAddressField, UtxoList } from '../components/flow/FlowPanels'
import { useLocale } from '../i18n/useLocale'
import { fetchApi, formatApiError } from '../utils/api'
import { FLOW_SCENARIOS } from '../utils/demoScenarios'
import { canRunReceiveCheck, isSendStepComplete } from '../utils/flowDisplay'
import { getScenarioContext } from '../utils/scenarioContext'

const STEPS = ['bob', 'alice', 'derive', 'scan']

const alertIcon = '/bitpolito/alert.svg'

function resetFlowState(setters) {
  setters.setPhase('bob')
  setters.setSendResult(null)
  setters.setRecvResult(null)
  setters.setSendError('')
  setters.setRecvError('')
  setters.setFurthest(0)
}

/**
 * @param {{ onOpenEdgeCases: () => void, onCloseHome?: () => void }} props
 */
export default function PaymentFlow({ onOpenEdgeCases, onCloseHome }) {
  const { tr } = useLocale()
  const scenario = FLOW_SCENARIOS[0]
  const [round, setRound] = useState(0)
  const testId = scenario.testId
  const panelRef = useRef(null)
  const previousPhase = useRef('bob')

  const [phase, setPhase] = useState('bob')
  const [caseData, setCaseData] = useState(null)
  const [loadError, setLoadError] = useState('')
  const [loadingCase, setLoadingCase] = useState(true)
  const [sendLoading, setSendLoading] = useState(false)
  const [recvLoading, setRecvLoading] = useState(false)
  const [sendError, setSendError] = useState('')
  const [recvError, setRecvError] = useState('')
  const [sendResult, setSendResult] = useState(null)
  const [recvResult, setRecvResult] = useState(null)
  const [furthest, setFurthest] = useState(0)

  const sendAbort = useRef(/** @type {AbortController | null} */ (null))
  const recvAbort = useRef(/** @type {AbortController | null} */ (null))

  useEffect(() => {
    const ac = new AbortController()
    fetchApi(`/api/test_case/${testId}`, { signal: ac.signal })
      .then((data) => { if (!ac.signal.aborted) setCaseData({ ...data, scenarioId: scenario.id }) })
      .catch((e) => {
        if (!ac.signal.aborted) setLoadError(e)
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoadingCase(false)
      })
    return () => ac.abort()
  }, [testId, scenario.id, round])

  useEffect(() => {
    if (previousPhase.current === phase) return
    previousPhase.current = phase
    panelRef.current?.focus({ preventScroll: true })
    panelRef.current?.scrollIntoView({ block: 'start', behavior: 'auto' })
  }, [phase])

  const ctx = useMemo(() => getScenarioContext(caseData), [caseData])
  const storyKind = ctx.storyKind

  useEffect(() => () => {
    sendAbort.current?.abort()
    recvAbort.current?.abort()
  }, [])

  const cancelChecks = useCallback(() => {
    sendAbort.current?.abort()
    recvAbort.current?.abort()
    setSendLoading(false)
    setRecvLoading(false)
  }, [])

  const runSend = useCallback(() => {
    sendAbort.current?.abort()
    const ac = new AbortController()
    sendAbort.current = ac
    setSendLoading(true)
    setSendError('')
    fetchApi(`/api/single_test/send/${testId}`, { signal: ac.signal })
      .then((data) => {
        if (ac.signal.aborted) return
        setSendResult(data)
        setSendError(data?.error ? String(data.error) : '')
      })
      .catch((e) => {
        if (e.name !== 'AbortError' && !ac.signal.aborted) {
          const msg = formatApiError(e, tr)
          setSendError(msg)
          setSendResult(null)
        }
      })
      .finally(() => {
        if (!ac.signal.aborted) setSendLoading(false)
      })
  }, [testId, tr])

  const runRecv = useCallback(() => {
    recvAbort.current?.abort()
    const ac = new AbortController()
    recvAbort.current = ac
    setRecvLoading(true)
    setRecvError('')
    fetchApi(`/api/single_test/receive/${testId}`, { signal: ac.signal })
      .then((data) => {
        if (ac.signal.aborted) return
        setRecvResult(data)
        setRecvError(data?.error ? String(data.error) : '')
      })
      .catch((e) => {
        if (e.name !== 'AbortError' && !ac.signal.aborted) {
          const msg = formatApiError(e, tr)
          setRecvError(msg)
          setRecvResult(null)
        }
      })
      .finally(() => {
        if (!ac.signal.aborted) setRecvLoading(false)
      })
  }, [testId, tr])

  const bobShare = ctx.bobShareAddresses[0] || ''

  const sendComplete = isSendStepComplete(sendResult, storyKind)
  const recvPassed = !!recvResult?.test_passed
  const done = recvPassed

  const edgeNoteKey = `flowAside_${storyKind}`
  const edgeNote = tr(edgeNoteKey)
  const showEdgeNote = storyKind !== 'linked' && Boolean(edgeNote?.trim()) && edgeNote !== edgeNoteKey
  const showCompleteActions = done && phase === 'scan'

  const stepIndex = STEPS.indexOf(phase)

  const railSteps = STEPS.map((id) => ({
    id,
    label: tr(`flowStep_${id}`),
    current: id === phase,
    done:
      (id === 'bob' && stepIndex > 0) ||
      (id === 'alice' && stepIndex > 1) ||
      (id === 'derive' && sendComplete) ||
      (id === 'scan' && recvPassed),
  }))

  const maxReachableIndex = useMemo(() => {
    const deriveIdx = STEPS.indexOf('derive')
    if (!sendComplete) return Math.min(Math.max(furthest, stepIndex), deriveIdx)
    return STEPS.length - 1
  }, [furthest, stepIndex, sendComplete])

  const goPhase = (id) => {
    const idx = STEPS.indexOf(id)
    if (idx === -1 || idx > maxReachableIndex) return
    if (id === 'scan' && !canRunReceiveCheck(sendResult, storyKind)) return
    cancelChecks()
    setPhase(id)
  }

  const goNext = useCallback(() => {
    cancelChecks()
    if (stepIndex < STEPS.length - 1) setPhase(STEPS[stepIndex + 1])
  }, [stepIndex, cancelChecks])

  const goPrev = () => {
    if (stepIndex <= 0) return
    cancelChecks()
    setFurthest((f) => Math.max(f, stepIndex))
    setPhase(STEPS[stepIndex - 1])
  }

  const restartDemo = useCallback(() => {
    cancelChecks()
    setRound((value) => value + 1)
    setLoadingCase(true)
    setCaseData(null)
    setLoadError('')
    resetFlowState({
      setPhase,
      setSendResult,
      setRecvResult,
      setSendError,
      setRecvError,
      setFurthest,
    })
  }, [cancelChecks])

  const expectedOutputCount = phase === 'scan'
    ? caseData?.receiving?.expected_outputs?.length || 0
    : caseData?.sending?.expected_output_sets?.[0]?.length || 0
  const currentResult = phase === 'scan' ? recvResult : phase === 'derive' ? sendResult : null

  const busy = sendLoading || recvLoading
  const canScan = canRunReceiveCheck(sendResult, storyKind)

  const primaryAction = useMemo(() => {
    if (busy || loadingCase) return { label: tr('flowBusy'), run: null, disabled: true }
    if (phase === 'derive' && !sendResult) return { label: tr('flowDeriveAction'), run: runSend, disabled: false }
    if (phase === 'derive' && sendResult && !sendComplete) {
      return { label: tr('flowRetry'), run: runSend, disabled: false }
    }
    if (phase === 'scan' && !recvResult) {
      return { label: tr('flowScanAction'), run: runRecv, disabled: !canScan }
    }
    if (phase === 'scan' && recvResult && !recvPassed) {
      return { label: tr('flowRetry'), run: runRecv, disabled: false }
    }
    if (phase === 'derive' && sendComplete) return { label: tr('flowContinue'), run: goNext, disabled: false }
    return { label: tr('flowContinue'), run: goNext, disabled: false }
  }, [
    busy,
    loadingCase,
    phase,
    sendResult,
    sendComplete,
    recvResult,
    recvPassed,
    canScan,
    tr,
    runSend,
    runRecv,
    goNext,
  ])

  const addressBadges = useMemo(
    () => ({
      notBc1Note: tr('flowNotBc1Note'),
      badgeSilent: tr('flowBadgeSilent'),
      badgeBc1: tr('flowBadgeBc1'),
    }),
    [tr],
  )

  if (loadingCase) {
    return (
      <div className="flex items-center justify-center gap-2 py-12">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-bp-blue border-t-transparent dark:border-bp-canvas dark:border-t-transparent" />
        <p className="text-sm text-bp-600 dark:text-bp-canvas/80">{tr('flowLoading')}</p>
      </div>
    )
  }

  if (loadError || !caseData) {
    return (
      <div className="flex items-center gap-3 rounded-lg border border-dashed border-bp-400 bg-bp-100 p-4 dark:border-bp-500/40 dark:bg-bp-700/35">
        <img src={alertIcon} alt="" className="sp-icon-blue h-8 w-8 shrink-0" />
        <p className="text-sm font-medium text-bp-blue dark:text-bp-canvas">{loadError ? formatApiError(loadError, tr) : tr('apiError')}</p>
      </div>
    )
  }

  return (
    <div className="sp-flow-shell sp-simple-demo">
      <p className="sp-description text-sm">{tr('learnSimulation')}</p>
      <FlowProgress ariaLabel={tr('learnProgress')} steps={railSteps} maxIndex={maxReachableIndex} onSelect={goPhase} />

      <article ref={panelRef} tabIndex={-1} role="region" aria-label={tr(`flowStep_${phase}`)} className="sp-walkthrough-grid">
        <div className="sp-flow-card">
          <WalkthroughVisual phase={phase} expectedCount={expectedOutputCount} result={currentResult} />
          <WalkthroughLesson key={phase} phase={phase} caseData={caseData} result={currentResult} />
          {showEdgeNote ? <p className="sp-flow-edge-note">{edgeNote}</p> : null}
          <div key={`${scenario.id}-${phase}`} className="sp-flow-panel">
          {phase === 'bob' ? (
            <>
              {bobShare ? (
                <section className="sp-demo-data"><DataBlock icon={FLOW_ICONS.address} label={tr('flowDataBobShare')} hint={tr('flowDataBobShareHint')}>
                  <SilentAddressField compact value={bobShare} {...addressBadges} />
                </DataBlock></section>
              ) : null}
            </>
          ) : null}

          {phase === 'alice' ? (
            <>
              <section className="sp-demo-data">
              <DataBlock icon={FLOW_ICONS.coins} label={tr('flowDataCoins')} hint={tr('flowDataCoinsHint').replace('{n}', String(ctx.inputCount))}>
                <UtxoList
                  inputs={ctx.aliceInputs}
                  signedLabel={tr('flowInputSigned')}
                  utxoLabel={tr('flowUtxoIndex')}
                  scriptLabel={tr('flowUtxoScript')}
                />
              </DataBlock>
              {bobShare ? (
                <DataBlock icon={FLOW_ICONS.address} label={tr('flowDataRecipient')} hint={tr('flowDataRecipientHint')}>
                  <SilentAddressField compact value={bobShare} {...addressBadges} />
                </DataBlock>
              ) : null}
              </section>
            </>
          ) : null}

          {phase === 'derive' ? (
            <>
              {sendLoading ? <p className="sp-demo-running">{tr('flowDeriveRunning')}</p> : null}
              {sendError ? <p role="alert" className="sp-demo-error">{tr('teachRequestError')}: {sendError}</p> : null}
              {sendResult?.note === 'zero key sum' ? <p className="sp-flow-note">{tr('zeroKeyNote')}</p> : null}
              {sendResult && !sendLoading ? (
                <div className="space-y-2">
                  <DemoRunResults tr={tr} testType="send" testResults={sendResult} walkthrough />
                </div>
              ) : null}
            </>
          ) : null}

          {phase === 'scan' ? (
            <>
              {!canScan && !recvResult ? <p className="sp-flow-note">{tr('flowScanNeedsSend')}</p> : null}
              {recvLoading ? <p className="sp-demo-running">{tr('flowScanRunning')}</p> : null}
              {recvError ? <p role="alert" className="sp-demo-error">{tr('teachRequestError')}: {recvError}</p> : null}
              {recvResult && !recvLoading ? (
                <div className="space-y-2">
                  <DemoRunResults tr={tr} testType="receive" testResults={recvResult} walkthrough />
                </div>
              ) : null}
              {done && <section className="space-y-3" data-testid="walkthrough-recap">
                <p className="sp-flow-done">{tr('flowCompleteBody')}</p>
                <p className="text-sm">{tr('uiDemoTakeaway')}</p>
              </section>}
            </>
          ) : null}
          </div>
        </div>
      </article>

      <div className="sp-walkthrough-actions">
        <button
          type="button"
          onClick={goPrev}
          disabled={stepIndex <= 0 || loadingCase}
          aria-disabled={stepIndex <= 0 || loadingCase}
          className="rounded-lg px-2 py-2 text-xs font-bold text-bp-blue underline underline-offset-2 disabled:opacity-35 dark:text-bp-canvas"
        >
          {tr('demoNavBack')}
        </button>
        {showCompleteActions ? (
          <div className="ml-auto flex basis-full flex-wrap justify-end gap-2 sm:basis-auto sm:flex-none">
            <button
              type="button"
              onClick={restartDemo}
              disabled={loadingCase || busy}
              className="min-w-[7.5rem] flex-1 rounded-[10px] border border-bp-blue/35 bg-transparent px-4 py-2.5 text-sm font-bold text-bp-blue disabled:opacity-45 dark:border-bp-canvas/35 dark:text-bp-canvas sm:flex-initial"
            >
              {tr('flowFinishRestart')}
            </button>
            <button
              type="button"
              onClick={() => onCloseHome?.()}
              className="min-w-[7.5rem] flex-1 rounded-[10px] bg-bp-blue px-4 py-2.5 text-sm font-bold text-bp-canvas dark:bg-bp-canvas dark:text-bp-blue sm:flex-initial"
            >
              {tr('flowFinishHome')}
            </button>
          </div>
        ) : (
          <button
            type="button"
            disabled={primaryAction.disabled}
            onClick={() => {
              if (primaryAction.run) primaryAction.run()
              else if (!primaryAction.disabled) goNext()
            }}
            className="ml-auto min-w-0 flex-1 rounded-[10px] bg-bp-blue px-4 py-2.5 text-sm font-bold text-bp-canvas disabled:opacity-45 dark:bg-bp-canvas dark:text-bp-blue sm:flex-none sm:flex-initial"
          >
            {primaryAction.label}
          </button>
        )}
      </div>

      <p className="sp-flow-footer">
        <button type="button" onClick={onOpenEdgeCases} className="font-medium underline underline-offset-2">
          {tr('flowEdgeLink')}
        </button>
      </p>
    </div>
  )
}
