import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { STORY } from '../assets/icons'
import Collapsible from '../components/protocol/Collapsible'
import DemoRunResults from '../components/protocol/DemoRunResults'
import { FLOW_ICONS } from '../assets/flowIcons'
import FlowProgress from '../components/flow/FlowProgress'
import { DataBlock, PubkeyOutput, SilentAddressField, StepHeader, UtxoList } from '../components/flow/FlowPanels'
import { useLocale } from '../i18n/LocaleContext'
import { fetchApi, formatApiError } from '../utils/api'
import { pickRandomFlowScenario } from '../utils/demoScenarios'
import { canRunReceiveCheck, isSendStepComplete } from '../utils/flowDisplay'
import { getScenarioContext, resolveAliceOutputs } from '../utils/scenarioContext'

const STEPS = ['bob', 'alice', 'derive', 'scan']

const SCENARIO_MID_ICON = {
  donation: STORY.donation,
  silent: STORY.silent,
  wallet: STORY.wallet,
  key: STORY.key,
}

const alertIcon = '/bitpolito/alert.svg'

function resetFlowState(setters) {
  setters.setPhase('bob')
  setters.setSendResult(null)
  setters.setRecvResult(null)
  setters.setSendError('')
  setters.setRecvError('')
  setters.setFurthest(0)
}

function StoryStrip({ phase, tr, midIcon }) {
  const bobOn = phase === 'bob' || phase === 'scan'
  const aliceOn = phase === 'alice' || phase === 'derive'
  const mid = phase === 'derive' || phase === 'scan' ? STORY.bitlogo : midIcon || STORY.donation

  return (
    <div className="sp-story-stage py-1">
      <div className={`sp-story-actor max-w-[4rem] ${aliceOn ? 'is-active' : 'is-dim'}`}>
        <img src={STORY.alice} alt="" className="sp-story-actor-img !h-8 !w-8" />
        <span className="sp-story-actor-name">{tr('demoAlice')}</span>
      </div>
      <img src={mid} alt="" className="sp-story-pizza !h-7 !w-7" />
      <div className={`sp-story-actor max-w-[4rem] ${bobOn ? 'is-active' : 'is-dim'}`}>
        <img src={STORY.bob} alt="" className="sp-story-actor-img !h-8 !w-8" />
        <span className="sp-story-actor-name">{tr('demoBob')}</span>
      </div>
    </div>
  )
}

function Verdict({ ok, okText, failText }) {
  return (
    <p className={`sp-flow-verdict ${ok ? 'is-ok' : 'is-fail'}`} role="status">
      {ok ? okText : failText}
    </p>
  )
}

/**
 * @param {{ onOpenEdgeCases: () => void, onCloseHome?: () => void }} props
 */
export default function PaymentFlow({ onOpenEdgeCases, onCloseHome }) {
  const { tr } = useLocale()
  const [scenario, setScenario] = useState(() => pickRandomFlowScenario())
  const testId = scenario.testId

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
    setLoadingCase(true)
    setLoadError('')
    setCaseData(null)
    fetchApi(`/api/test_case/${testId}`, { signal: ac.signal })
      .then((data) => setCaseData({ ...data, scenarioId: scenario.id }))
      .catch((e) => {
        if (e.name !== 'AbortError') setLoadError(formatApiError(e, tr))
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoadingCase(false)
      })
    return () => ac.abort()
  }, [testId, scenario.id, tr])

  const ctx = useMemo(() => getScenarioContext(caseData), [caseData])
  const storyKind = ctx.storyKind

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
          setSendResult({ test_passed: false, error: msg })
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
          setRecvResult({ test_passed: false, error: msg })
        }
      })
      .finally(() => {
        if (!ac.signal.aborted) setRecvLoading(false)
      })
  }, [testId, tr])

  const liveOutputs = useMemo(() => {
    if (sendResult) return Array.isArray(sendResult.outputs) ? sendResult.outputs : []
    return resolveAliceOutputs(null, ctx.silentOutputs)
  }, [sendResult, ctx.silentOutputs])

  const bobShare = ctx.bobShareAddresses[0] || ''
  const bobReceivePreview = ctx.bobReceiveOnChain[0] || ''
  const bobReceiveFound =
    recvResult?.outputs?.[0]?.pub_key || liveOutputs[0] || bobReceivePreview || ''

  const sendComplete = isSendStepComplete(sendResult, storyKind)
  const sendPassedStrict = !!sendResult?.test_passed
  const recvPassed = !!recvResult?.test_passed
  const done = recvPassed

  const edgeNoteKey = `flowAside_${storyKind}`
  const edgeNote = tr(edgeNoteKey)
  const showEdgeNote = storyKind !== 'linked' && Boolean(edgeNote?.trim()) && edgeNote !== edgeNoteKey
  const showCompleteActions = done && phase === 'scan'

  const stepIndex = STEPS.indexOf(phase)

  useEffect(() => {
    setFurthest((f) => Math.max(f, stepIndex))
  }, [stepIndex])

  useEffect(() => {
    if (sendResult) setFurthest((f) => Math.max(f, STEPS.length - 1))
  }, [sendResult])

  useEffect(() => {
    if (recvPassed) setFurthest((f) => Math.max(f, STEPS.length - 1))
  }, [recvPassed])

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
    if (!sendResult) return Math.min(furthest, deriveIdx)
    return furthest
  }, [furthest, sendResult])

  const goPhase = (id) => {
    const idx = STEPS.indexOf(id)
    if (idx === -1 || idx > maxReachableIndex) return
    if (id === 'scan' && !canRunReceiveCheck(sendResult, storyKind)) return
    setPhase(id)
  }

  const goNext = useCallback(() => {
    if (stepIndex < STEPS.length - 1) setPhase(STEPS[stepIndex + 1])
  }, [stepIndex])

  const goPrev = () => {
    if (stepIndex <= 0) return
    sendAbort.current?.abort()
    recvAbort.current?.abort()
    setSendLoading(false)
    setRecvLoading(false)
    setPhase(STEPS[stepIndex - 1])
  }

  const restartDemo = useCallback(() => {
    sendAbort.current?.abort()
    recvAbort.current?.abort()
    setScenario((prev) => pickRandomFlowScenario(prev.id))
    resetFlowState({
      setPhase,
      setSendResult,
      setRecvResult,
      setSendError,
      setRecvError,
      setFurthest,
    })
  }, [])

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

  const midIcon = SCENARIO_MID_ICON[scenario.icon] || STORY.donation

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
        <img src={alertIcon} alt="" className="h-8 w-8 shrink-0" />
        <p className="text-sm font-medium text-bp-blue dark:text-bp-canvas">{loadError || tr('apiError')}</p>
      </div>
    )
  }

  return (
    <div className="sp-flow-shell">
      <FlowProgress steps={railSteps} maxIndex={maxReachableIndex} onSelect={goPhase} />

      <article className="sp-flow-card">
        <StoryStrip phase={phase} tr={tr} midIcon={midIcon} />

        {showEdgeNote ? <p className="sp-flow-edge-note">{edgeNote}</p> : null}

        <div key={`${scenario.id}-${phase}`} className="sp-flow-panel">
          {phase === 'bob' ? (
            <>
              <StepHeader icon={FLOW_ICONS.bob} title={tr('flowBobTitle')}>
                <p className="sp-flow-step-lead">{tr('flowBobLead')}</p>
              </StepHeader>
              {bobShare ? (
                <DataBlock icon={FLOW_ICONS.address} label={tr('flowDataBobShare')} hint={tr('flowDataBobShareHint')}>
                  <SilentAddressField compact value={bobShare} {...addressBadges} />
                </DataBlock>
              ) : null}
            </>
          ) : null}

          {phase === 'alice' ? (
            <>
              <StepHeader icon={FLOW_ICONS.alice} title={tr('flowAliceTitle')}>
                <p className="sp-flow-step-lead">{tr('flowAliceLead')}</p>
              </StepHeader>
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
            </>
          ) : null}

          {phase === 'derive' ? (
            <>
              <StepHeader icon={FLOW_ICONS.derive} title={tr('flowDeriveTitle')}>
                <p className="sp-flow-step-lead">{tr('flowDeriveLead')}</p>
              </StepHeader>
              {sendLoading ? <p className="sp-demo-running">{tr('flowDeriveRunning')}</p> : null}
              {sendError ? <p className="sp-demo-error">{sendError}</p> : null}
              {sendResult?.note === 'zero key sum' ? <p className="sp-flow-note">{tr('zeroKeyNote')}</p> : null}
              {sendResult && !sendLoading ? (
                <div className="space-y-2">
                  <Verdict
                    ok={sendComplete}
                    okText={sendPassedStrict ? tr('flowVerifyOk') : tr('flowVerifyOkEdge')}
                    failText={tr('flowVerifyFail')}
                  />
                  <DataBlock icon={FLOW_ICONS.receive} label={tr('flowDataPaymentOut')}>
                    {liveOutputs.length ? (
                      liveOutputs.map((hex) => <PubkeyOutput key={hex} pubkey={hex} />)
                    ) : (
                      <p className="sp-flow-muted text-[11px]">{tr('flowDataNoPaymentBuilt')}</p>
                    )}
                  </DataBlock>
                  {!sendComplete ? (
                    <Collapsible title={tr('flowVerifyFold')} nested>
                      <DemoRunResults tr={tr} testType="send" testResults={sendResult} compact />
                    </Collapsible>
                  ) : null}
                </div>
              ) : null}
            </>
          ) : null}

          {phase === 'scan' ? (
            <>
              <StepHeader icon={FLOW_ICONS.scan} title={tr('flowScanTitle')}>
                <p className="sp-flow-step-lead">{tr('flowScanLead')}</p>
              </StepHeader>
              {!canScan && !recvResult ? <p className="sp-flow-note">{tr('flowScanNeedsSend')}</p> : null}
              {recvLoading ? <p className="sp-demo-running">{tr('flowScanRunning')}</p> : null}
              {recvError ? <p className="sp-demo-error">{recvError}</p> : null}
              {recvResult && !recvLoading ? (
                <div className="space-y-2">
                  <Verdict ok={recvPassed} okText={tr('flowVerifyOk')} failText={tr('flowVerifyFail')} />
                  {recvPassed && bobReceiveFound ? (
                    <DataBlock icon={FLOW_ICONS.receive} label={tr('flowDataFound')} hint={tr('flowDataFoundHint')}>
                      <PubkeyOutput pubkey={bobReceiveFound} />
                    </DataBlock>
                  ) : null}
                  {!recvPassed ? (
                    <Collapsible title={tr('flowVerifyFold')} nested>
                      <DemoRunResults tr={tr} testType="receive" testResults={recvResult} compact />
                    </Collapsible>
                  ) : null}
                </div>
              ) : null}
              {done ? <p className="sp-flow-done">{tr('flowCompleteBody')}</p> : null}
            </>
          ) : null}
        </div>
      </article>

      <div className="flex items-center gap-2">
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
          <div className="ml-auto flex flex-1 flex-wrap justify-end gap-2 sm:flex-none">
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
            className="ml-auto min-w-[10rem] flex-1 rounded-[10px] bg-bp-blue px-4 py-2.5 text-sm font-bold text-bp-canvas disabled:opacity-45 dark:bg-bp-canvas dark:text-bp-blue sm:flex-none sm:flex-initial"
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
