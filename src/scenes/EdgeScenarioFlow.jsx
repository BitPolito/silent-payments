import { useCallback, useMemo, useRef, useState } from 'react'
import Collapsible from '../components/protocol/Collapsible'
import DemoRunResults from '../components/protocol/DemoRunResults'
import { FLOW_ICONS } from '../assets/flowIcons'
import FlowProgress from '../components/flow/FlowProgress'
import { DataBlock, PubkeyOutput, StepHeader, UtxoList } from '../components/flow/FlowPanels'
import { useLocale } from '../i18n/useLocale'
import { fetchApi, formatApiError } from '../utils/api'
import { explainSendOutcome } from '../utils/edgeScenarioCopy'
import { getScenarioContext } from '../utils/scenarioContext'

const STEPS = ['why', 'send', 'recv', 'done']

function Verdict({ ok, okText, failText, expectedText }) {
  if (ok === null) return null
  const text = ok ? okText : expectedText && !ok ? expectedText : failText
  return (
    <p className={`sp-flow-verdict ${ok || (expectedText && ok) ? 'is-ok' : 'is-fail'}`} role="status">
      {text}
    </p>
  )
}

/**
 * @param {{ caseData: object, scenarioId: string, testId: number, onBack: () => void, onCloseHome?: () => void }} props
 */
export default function EdgeScenarioFlow({ caseData, scenarioId, testId, onBack, onCloseHome }) {
  const { tr } = useLocale()
  const [phase, setPhase] = useState('why')
  const [sendLoading, setSendLoading] = useState(false)
  const [recvLoading, setRecvLoading] = useState(false)
  const [sendError, setSendError] = useState('')
  const [recvError, setRecvError] = useState('')
  const [sendResult, setSendResult] = useState(null)
  const [recvResult, setRecvResult] = useState(null)
  const [furthest, setFurthest] = useState(0)

  const sendAbort = useRef(/** @type {AbortController | null} */ (null))
  const recvAbort = useRef(/** @type {AbortController | null} */ (null))

  const ctx = useMemo(() => getScenarioContext(caseData), [caseData])
  const storyKind = ctx.storyKind
  const hasSend = !!caseData.sending
  const hasRecv = !!caseData.receiving

  const activeSteps = useMemo(
    () => STEPS.filter((id) => (id === 'send' ? hasSend : id === 'recv' ? hasRecv : true)),
    [hasSend, hasRecv],
  )

  const stepIndex = activeSteps.indexOf(phase)

  const runSend = useCallback(() => {
    if (!hasSend) return
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
  }, [hasSend, testId, tr])

  const runRecv = useCallback(() => {
    if (!hasRecv) return
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
  }, [hasRecv, testId, tr])

  const sendOutcome = explainSendOutcome(sendResult, storyKind)
  const liveOutputs = sendResult?.outputs?.length ? sendResult.outputs : []
  const busy = sendLoading || recvLoading

  const goNext = useCallback(() => {
    if (stepIndex < 0 || stepIndex >= activeSteps.length - 1) return
    setFurthest((f) => Math.max(f, stepIndex + 1))
    setPhase(activeSteps[stepIndex + 1])
  }, [stepIndex, activeSteps])

  const goPrev = useCallback(() => {
    if (stepIndex <= 0) return
    sendAbort.current?.abort()
    recvAbort.current?.abort()
    setSendLoading(false)
    setRecvLoading(false)
    setFurthest((f) => Math.max(f, stepIndex))
    setPhase(activeSteps[stepIndex - 1])
  }, [stepIndex, activeSteps])

  const restartCase = useCallback(() => {
    sendAbort.current?.abort()
    recvAbort.current?.abort()
    setPhase('why')
    setSendResult(null)
    setRecvResult(null)
    setSendError('')
    setRecvError('')
    setFurthest(0)
  }, [])

  const primaryAction = useMemo(() => {
    if (busy) return { label: tr('flowBusy'), run: null, disabled: true }
    if (phase === 'why') return { label: tr('flowContinue'), run: goNext, disabled: false }
    if (phase === 'send' && !sendResult) return { label: tr('edgeRunSend'), run: runSend, disabled: false }
    if (phase === 'send' && sendResult) return { label: tr('flowContinue'), run: goNext, disabled: false }
    if (phase === 'recv' && !recvResult) return { label: tr('edgeRunRecv'), run: runRecv, disabled: false }
    if (phase === 'recv' && recvResult) return { label: tr('flowContinue'), run: goNext, disabled: false }
    return { label: tr('flowContinue'), run: goNext, disabled: false }
  }, [busy, phase, sendResult, recvResult, tr, runSend, runRecv, goNext])

  const finished = phase === 'done'

  const railSteps = activeSteps.map((id) => ({
    id,
    label: tr(`edgeStep_${id}`),
    current: id === phase,
    done:
      (id === 'why' && stepIndex > 0) ||
      (id === 'send' && sendResult != null) ||
      (id === 'recv' && recvResult != null) ||
      (id === 'done' && phase === 'done'),
  }))

  return (
    <div className="sp-flow-shell">
      <button
        type="button"
        onClick={onBack}
        className="self-start text-xs font-semibold text-bp-blue underline underline-offset-2 dark:text-bp-canvas"
      >
        ← {tr('edgeBackToList')}
      </button>

      <FlowProgress
        steps={railSteps}
        maxIndex={furthest}
        onSelect={(id) => {
          const idx = activeSteps.indexOf(id)
          if (idx >= 0 && idx <= furthest) setPhase(id)
        }}
      />

      <article className="sp-card sp-flow-card">
        <h3 className="text-sm font-bold text-bp-blue dark:text-bp-canvas">{tr(`edgeCard_${scenarioId}_title`)}</h3>

        <div key={phase} className="sp-flow-panel">
          {phase === 'why' ? (
            <p className="text-xs leading-relaxed text-bp-700 dark:text-bp-canvas/85">{tr(`edgeWhy_${scenarioId}`)}</p>
          ) : null}

          {phase === 'send' && hasSend ? (
            <>
              <StepHeader icon={FLOW_ICONS.alice} title={tr('edgeSendTitle')}>
                <p className="sp-flow-step-lead">{tr(`edgeSendIntro_${scenarioId}`)}</p>
              </StepHeader>
              <DataBlock
                icon={FLOW_ICONS.coins}
                label={tr('flowDataCoins')}
                hint={tr('flowDataCoinsHint').replace('{n}', String(ctx.inputCount))}
              >
                <UtxoList
                  inputs={ctx.aliceInputs}
                  signedLabel={tr('flowInputSigned')}
                  utxoLabel={tr('flowUtxoIndex')}
                  scriptLabel={tr('flowUtxoScript')}
                />
              </DataBlock>
              {sendLoading ? <p className="sp-demo-running">{tr('flowDeriveRunning')}</p> : null}
              {sendError ? <p className="sp-demo-error">{sendError}</p> : null}
              {sendResult && !sendLoading ? (
                <div className="space-y-2">
                  <Verdict
                    ok={sendOutcome.ok}
                    okText={tr('flowVerifyOk')}
                    failText={tr('flowVerifyFail')}
                    expectedText={
                      sendOutcome.isExpectedEmpty ? tr(`edgeSendExpected_${scenarioId}`) : undefined
                    }
                  />
                  <DataBlock icon={FLOW_ICONS.receive} label={tr('flowDataPaymentOut')} hint={tr('flowDataPaymentOutHint')}>
                    {liveOutputs.length ? (
                      liveOutputs.map((hex) => <PubkeyOutput key={hex} pubkey={hex} />)
                    ) : (
                      <p className="sp-flow-muted text-[11px]">{tr('flowDataNoPaymentBuilt')}</p>
                    )}
                  </DataBlock>
                  {!sendOutcome.ok ? (
                    <Collapsible title={tr('flowVerifyFold')} nested>
                      <DemoRunResults tr={tr} testType="send" testResults={sendResult} compact />
                    </Collapsible>
                  ) : null}
                </div>
              ) : null}
            </>
          ) : null}

          {phase === 'recv' && hasRecv ? (
            <>
              <StepHeader icon={FLOW_ICONS.scan} title={tr('edgeRecvTitle')}>
                <p className="sp-flow-step-lead">{tr(`edgeRecvIntro_${scenarioId}`)}</p>
              </StepHeader>
              {recvLoading ? <p className="sp-demo-running">{tr('flowScanRunning')}</p> : null}
              {recvError ? <p className="sp-demo-error">{recvError}</p> : null}
              {recvResult && !recvLoading ? (
                <div className="space-y-2">
                  <Verdict
                    ok={!!recvResult.test_passed}
                    okText={tr('flowVerifyOk')}
                    failText={tr('flowVerifyFail')}
                  />
                  {!recvResult.test_passed ? (
                    <Collapsible title={tr('flowVerifyFold')} nested>
                      <DemoRunResults tr={tr} testType="receive" testResults={recvResult} compact />
                    </Collapsible>
                  ) : null}
                </div>
              ) : null}
            </>
          ) : null}

          {phase === 'done' ? (
            <>
              <p className="text-[11px] leading-relaxed text-bp-700 dark:text-bp-canvas/85">{tr(`edgeDone_${scenarioId}`)}</p>
              <div className="flex flex-wrap gap-2 pt-1">
                {hasSend ? (
                  <span
                    className={`rounded-full px-2.5 py-1 text-[10px] font-bold ${sendOutcome.ok ? 'bg-bp-blue/10 text-bp-blue dark:bg-bp-canvas/15 dark:text-bp-canvas' : 'bg-red-50 text-red-800 dark:bg-red-950/40 dark:text-red-200'}`}
                  >
                    {tr('edgeChipSend')}: {sendOutcome.ok ? tr('passed') : tr('failed')}
                  </span>
                ) : null}
                {hasRecv ? (
                  <span
                    className={`rounded-full px-2.5 py-1 text-[10px] font-bold ${recvResult?.test_passed ? 'bg-bp-blue/10 text-bp-blue dark:bg-bp-canvas/15 dark:text-bp-canvas' : 'bg-red-50 text-red-800 dark:bg-red-950/40 dark:text-red-200'}`}
                  >
                    {tr('edgeChipRecv')}: {recvResult?.test_passed ? tr('passed') : tr('failed')}
                  </span>
                ) : null}
              </div>
            </>
          ) : null}
        </div>
      </article>

      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={goPrev}
          disabled={stepIndex <= 0}
          className="rounded-lg px-2 py-2 text-xs font-bold text-bp-blue underline underline-offset-2 disabled:opacity-35 dark:text-bp-canvas"
        >
          {tr('demoNavBack')}
        </button>
        {finished ? (
          <div className="ml-auto flex flex-1 flex-wrap justify-end gap-2 sm:flex-none">
            <button
              type="button"
              onClick={restartCase}
              className="min-w-[7.5rem] flex-1 rounded-[10px] border border-bp-blue/35 bg-transparent px-4 py-2.5 text-sm font-bold text-bp-blue dark:border-bp-canvas/35 dark:text-bp-canvas sm:flex-initial"
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
            onClick={() => primaryAction.run?.() ?? goNext()}
            className="ml-auto min-w-[10rem] flex-1 rounded-[10px] bg-bp-blue px-4 py-2.5 text-sm font-bold text-bp-canvas disabled:opacity-45 dark:bg-bp-canvas dark:text-bp-blue sm:flex-none"
          >
            {primaryAction.label}
          </button>
        )}
      </div>
    </div>
  )
}
