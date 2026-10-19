import { useEffect, useState } from 'react'
import { STORY } from '../assets/icons'
import ModalShell from '../components/ModalShell'
import { useLocale } from '../i18n/useLocale'
import { useApiOnline } from '../hooks/useApiOnline'
import { EDGE_SCENARIOS } from '../utils/demoScenarios'
import { fetchApi, formatApiError } from '../utils/api'
import EdgeScenarioFlow from './EdgeScenarioFlow'
import PaymentFlow from './PaymentFlow'
import ReferenceCases from './ReferenceCases'

const SCENARIO_ICONS = {
  no_outputs: STORY.wallet,
  zero_sum: STORY.key,
}

const alertIcon = '/bitpolito/alert.svg'

export default function ProtocolDemoModal({ open, onClose }) {
  const { tr } = useLocale()
  const [view, setView] = useState('flow')
  const [selectedScenarioId, setSelectedScenarioId] = useState(/** @type {string | null} */ (null))
  const [caseData, setCaseData] = useState(null)
  const [caseLoading, setCaseLoading] = useState(false)
  const [caseError, setCaseError] = useState('')
  const apiStatus = useApiOnline(open && (view === 'detail' || view === 'flow'))

  useEffect(() => {
    if (!open || !selectedScenarioId || view !== 'detail') return
    const scenario = EDGE_SCENARIOS.find((s) => s.id === selectedScenarioId)
    if (!scenario) return

    const ac = new AbortController()
    fetchApi(`/api/test_case/${scenario.testId}`, { signal: ac.signal })
      .then((data) => ({
        ...data,
        title: tr(`edgeCard_${scenario.id}_title`),
        scenarioId: scenario.id,
      }))
      .then((data) => { if (!ac.signal.aborted) setCaseData(data) })
      .catch((e) => {
        if (e.name !== 'AbortError') setCaseError(formatApiError(e, tr))
      })
      .finally(() => {
        if (!ac.signal.aborted) setCaseLoading(false)
      })
    return () => ac.abort()
  }, [open, selectedScenarioId, view, tr])

  const openScenario = (scenarioId) => {
    setCaseLoading(true)
    setCaseError('')
    setCaseData(null)
    setSelectedScenarioId(scenarioId)
    setView('detail')
  }

  const selectedScenario = EDGE_SCENARIOS.find((s) => s.id === selectedScenarioId)

  const modalTitle =
    view === 'reference' ? tr('referenceTitle') : view === 'flow' ? tr('demoTitle') : view === 'edges' ? tr('flowEdgeTitle') : tr('demoDetailTitle')
  const modalSubtitle =
    view === 'flow'
      ? tr('demoSubtitle')
      : view === 'edges'
        ? tr('flowEdgeSubtitle')
        : selectedScenario
          ? tr(`edgeCard_${selectedScenario.id}_title`)
          : ''

  return (
    <ModalShell
      open={open}
      onClose={onClose}
      title={modalTitle}
      subtitle={modalSubtitle}
      closeLabel={tr('close')}
    >
      <nav className="mb-4 flex gap-4 text-sm"><button onClick={() => setView('flow')}>{tr('demoTitle')}</button><button onClick={() => setView('reference')}>{tr('referenceTitle')}</button></nav>
      {view === 'reference' && <ReferenceCases />}
      {view === 'flow' ? (
        apiStatus === 'offline' ? (
          <div className="flex items-center gap-3 rounded-lg border border-bp-200 bg-bp-50 p-4 dark:border-bp-500/40 dark:bg-bp-700/40">
            <img src={alertIcon} alt="" className="sp-icon-blue h-8 w-8 shrink-0" />
            <p className="text-sm font-medium text-bp-blue dark:text-bp-canvas">
              {tr(import.meta.env.PROD ? 'apiOfflineProd' : 'apiOffline')}
            </p>
          </div>
        ) : (
          <PaymentFlow
            onOpenEdgeCases={() => setView('edges')}
            onCloseHome={onClose}
          />
        )
      ) : null}

      {view === 'edges' ? (
        <div className="flex flex-col gap-3">
          <button
            type="button"
            onClick={() => setView('flow')}
            className="self-start text-sm font-bold text-bp-blue underline underline-offset-2 dark:text-bp-canvas"
          >
            ← {tr('flowBackToWalkthrough')}
          </button>
          <p className="text-xs leading-relaxed text-bp-600 dark:text-bp-canvas/75">{tr('demoIntro')}</p>
          <ul className="space-y-2">
            {EDGE_SCENARIOS.map((scenario) => (
              <li key={scenario.id}>
                <button
                  type="button"
                  onClick={() => openScenario(scenario.id)}
                  className="sp-surface group flex w-full items-start gap-3 rounded-xl px-3 py-3 text-left transition hover:border-bp-blue/30 dark:hover:border-bp-canvas/45"
                >
                  <img
                    src={SCENARIO_ICONS[scenario.id] ?? STORY.wallet}
                    alt=""
                    className="sp-icon-blue mt-0.5 h-8 w-8 shrink-0"
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block text-sm font-bold text-bp-blue dark:text-bp-canvas">
                      {tr(`edgeCard_${scenario.id}_title`)}
                    </span>
                    <span className="mt-0.5 block text-xs text-bp-600 dark:text-bp-canvas/75">
                      {tr(`edgeCard_${scenario.id}_desc`)}
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {view === 'detail' ? (
        apiStatus === 'offline' ? (
          <div className="flex items-center gap-3 rounded-lg border border-bp-200 bg-bp-50 p-4 dark:border-bp-500/40 dark:bg-bp-700/40">
            <img src={alertIcon} alt="" className="sp-icon-blue h-8 w-8 shrink-0" />
            <p className="text-sm font-medium text-bp-blue dark:text-bp-canvas">
              {tr(import.meta.env.PROD ? 'apiOfflineProd' : 'apiOffline')}
            </p>
          </div>
        ) : caseLoading ? (
          <p className="text-sm text-bp-600 dark:text-bp-canvas/80">{tr('loadingScenario')}</p>
        ) : caseError ? (
          <div className="flex items-center gap-3 rounded-lg border border-dashed border-bp-400 bg-bp-100 p-4 dark:bg-bp-700/35">
            <img src={alertIcon} alt="" className="sp-icon-blue h-8 w-8" />
            <p className="text-sm font-bold text-bp-blue dark:text-bp-canvas">{caseError}</p>
          </div>
        ) : caseData && selectedScenario ? (
          <EdgeScenarioFlow
            key={selectedScenario.id}
            caseData={caseData}
            scenarioId={selectedScenario.id}
            testId={selectedScenario.testId}
            onBack={() => {
              setView('edges')
              setSelectedScenarioId(null)
              setCaseData(null)
            }}
            onCloseHome={onClose}
          />
        ) : null
      ) : null}
    </ModalShell>
  )
}
