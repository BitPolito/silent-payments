import { useEffect, useState } from 'react'
import { STORY } from '../assets/icons'
import AppLink from '../components/AppLink'
import { useLocale } from '../i18n/useLocale'
import { useApiOnline } from '../hooks/useApiOnline'
import { EDGE_SCENARIOS } from '../utils/demoScenarios'
import { fetchApi, formatApiError } from '../utils/api'
import { navigateTo, pageURL } from '../utils/navigation'
import { referenceURL } from '../utils/referenceLinks'
import EdgeScenarioFlow from './EdgeScenarioFlow'
import PaymentFlow from './PaymentFlow'
import ReferenceCases from './ReferenceCases'

export default function LearningPage({ view, initialSearch, headingRef }) {
  const { tr } = useLocale()
  const [screen, setScreen] = useState('flow')
  const [scenarioId, setScenarioId] = useState(null)
  const [caseData, setCaseData] = useState(null)
  const [error, setError] = useState(null)
  const isWalkthrough = view === 'walkthrough'
  const apiStatus = useApiOnline(isWalkthrough && screen !== 'edges')
  useEffect(() => {
    if (!isWalkthrough || screen !== 'detail' || !scenarioId) return
    const scenario = EDGE_SCENARIOS.find((item) => item.id === scenarioId)
    const controller = new AbortController()
    fetchApi(`/api/test_case/${scenario.testId}`, { signal: controller.signal })
      .then((data) => { if (!controller.signal.aborted) setCaseData({ ...data, scenarioId }) })
      .catch((err) => { if (!controller.signal.aborted) setError(err) })
    return () => controller.abort()
  }, [isWalkthrough, screen, scenarioId])
  const scenario = EDGE_SCENARIOS.find((item) => item.id === scenarioId)
  const goHome = () => navigateTo(pageURL('home').href)
  return <>
    <div className="sp-page-header">
      <div>
        <AppLink className="sp-back-link" href={pageURL('home').href}>← {tr('uiBackHome')}</AppLink>
        <h1 ref={headingRef} tabIndex={-1}>{tr(isWalkthrough ? 'demoTitle' : 'referenceTitle')}</h1>
        <p className="sp-description">{tr(isWalkthrough ? 'uiWalkthroughIntro' : 'uiReferenceIntro')}</p>
      </div>
      <span className="sp-page-badge">BIP-352 · {tr('uiDemoOnly')}</span>
    </div>
    <nav className="sp-learning-nav" aria-label={tr('uiLearningNav')}>
      <AppLink href={pageURL('walkthrough').href} aria-current={isWalkthrough ? 'page' : undefined}>{tr('demoTitle')}</AppLink>
      <AppLink href={pageURL('reference').href} aria-current={!isWalkthrough ? 'page' : undefined}>{tr('referenceTitle')}</AppLink>
    </nav>
    {!isWalkthrough ? <ReferenceCases initialSearch={initialSearch} /> : <>
      {apiStatus === 'offline' && screen !== 'edges' ? <p role="alert" className="sp-notice">{tr(import.meta.env.PROD ? 'apiOfflineProd' : 'apiOffline')}</p> : <>
        {screen === 'flow' && <PaymentFlow onOpenEdgeCases={() => setScreen('edges')} onCloseHome={goHome} onOpenReference={(selection) => navigateTo(referenceURL(selection).href)} />}
        {screen === 'edges' && <section className="sp-edge-page space-y-4">
          <button className="sp-back-link" onClick={() => setScreen('flow')}>← {tr('flowBackToWalkthrough')}</button>
          <h2 className="text-2xl font-bold">{tr('flowEdgeTitle')}</h2>
          <p className="sp-description">{tr('demoIntro')}</p>
          <ul className="grid gap-4 sm:grid-cols-2">{EDGE_SCENARIOS.map((item) => <li key={item.id}>
            <button type="button" className="sp-surface flex h-full w-full items-start gap-4 rounded-xl p-5 text-left" onClick={() => { setCaseData(null); setError(null); setScenarioId(item.id); setScreen('detail') }}>
              <img src={item.id === 'zero_sum' ? STORY.key : STORY.wallet} alt="" className="sp-icon-blue h-8 w-8" />
              <span><strong className="block">{tr(`edgeCard_${item.id}_title`)}</strong><span className="sp-description mt-2 block text-sm">{tr(`edgeCard_${item.id}_desc`)}</span></span>
            </button>
          </li>)}</ul>
        </section>}
        {screen === 'detail' && (error ? <p className="sp-notice" role="alert">{formatApiError(error, tr)}</p> : !caseData ? <p role="status">{tr('loadingScenario')}</p> : <EdgeScenarioFlow key={scenario.id} caseData={{ ...caseData, title: tr(`edgeCard_${scenario.id}_title`) }} scenarioId={scenario.id} testId={scenario.testId} onBack={() => setScreen('edges')} onCloseHome={goHome} />)}
      </>}
    </>}
  </>
}
