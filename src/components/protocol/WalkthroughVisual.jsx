import { STORY } from '../../assets/icons'
import { useLocale } from '../../i18n/useLocale'

/** Illustrates the current step; counts after execution come only from the API. */
export default function WalkthroughVisual({ phase, expectedCount, result }) {
  const { tr } = useLocale()
  return <figure className="sp-demo-visual" data-testid="demo-visual">
    <div className="sp-demo-journey" aria-hidden="true">
      <div className={phase === 'alice' || phase === 'derive' ? 'is-active' : ''}><img src={STORY.alice} className="sp-icon-blue" alt="" /><span>{tr('demoAlice')}</span></div>
      <span className="sp-demo-object">{phase === 'bob' ? '✉' : phase === 'alice' ? '₿' : phase === 'scan' && result?.test_passed ? '✓' : '→'}</span>
      <div className={phase === 'bob' || phase === 'scan' ? 'is-active' : ''}><img src={STORY.bob} className="sp-icon-blue" alt="" /><span>{tr('demoBob')}</span></div>
    </div>
    <figcaption><span>{tr('uiDemoIllustration')}</span></figcaption>
    {(phase === 'derive' || phase === 'scan') && <p className="sp-demo-expectation">{result
      ? tr(phase === 'derive' ? 'uiDemoCreated' : 'uiDemoFound').replace('{n}', result.outputs?.length || 0)
      : tr('uiDemoExpected').replace('{n}', expectedCount)}</p>}
  </figure>
}
