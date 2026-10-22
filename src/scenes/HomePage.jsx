import { STORY } from '../assets/icons'
import AppLink from '../components/AppLink'
import { useLocale } from '../i18n/useLocale'
import { pageURL } from '../utils/navigation'
import { studioURL } from '../features/studio/navigation'
import { TOOLS } from '../features/studio/content'
import { useStudioText } from '../features/studio/useStudioText'

export default function HomePage({ headingRef, onGenerate }) {
  const { tr } = useLocale()
  const experiments = useStudioText()
  const observerURL = pageURL('privacy'); observerURL.hash = 'observer'
  return <div className="sp-simple-home">
    <section className="sp-simple-intro">
      <p className="sp-eyebrow">BitPolito · BIP-352</p>
      <h1 ref={headingRef} tabIndex={-1}>{tr('title')}</h1>
      <p className="sp-lead">{tr('uiSimpleIntro')}</p>
    </section>
    <div className="sp-home-essentials">
      <section className="sp-home-demo">
        <div className="sp-home-actors" aria-hidden="true"><img className="sp-icon-blue" src={STORY.alice} alt="" /><span>→</span><img className="sp-icon-blue" src={STORY.bob} alt="" /></div>
        <h2>{tr('uiTryDemo')}</h2>
        <p className="sp-description">{tr('uiGuideHint')}</p>
        <AppLink href={pageURL('walkthrough').href} className="sp-btn-solid">{tr('demoTitle')} →</AppLink>
      </section>
      <section className="sp-home-utility">
        <img src={STORY.key} className="sp-icon-blue" alt="" />
        <h2>{tr('uiAddressTools')}</h2>
        <p className="sp-description">{tr('uiSimpleTools')}</p>
        <div className="sp-home-card-actions"><button className="sp-btn-outline" onClick={() => onGenerate('random')}>{tr('cardGen')}</button><button className="sp-back-link" onClick={() => onGenerate('vanity')}>{tr('cardVanity')} →</button></div>
      </section>
      <section className="sp-home-utility">
        <img src={STORY.wallet} className="sp-icon-blue" alt="" />
        <h2>{tr('uiReference')}</h2>
        <p className="sp-description">{tr('uiSimpleReferences')}</p>
        <AppLink href={pageURL('reference').href} className="sp-btn-outline">{tr('referenceTitle')} →</AppLink>
      </section>
    </div>
    <p className="sp-home-note">{tr('uiSimpleNotice')}</p>
    <details className="sp-home-extras">
      <summary>{tr('uiMoreExperiments')}</summary>
      <div><AppLink href={pageURL('privacy').href}>{experiments.privacy} ↗</AppLink><AppLink href={observerURL.href}>{experiments.observer} ↗</AppLink>{TOOLS.map((tool) => <AppLink key={tool} href={studioURL(tool).href}>{experiments[tool]} ↗</AppLink>)}</div>
    </details>
  </div>
}
