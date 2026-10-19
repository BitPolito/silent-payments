import AppLink from '../components/AppLink'
import { pageURL } from '../utils/navigation'
import { studioURL } from '../features/studio/navigation'
import { TOOLS } from '../features/studio/content'
import { useStudioText } from '../features/studio/useStudioText'
export default function HomePage({ headingRef }) {
  const t = useStudioText()
  return <>
    <section className="sp-studio-hero"><p className="sp-eyebrow">BitPolito · Silent Payments Studio</p><h1 ref={headingRef} tabIndex={-1}>{t.title}</h1><p className="sp-description">{t.intro}</p><AppLink href={studioURL().href} className="sp-btn-solid">{t.start} →</AppLink></section>
    <div className="sp-experiment-grid">{TOOLS.map((tool, index) => <AppLink className="sp-experiment-card" key={tool} href={studioURL(tool).href}><span className="sp-experiment-number" aria-hidden>0{index + 1} ↗</span><h2>{t[tool]}</h2><p className="sp-description">{t.objectives[tool]}</p></AppLink>)}</div>
    <section className="sp-studio-learning"><h2>{t.learning}</h2><div><AppLink href={pageURL('privacy').href}>{t.privacy} ↗</AppLink><AppLink href={pageURL('privacy').href + '#observer'}>{t.observer} ↗</AppLink><AppLink href={pageURL('walkthrough').href}>{t.guided} ↗</AppLink><AppLink href={pageURL('reference').href}>{t.reference} ↗</AppLink></div></section>
  </>
}
