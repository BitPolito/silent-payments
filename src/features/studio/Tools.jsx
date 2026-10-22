import { ICON, STORY } from '../../assets/icons'
import AppLink from '../../components/AppLink'
import BpIcon from '../../components/BpIcon'
import { useLocale } from '../../i18n/useLocale'
import { pageURL } from '../../utils/navigation'
import { useStudioText } from './useStudioText'

export default function Tools({ headingRef, onGenerate }) {
  const { tr } = useLocale()
  const t = useStudioText()
  return <div className="sp-tools-page">
    <div className="sp-page-header">
      <div>
        <AppLink className="sp-back-link" href={pageURL('home').href}>← {tr('uiBackHome')}</AppLink>
        <h1 ref={headingRef} tabIndex={-1}>{t.tools}</h1>
        <p className="sp-description">{tr('uiToolsLead')}</p>
      </div>
    </div>
    <div className="sp-tools-grid">
      {[['random', ICON.key, 'cardGen', 'uiToolsRandom', 'uiToolsRandomAction'], ['vanity', STORY.letter, 'cardVanity', 'uiToolsVanity', 'uiToolsVanityAction']].map(([mode, icon, title, description, action]) => <section className="sp-card sp-tool-card" key={mode}>
        <div className="sp-tool-art" aria-hidden="true"><BpIcon src={icon} className="h-12 w-12" /></div>
        <h2>{tr(title)}</h2>
        <p className="sp-description">{tr(description)}</p>
        <button type="button" className={mode === 'random' ? 'sp-btn-solid' : 'sp-btn-outline'} aria-label={`${tr(title)} · ${tr(action)}`} onClick={() => onGenerate(mode)}>{tr(action)} <BpIcon src={STORY.arrow} className="h-4 w-5" /></button>
      </section>)}
    </div>
    <p className="sp-notice sp-tools-notice">{tr('uiToolsNotice')}</p>
  </div>
}
