import { useLocale } from '../../i18n/useLocale'
import ActionCard from '../../components/ActionCard'
import { useStudioText } from './useStudioText'
export default function Tools({ headingRef, onGenerate }) {
  const { tr } = useLocale(); const t = useStudioText()
  return <><div className="sp-page-header"><div><h1 ref={headingRef} tabIndex={-1}>{t.tools}</h1><p>{tr('uiToolsLead')}</p></div></div><div className="grid gap-4 sm:grid-cols-2"><ActionCard title={tr('cardGen')} description={tr('cardGenDesc')} onClick={() => onGenerate('random')} /><ActionCard title={tr('cardVanity')} description={tr('cardVanityDesc')} onClick={() => onGenerate('vanity')} /></div></>
}
