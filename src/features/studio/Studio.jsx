import { visualContent } from './visualContent'
import { useState } from 'react'
import AppLink from '../../components/AppLink'
import { useLocale } from '../../i18n/useLocale'
import { pageURL } from '../../utils/navigation'
import { studioSelection, studioURL } from './navigation'
import { TOOLS } from './content'
import PaymentExperiment from './PaymentExperiment'
import AddressExperiment from './AddressExperiment'
import LabelScanExperiment from './LabelScanExperiment'
import { useStudioText } from './useStudioText'
export default function Studio({ headingRef, search }) {
  const t = useStudioText()
  const { tr, locale } = useLocale()
  const v = visualContent[locale] || visualContent.en
  const selection = studioSelection(search)
  const [copied, setCopied] = useState('')
  return <>
    <div className="sp-page-header"><div><AppLink className="sp-back-link" href={pageURL('home').href}>← {tr('uiBackHome')}</AppLink><h1 ref={headingRef} tabIndex={-1}>{t[selection.tool]}</h1><p>{t.objectives[selection.tool]}</p></div><button className="sp-btn-outline" onClick={async () => { try { await navigator.clipboard.writeText(studioURL(selection.tool, selection.preset).href); setCopied(t.copied) } catch { setCopied(t.copyFailed) } }}>{t.share}</button></div>
    {copied && <p role="status">{copied}</p>}{selection.invalid && <p role="alert">{t.missing}</p>}
    <nav className="sp-studio-tabs" aria-label={t.select}>{TOOLS.map((tool) => <AppLink key={tool} href={studioURL(tool).href} aria-current={tool === selection.tool ? 'page' : undefined}>{t[tool]}</AppLink>)}</nav>
    <p className="sp-experiment-notice">{v.demo}</p>{selection.tool === 'payment' ? <PaymentExperiment preset={selection.preset} /> : selection.tool === 'address' ? <AddressExperiment /> : <LabelScanExperiment tool={selection.tool} />}
  </>
}
