import { useLocale } from '../i18n/useLocale'

export default function LangToggle() {
  const { locale, setLocale, tr } = useLocale()
  return <button type="button" onClick={() => setLocale(locale === 'en' ? 'it' : 'en')} aria-label={tr('langToggleAria')} className="sp-header-control sp-language-control">
    <span className="sp-language-track">{['it', 'en'].map(language => <span key={language} className={locale === language ? 'is-selected' : undefined}>{tr(language === 'it' ? 'langIt' : 'langEn')}</span>)}</span>
  </button>
}
