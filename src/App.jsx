import { useEffect, useRef, useState } from 'react'
import { BRAND } from './assets/icons'
import { BITPOLITO_URL } from './config/site'
import AppFooter from './components/AppFooter'
import AppLink from './components/AppLink'
import LangToggle from './components/LangToggle'
import ThemeToggle from './components/ThemeToggle'
import { useLocale } from './i18n/useLocale'
import GenerateAddrModal from './scenes/GenerateAddr'
import LearningPage from './scenes/LearningPage'
import HomePage from './scenes/HomePage'
import { currentView, pageURL } from './utils/navigation'

export default function App() {
  const { tr } = useLocale()
  const [search, setSearch] = useState(() => window.location.search)
  const [generator, setGenerator] = useState(null)
  const headingRef = useRef(null)
  const view = currentView(search)
  useEffect(() => {
    const followURL = () => { setGenerator(null); setSearch(window.location.search) }
    window.addEventListener('popstate', followURL)
    window.addEventListener('sp:navigate', followURL)
    return () => {
      window.removeEventListener('popstate', followURL)
      window.removeEventListener('sp:navigate', followURL)
    }
  }, [])
  useEffect(() => {
    headingRef.current?.focus({ preventScroll: true })
    window.scrollTo({ top: 0, behavior: 'auto' })
  }, [search])
  useEffect(() => {
    document.title = `${view === 'home' ? tr('title') : tr(view === 'walkthrough' ? 'demoTitle' : 'referenceTitle')} · BitPolito`
  }, [view, tr])
  return <div className="sp-app">
    <a className="sp-skip-link" href="#main-content">{tr('uiSkip')}</a>
    <header className="sp-site-header">
      <div className="sp-header-inner">
        <AppLink href={pageURL('home').href} className="sp-brand" aria-label={`${tr('title')} · ${tr('uiHome')}`}>
          <img src={BRAND.cowIconBlue} alt="" className="sp-icon-blue h-8 w-8" width={32} height={32} />
          <span>{tr('title')}</span>
        </AppLink>
        <nav className="sp-primary-nav" aria-label={tr('uiMainNav')}>
          {[['home', 'uiHome'], ['walkthrough', 'uiLearn'], ['reference', 'uiReference']].map(([target, label]) => <AppLink key={target} href={pageURL(target).href} aria-current={view === target ? 'page' : undefined}>{tr(label)}</AppLink>)}
        </nav>
        <div className="sp-header-controls"><LangToggle /><ThemeToggle ariaLabel={tr('themeAria')} /></div>
      </div>
    </header>
    <main id="main-content" tabIndex={-1} className={`sp-main ${view === 'home' ? '' : 'sp-learning-page'}`}>
      {view === 'home'
        ? <HomePage headingRef={headingRef} onGenerate={setGenerator} />
        : <LearningPage key={search} view={view} initialSearch={search} headingRef={headingRef} />}
    </main>
    <div className="sp-resource-links"><a href="https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki" target="_blank" rel="noopener noreferrer">{tr('bipCta')} ↗</a><a href={BITPOLITO_URL} target="_blank" rel="noopener noreferrer">bitpolito.it ↗</a></div>
    <AppFooter />
    {generator && <GenerateAddrModal open onClose={() => setGenerator(null)} initialTab={generator} />}
  </div>
}
