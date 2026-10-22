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
import PrivacyLab from './features/privacy/PrivacyLab'
import Studio from './features/studio/Studio'
import Tools from './features/studio/Tools'
import { useStudioText } from './features/studio/useStudioText'
import HomePage from './scenes/HomePage'
import { currentView, pageURL } from './utils/navigation'

export default function App() {
  const { tr } = useLocale()
  const t = useStudioText()
  const [search, setSearch] = useState(() => window.location.search)
  const [generator, setGenerator] = useState(null)
  const headingRef = useRef(null)
  const headerRef = useRef(null)
  const view = currentView(search)
  useEffect(() => {
    const header = headerRef.current
    const updateHeight = () => document.documentElement.style.setProperty('--sp-header-height', `${header.getBoundingClientRect().height}px`)
    const observer = new ResizeObserver(updateHeight)
    observer.observe(header)
    updateHeight()
    return () => {
      observer.disconnect()
      document.documentElement.style.removeProperty('--sp-header-height')
    }
  }, [])
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
    document.title = `${view === 'home' ? tr('title') : view === 'studio' ? t.explore : view === 'tools' ? t.tools : tr(view === 'privacy' ? 'uiPrivacy' : view === 'walkthrough' ? 'demoTitle' : 'referenceTitle')} · BitPolito`
  }, [view, tr, t])
  return <div className="sp-app">
    <a className="sp-skip-link" href="#main-content">{tr('uiSkip')}</a>
    <header ref={headerRef} className="sp-site-header">
      <div className="sp-header-inner">
        <AppLink href={pageURL('home').href} className="sp-brand" aria-label={`${tr('title')} · ${tr('uiHome')}`}>
          <img src={BRAND.cowIconBlue} alt="" className="sp-icon-blue h-8 w-8" width={32} height={32} />
          <span>{tr('title')}</span>
        </AppLink>
        <nav className="sp-primary-nav" aria-label={tr('uiMainNav')}>
          {[['home', tr('uiHome')], ['walkthrough', tr('uiDemoNav')], ['reference', t.referenceNav], ['tools', t.tools]].map(([target, label]) => <AppLink key={target} href={pageURL(target).href} aria-current={(view === target || (target === 'home' && ['studio', 'privacy'].includes(view))) ? 'page' : undefined}>{label}</AppLink>)}
        </nav>
        <div className="sp-header-controls"><LangToggle /><ThemeToggle ariaLabel={tr('themeAria')} /></div>
      </div>
    </header>
    <main id="main-content" tabIndex={-1} className={`sp-main ${view === 'home' ? '' : 'sp-learning-page'} ${view === 'walkthrough' ? 'sp-walkthrough-page' : ''}`}>
      {view === 'home'
        ? <HomePage headingRef={headingRef} onGenerate={setGenerator} />
        : view === 'studio' ? <Studio key={search} search={search} headingRef={headingRef} /> : view === 'tools' ? <Tools headingRef={headingRef} onGenerate={setGenerator} /> : view === 'privacy' ? <PrivacyLab headingRef={headingRef} /> : <LearningPage key={search} view={view} initialSearch={search} headingRef={headingRef} />}
    </main>
    <div className="sp-resource-links"><a href="https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki" target="_blank" rel="noopener noreferrer">{tr('bipCta')} ↗</a><a href={BITPOLITO_URL} target="_blank" rel="noopener noreferrer">bitpolito.it ↗</a></div>
    <AppFooter />
    {generator && <GenerateAddrModal open onClose={() => setGenerator(null)} initialTab={generator} />}
  </div>
}
