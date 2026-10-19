import { useState } from 'react'
import { BRAND, ICON, STORY } from './assets/icons'
import { BITPOLITO_URL } from './config/site'
import ActionCard from './components/ActionCard'
import AppFooter from './components/AppFooter'
import BpIcon from './components/BpIcon'
import LangToggle from './components/LangToggle'
import ThemeToggle from './components/ThemeToggle'
import { useLocale } from './i18n/useLocale'
import GenerateAddrModal from './scenes/GenerateAddr'
import ProtocolDemoModal from './scenes/ProtocolDemo'

const BIP352_URL = 'https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki'

function StoryIcon({ src, className = 'h-4 w-4 shrink-0' }) {
  return <img src={src} alt="" className={`sp-icon-blue ${className}`} aria-hidden />
}

export default function App() {
  const { tr } = useLocale()
  const [showTests, setShowTests] = useState(false)
  const [showAddr, setShowAddr] = useState(false)
  const [addrTab, setAddrTab] = useState(/** @type {'random' | 'vanity'} */ ('random'))

  return (
    <div className="flex min-h-screen flex-col bg-bp-canvas font-sans text-bp-blue antialiased transition-colors duration-300 dark:bg-bp-blue dark:text-bp-canvas">
      <header className="sticky top-0 z-40 border-b border-bp-200 bg-bp-canvas/95 backdrop-blur-md dark:border-bp-500/35 dark:bg-bp-800/95">
        <div className="mx-auto flex max-w-3xl items-center justify-between gap-4 px-4 py-2.5 sm:px-6 sm:py-3">
          <div className="flex min-w-0 items-center gap-2.5 sm:gap-3">
            <a
              href={BITPOLITO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="shrink-0 rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-bp-blue dark:focus-visible:outline-bp-canvas"
              aria-label={tr('headerBitpolitoAria')}
            >
              <img
                src={BRAND.cowIconBlue}
                alt=""
                className="h-8 w-8 object-contain dark:hidden sm:h-9 sm:w-9"
                width={36}
                height={36}
              />
              <img
                src={BRAND.cowIconWhite}
                alt=""
                className="hidden h-8 w-8 object-contain dark:block sm:h-9 sm:w-9"
                width={36}
                height={36}
              />
            </a>
            <a
              href="/"
              className="whitespace-nowrap text-base font-bold leading-none tracking-tight text-bp-blue no-underline hover:no-underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-bp-blue dark:text-bp-canvas dark:focus-visible:outline-bp-canvas sm:text-lg"
            >
              {tr('title')}
            </a>
          </div>
          <div className="flex shrink-0 items-center gap-2 sm:gap-2.5">
            <LangToggle />
            <ThemeToggle ariaLabel={tr('themeAria')} />
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-8 sm:px-6 sm:py-10">
        <section className="sp-hero-panel mb-10">
          <p className="sp-hero-kicker">{tr('heroKicker')}</p>
          <h1 className="mt-2 text-3xl font-bold leading-[1.1] tracking-tight text-bp-blue dark:text-bp-canvas sm:text-4xl">
            {tr('title')}
          </h1>
          <p className="mt-3 max-w-prose text-base leading-relaxed text-bp-blue/85 dark:text-bp-canvas/90">
            {tr('heroSubtitle')}
          </p>
          <p className="mt-2 text-xs leading-relaxed text-bp-blue/60 dark:text-bp-canvas/65">{tr('subtitle')}</p>
          <div className="mt-5 flex flex-wrap gap-2">
            <a
              href={BIP352_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="sp-btn-solid inline-flex items-center gap-2 text-sm"
            >
              <BpIcon src={STORY.share} className="h-4 w-4 shrink-0 text-inherit" />
              {tr('bipCta')}
            </a>
            <a
              href={BITPOLITO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="sp-btn-solid inline-flex items-center gap-2 text-sm"
            >
              <img src={BRAND.cowIconWhite} alt="" className="h-4 w-4 shrink-0 object-contain dark:hidden" aria-hidden />
              <img src={BRAND.cowIconBlue} alt="" className="hidden h-4 w-4 shrink-0 object-contain dark:block" aria-hidden />
              {tr('bitpolitoCta')}
            </a>
          </div>
        </section>

        <section>
          <h2 className="sp-section-label">{tr('toolsHeading')}</h2>
          <div className="flex flex-col gap-2">
            <ActionCard
              title={tr('cardTests')}
              description={tr('cardTestsDesc')}
              onClick={() => setShowTests(true)}
              icon={<StoryIcon src={STORY.donation} className="h-5 w-5" />}
            />
            <ActionCard
              title={tr('cardGen')}
              description={tr('cardGenDesc')}
              onClick={() => {
                setAddrTab('random')
                setShowAddr(true)
              }}
              icon={<BpIcon src={ICON.key} className="h-5 w-5 text-inherit" />}
            />
            <ActionCard
              title={tr('cardVanity')}
              description={tr('cardVanityDesc')}
              onClick={() => {
                setAddrTab('vanity')
                setShowAddr(true)
              }}
              icon={<BpIcon src={ICON.crown} className="h-5 w-5 text-inherit" />}
            />
          </div>
        </section>
      </main>

      <AppFooter />

      {showTests && <ProtocolDemoModal
        open={showTests}
        onClose={() => {
          setShowTests(false)
          window.scrollTo({ top: 0, behavior: 'smooth' })
        }}
      />}
      {showAddr && <GenerateAddrModal open={showAddr} onClose={() => setShowAddr(false)} initialTab={addrTab} />}
    </div>
  )
}
