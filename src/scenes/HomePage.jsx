import { BRAND, ICON, STORY } from '../assets/icons'
import { useLocale } from '../i18n/useLocale'
import { pageURL } from '../utils/navigation'
import ActionCard from '../components/ActionCard'
import AppLink from '../components/AppLink'
import BpIcon from '../components/BpIcon'

export default function HomePage({ onGenerate, headingRef }) {
  const { tr } = useLocale()
  return <>
    <section className="sp-home-hero">
      <div className="sp-home-intro">
        <p className="sp-eyebrow">{tr('heroKicker')}</p>
        <h1 ref={headingRef} tabIndex={-1} className="sp-hero-title">{tr('uiHeroTitle')}</h1>
        <p className="sp-lead">{tr('uiHeroLead')}</p>
        <div className="sp-hero-actions">
          <AppLink href={pageURL('walkthrough').href} className="sp-btn-solid">{tr('cardTests')} <span aria-hidden>→</span></AppLink>
          <AppLink href={pageURL('reference').href} className="sp-btn-outline">{tr('referenceTitle')}</AppLink>
        </div>
        <p className="sp-description mt-3 text-sm">{tr('uiGuideHint')}</p>
        <div className="sp-home-facts"><span>{tr('uiExamples')}</span><span>{tr('uiLanguages')}</span><span>{tr('uiDemoOnly')}</span></div>
      </div>
      <figure className="sp-story-preview">
        <figcaption className="sp-eyebrow">{tr('uiStory')}</figcaption>
        <svg className="sp-payment-graphic" viewBox="0 0 440 140" fill="none" aria-hidden="true" focusable="false">
          <g stroke="#f9f9f9" strokeWidth="2">
            <path d="M80 70H170C215 70 210 28 260 28H346M170 70H346M170 70C215 70 210 112 260 112H346" />
            <circle cx="80" cy="70" r="26" fill="#001ce0" />
            <path d="M69 70l8 8 15-16" strokeWidth="3" />
          </g>
          <g fill="#f9f9f9" stroke="#001ce0" strokeWidth="2">
            <rect x="330" y="12" width="32" height="32" rx="8" />
            <rect x="330" y="54" width="32" height="32" rx="8" />
            <rect x="330" y="96" width="32" height="32" rx="8" />
            <circle cx="170" cy="70" r="5" />
          </g>
          <g fill="#001ce0"><circle cx="346" cy="28" r="4" /><circle cx="346" cy="70" r="4" /><circle cx="346" cy="112" r="4" /></g>
        </svg>
        {[[STORY.bob, 'uiStoryAddress', 'uiStoryAddressHint'], [STORY.alice, 'uiStoryPayment', 'uiStoryPaymentHint'], [STORY.wallet, 'uiStoryReceive', 'uiStoryReceiveHint']].map(([icon, title, hint], index) => <div className="sp-story-preview-step" key={title}>
          <span className="sp-story-preview-number" aria-hidden>{index + 1}</span>
          <img src={icon} alt="" className="sp-icon-blue h-9 w-9" />
          <div><p className="font-bold">{tr(title)}</p><p className="sp-description mt-1 text-sm">{tr(hint)}</p></div>
        </div>)}
        <div className="sp-story-preview-brand"><img src={BRAND.cowIconBlue} alt="" className="sp-icon-blue h-5 w-5" /><span>{tr('uiHeroNote')}</span></div>
      </figure>
    </section>
    <section className="sp-home-tools" aria-labelledby="tools-heading">
      <div className="mb-5"><h2 id="tools-heading" className="text-2xl font-bold">{tr('toolsHeading')}</h2><p className="sp-description mt-2">{tr('uiToolsLead')}</p></div>
      <div className="grid gap-4 sm:grid-cols-2">
        <ActionCard title={tr('cardGen')} description={tr('cardGenDesc')} onClick={() => onGenerate('random')} icon={<BpIcon src={ICON.key} className="h-6 w-6" />} />
        <ActionCard title={tr('cardVanity')} description={tr('cardVanityDesc')} onClick={() => onGenerate('vanity')} icon={<BpIcon src={ICON.crown} className="h-6 w-6" />} />
      </div>
    </section>
  </>
}
