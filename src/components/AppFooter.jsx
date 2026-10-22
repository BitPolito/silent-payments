import { BRAND, ICON, SOCIAL } from '../assets/icons'
import BpIcon from './BpIcon'
import { useLocale } from '../i18n/useLocale'

const SOCIAL_LINKS = [
  { href: 'https://t.me/BitPolitoForum', icon: SOCIAL.telegram, label: 'Telegram' },
  { href: 'https://www.x.com/bitpolito', icon: SOCIAL.x, label: 'X' },
  { href: 'https://www.instagram.com/bitpolito/', icon: SOCIAL.instagram, label: 'Instagram' },
  { href: 'https://www.youtube.com/@BitPolito', icon: SOCIAL.youtube, label: 'YouTube' },
  { href: 'https://open.spotify.com/show/3xXqSrkyLloGhTozWMnuhH', icon: SOCIAL.spotify, label: 'Spotify' },
  { href: 'https://github.com/BitPolito', icon: SOCIAL.github, label: 'GitHub' },
  {
    href: 'https://www.linkedin.com/company/bitpolito/?originalSubdomain=it',
    icon: SOCIAL.linkedin,
    label: 'LinkedIn',
  },
]

const SOCIAL_LEFT = SOCIAL_LINKS.slice(0, 3)
const SOCIAL_RIGHT = SOCIAL_LINKS.slice(3)

const socialBtnClass =
  'inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-full border border-bp-200 bg-white shadow-xs transition hover:border-bp-400 hover:bg-bp-50 dark:border-bp-canvas/45 dark:bg-bp-canvas/15 dark:hover:border-bp-canvas dark:hover:bg-bp-canvas/25'

const socialIconSlotClass = 'inline-flex h-[18px] w-[18px] shrink-0 items-center justify-center'

const socialIconClass = 'sp-icon-blue block h-full w-full opacity-90'

function CircleLink({ href, label, children }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={label}
      aria-label={label}
      className={socialBtnClass}
    >
      {children}
    </a>
  )
}

function SocialLink({ href, icon, label }) {
  return (
    <CircleLink href={href} label={label}>
      <span className={socialIconSlotClass}>
        <img src={icon} alt="" className={socialIconClass} width={18} height={18} />
      </span>
    </CircleLink>
  )
}

export default function AppFooter() {
  const { tr } = useLocale()

  return (
    <footer className="site-footer">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="flex flex-col items-center gap-4">
          <div className="flex flex-col items-center gap-2">
            <img
              src={BRAND.cowBullBlue}
              alt=""
              className="h-12 w-auto max-w-[min(100%,240px)] object-contain opacity-90 dark:hidden sm:h-14"
              aria-hidden
            />
            <img
              src={BRAND.cowBullWhite}
              alt=""
              className="hidden h-12 w-auto max-w-[min(100%,240px)] object-contain opacity-95 dark:block sm:h-14"
              aria-hidden
            />
            <p className="inline-flex flex-wrap items-center justify-center gap-x-1.5 text-center text-sm font-semibold text-bp-blue dark:text-bp-canvas">
              <span>{tr('footerMadeWith')}</span>
              <BpIcon src={ICON.heart} className="h-[18px] w-[18px]" />
              <span className="whitespace-nowrap">{tr('footerBy')}</span>
            </p>
          </div>

          <nav className="flex flex-wrap items-center justify-center gap-2" aria-label={tr('uiSocial')}>
            {SOCIAL_LEFT.map((item) => (
              <SocialLink key={item.href} {...item} />
            ))}
            <CircleLink href="mailto:info@bitpolito.it" label="info@bitpolito.it">
              <BpIcon src={ICON.email} className="h-[18px] w-[18px]" />
            </CircleLink>
            {SOCIAL_RIGHT.map((item) => (
              <SocialLink key={item.href} {...item} />
            ))}
          </nav>

          <p className="text-center text-xs font-semibold text-bp-blue dark:text-bp-canvas">
            {tr('footerCopyright')}
          </p>
        </div>
      </div>
    </footer>
  )
}
