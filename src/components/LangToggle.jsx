import { useLocale } from '../i18n/LocaleContext'

export default function LangToggle() {
  const { locale, setLocale, tr } = useLocale()
  const toggle = () => setLocale(locale === 'en' ? 'it' : 'en')

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={tr('langToggleAria')}
      className="flex cursor-pointer select-none overflow-hidden rounded-full border border-bp-200 bg-bp-canvas p-0.5 shadow-sm transition hover:border-bp-300 dark:border-bp-500/45 dark:bg-bp-800/80 dark:hover:border-bp-400/60"
    >
      <span
        className={`flex min-w-[44px] items-center justify-center rounded-full px-3 py-1.5 text-center text-sm font-semibold leading-none transition ${
          locale === 'it'
            ? 'bg-bp-blue text-bp-canvas shadow-sm dark:bg-bp-canvas dark:text-bp-blue'
            : 'text-bp-600 dark:text-bp-200'
        }`}
      >
        {tr('langIt')}
      </span>
      <span
        className={`flex min-w-[44px] items-center justify-center rounded-full px-3 py-1.5 text-center text-sm font-semibold leading-none transition ${
          locale === 'en'
            ? 'bg-bp-blue text-bp-canvas shadow-sm dark:bg-bp-canvas dark:text-bp-blue'
            : 'text-bp-600 dark:text-bp-200'
        }`}
      >
        {tr('langEn')}
      </span>
    </button>
  )
}
