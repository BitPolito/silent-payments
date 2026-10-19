import { useLocale } from '../i18n/useLocale'

export default function LangToggle() {
  const { locale, setLocale, tr } = useLocale()
  const toggle = () => setLocale(locale === 'en' ? 'it' : 'en')

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={tr('langToggleAria')}
      className="sp-language-control"
    >
      <span
        className={`flex min-h-[36px] min-w-[36px] items-center justify-center rounded-full px-2 py-1.5 text-center text-sm font-semibold leading-none transition ${
          locale === 'it'
            ? 'bg-bp-blue text-bp-canvas shadow-sm dark:bg-bp-canvas dark:text-bp-blue'
            : 'text-bp-600 dark:text-bp-200'
        }`}
      >
        {tr('langIt')}
      </span>
      <span
        className={`flex min-h-[36px] min-w-[36px] items-center justify-center rounded-full px-2 py-1.5 text-center text-sm font-semibold leading-none transition ${
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
