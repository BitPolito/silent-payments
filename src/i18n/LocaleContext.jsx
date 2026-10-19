import { useCallback, useEffect, useMemo, useState } from 'react'
import { t } from './strings'

/** @typedef {import('./strings').Locale} Locale */

import { LocaleContext } from './useLocale'

export function LocaleProvider({ children }) {
  const [locale, setLocaleState] = useState(
    /** @type {Locale} */ (
      typeof localStorage !== 'undefined' && localStorage.getItem('sp-locale') === 'it'
        ? 'it'
        : 'en'
    ),
  )

  const setLocale = useCallback((/** @type {Locale} */ next) => {
    setLocaleState(next)
    localStorage.setItem('sp-locale', next)
  }, [])

  const tr = useCallback((key) => t(locale, key), [locale])

  useEffect(() => {
    document.documentElement.lang = locale
  }, [locale])

  const value = useMemo(() => ({ locale, setLocale, tr }), [locale, setLocale, tr])

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>
}
