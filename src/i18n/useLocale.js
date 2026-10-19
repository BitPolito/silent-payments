import { createContext, useContext } from 'react'
export const LocaleContext = createContext({ locale: 'en', setLocale: () => {}, tr: (key) => key })
export function useLocale() { return useContext(LocaleContext) }
