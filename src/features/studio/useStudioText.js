import { useLocale } from '../../i18n/useLocale'
import { studioContent } from './content'
export function useStudioText() { const { locale } = useLocale(); return studioContent[locale] || studioContent.en }
