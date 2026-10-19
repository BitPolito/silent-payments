import { pageURL } from '../../utils/navigation'
import { PRESETS, TOOLS } from './content'
export function studioSelection(search) {
  const params = new URLSearchParams(search)
  const tool = params.get('tool') || 'payment'
  const preset = params.get('preset') || 'default'
  const valid = params.getAll('tool').length <= 1 && params.getAll('preset').length <= 1 && TOOLS.includes(tool) && PRESETS[tool].includes(preset)
  return { tool: valid ? tool : 'payment', preset: valid ? preset : 'default', invalid: !valid }
}
export function studioURL(tool = 'payment', preset = 'default', href = window.location.href) {
  const url = pageURL('studio', href)
  url.search = ''
  url.hash = ''
  url.searchParams.set('view', 'studio')
  url.searchParams.set('tool', tool)
  url.searchParams.set('preset', preset)
  return url
}
