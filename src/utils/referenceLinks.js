export const DEFAULT_REFERENCE = { id: 0, direction: 'send', subcase: 0 }
const OWN_PARAMS = ['view', 'case', 'direction', 'subcase']

export function referenceURL(selection, href = window.location.href) {
  const url = new URL(href)
  OWN_PARAMS.forEach((key) => url.searchParams.delete(key))
  if (selection) {
    url.searchParams.set('view', 'reference')
    url.searchParams.set('case', String(selection.id))
    url.searchParams.set('direction', selection.direction)
    url.searchParams.set('subcase', String(selection.subcase))
  }
  return url
}

export function writeReferenceSelection(selection) {
  window.history.replaceState(window.history.state, '', referenceURL(selection))
}

export function validateReferenceLink(search, cases) {
  const params = new URLSearchParams(search)
  if (params.get('view') !== 'reference') return { selection: DEFAULT_REFERENCE, invalid: false }
  const id = params.get('case') ?? '0'
  const subcase = params.get('subcase') ?? '0'
  const direction = params.get('direction') ?? 'send'
  const group = cases.find((entry) => entry.id === Number(id))
  const valid = /^\d+$/.test(id) && /^\d+$/.test(subcase) && Number.isSafeInteger(Number(id)) && Number.isSafeInteger(Number(subcase)) &&
    ['send', 'receive'].includes(direction) && group && Number(subcase) < group.case_counts[direction === 'send' ? 'sending' : 'receiving'] &&
    ['case', 'direction', 'subcase', 'view'].every((key) => params.getAll(key).length <= 1)
  return { selection: valid ? { id: Number(id), direction, subcase: Number(subcase) } : DEFAULT_REFERENCE, invalid: !valid }
}
