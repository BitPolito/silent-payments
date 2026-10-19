import { DEFAULT_REFERENCE, referenceURL } from './referenceLinks'

export function currentView(search) {
  const view = new URLSearchParams(search).get('view')
  return view === 'reference' || view === 'walkthrough' ? view : 'home'
}

export function pageURL(view, href = window.location.href) {
  if (view === 'reference') return referenceURL(DEFAULT_REFERENCE, href)
  const url = referenceURL(null, href)
  if (view === 'walkthrough') url.searchParams.set('view', 'walkthrough')
  return url
}

export function navigateTo(href) {
  const url = new URL(href, window.location.href)
  if (url.href === window.location.href) return
  window.history.pushState(null, '', url)
  window.dispatchEvent(new Event('sp:navigate'))
}

export function followsLocalLink(event, href) {
  return !event.defaultPrevented && event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey &&
    (!event.currentTarget.target || event.currentTarget.target === '_self') && new URL(href, window.location.href).origin === window.location.origin
}
