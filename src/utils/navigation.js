import { referenceURL } from './referenceLinks'

export function currentView(search) {
  const view = new URLSearchParams(search).get('view')
  return ['walkthrough', 'privacy', 'studio', 'tools'].includes(view) ? view : 'home'
}

export function pageURL(view, href = window.location.href) {
  const url = referenceURL(null, href)
  url.searchParams.delete('tool')
  url.searchParams.delete('preset')
  if (['walkthrough', 'privacy', 'studio', 'tools'].includes(view)) url.searchParams.set('view', view)
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
