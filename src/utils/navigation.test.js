import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { currentView, followsLocalLink, navigateTo, pageURL } from './navigation'
import { ui } from '../i18n/ui'

beforeEach(() => vi.stubGlobal('window', {
  location: { href: 'https://demo.example/?campaign=learn&view=reference&case=18&direction=receive&subcase=1#lesson', origin: 'https://demo.example' },
  history: { pushState: vi.fn() }, dispatchEvent: vi.fn(),
}))
afterEach(() => vi.unstubAllGlobals())

it('supports full-page learning and preserves the existing reference view', () => {
  expect(currentView('')).toBe('home')
  expect(currentView('?view=walkthrough')).toBe('walkthrough')
  expect(currentView('?view=privacy')).toBe('privacy')
  expect(currentView('?view=reference&case=18')).toBe('reference')
  expect(currentView('?view=unknown')).toBe('home')
})
it('clears stale reference selections when leaving, retaining unrelated parameters and hashes', () => {
  expect(pageURL('home').href).toBe('https://demo.example/?campaign=learn#lesson')
  expect(pageURL('walkthrough').href).toBe('https://demo.example/?campaign=learn&view=walkthrough#lesson')
  expect(pageURL('privacy').href).toBe('https://demo.example/?campaign=learn&view=privacy#lesson')
  const reference = pageURL('reference')
  expect(reference.searchParams.get('case')).toBe('0')
  expect(reference.searchParams.get('subcase')).toBe('0')
  expect(reference.searchParams.get('direction')).toBe('send')
})
it('creates real browser history entries and notifies the navigation listener', () => {
  navigateTo('/?view=walkthrough')
  expect(window.history.pushState.mock.calls[0][2].href).toBe('https://demo.example/?view=walkthrough')
  expect(window.dispatchEvent.mock.calls[0][0].type).toBe('sp:navigate')
})
it('does not create duplicate entries for an unchanged URL', () => {
  navigateTo(window.location.href)
  expect(window.history.pushState).not.toHaveBeenCalled()
})
it('preserves modified clicks, new tabs, prevented events, and external links', () => {
  const event = { defaultPrevented: false, button: 0, currentTarget: { target: '' } }
  expect(followsLocalLink(event, '/?view=walkthrough')).toBe(true)
  for (const change of [{ button: 1 }, { metaKey: true }, { ctrlKey: true }, { shiftKey: true }, { altKey: true }, { defaultPrevented: true }, { currentTarget: { target: '_blank' } }]) {
    expect(followsLocalLink({ ...event, ...change }, '/?view=walkthrough')).toBe(false)
  }
  expect(followsLocalLink(event, 'https://example.org/')).toBe(false)
})
it('defines every new UI label in English and Italian', () => {
  expect(Object.keys(ui.en).sort()).toEqual(Object.keys(ui.it).sort())
  for (const locale of ['en', 'it']) for (const value of Object.values(ui[locale])) expect(value.length).toBeGreaterThan(2)
})
