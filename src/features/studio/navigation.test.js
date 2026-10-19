import { afterEach, expect, it, vi } from 'vitest'
import { studioSelection, studioURL } from './navigation'
import { studioContent } from './content'
afterEach(() => vi.unstubAllGlobals())
it('validates shared selections and falls back visibly', () => {
  expect(studioSelection('?tool=payment&preset=mutation')).toEqual({ tool: 'payment', preset: 'mutation', invalid: false })
  expect(studioSelection('?tool=scan&preset=mutation')).toEqual({ tool: 'payment', preset: 'default', invalid: true })
  expect(studioSelection('?tool=scan&tool=payment').invalid).toBe(true)
  expect(studioSelection('?tool=unknown')).toEqual({ tool: 'payment', preset: 'default', invalid: true })
})
it('shares only tool and preset, keeping addresses and results out of links', () => {
  vi.stubGlobal('window', { location: { href: 'https://demo.example/?view=reference&case=18&direction=send&subcase=1#details' } })
  const url = studioURL('address')
  expect(Object.fromEntries(url.searchParams)).toEqual({ view: 'studio', tool: 'address', preset: 'default' })
})
it('has bilingual short objectives and matching controls', () => {
  expect(Object.keys(studioContent.en).sort()).toEqual(Object.keys(studioContent.it).sort())
  for (const content of Object.values(studioContent)) for (const text of Object.values(content.objectives)) expect(text.split(/\s+/).length).toBeLessThan(40)
})
