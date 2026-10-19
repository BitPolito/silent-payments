import { describe, expect, it } from 'vitest'
import { compareMultiset, compareReferenceResult } from './referenceComparison'
import { DEFAULT_REFERENCE, referenceURL, validateReferenceLink } from './referenceLinks'
import lessons from './referenceTeaching.json'
import provenance from '../../api/core/test/provenance.json'
import { teaching } from '../i18n/teaching'

const cases = [{ id: 0, case_counts: { sending: 1, receiving: 1 } }, { id: 18, case_counts: { sending: 1, receiving: 2 } }]

describe('reference comparisons', () => {
  it('matches reordered outputs and consumes each duplicate once', () => {
    expect(compareMultiset(['a', 'b', 'a'], ['a', 'a', 'b']).map((row) => row.status)).toEqual(['matched', 'matched', 'matched'])
    expect(compareMultiset(['a', 'a'], ['a', 'b']).map((row) => row.status)).toEqual(['matched', 'missing', 'unexpected'])
  })
  it('retains all missing and additional outputs, including an empty expectation', () => {
    expect(compareMultiset([], ['a', 'a'])).toHaveLength(2)
    expect(compareMultiset(['a', 'b'], [])).toEqual([{ expected: 'a', actual: undefined, status: 'missing' }, { expected: 'b', actual: undefined, status: 'missing' }])
  })
  it('chooses a permitted multiset alternative even when its order differs', () => {
    const result = compareReferenceResult({ expected_outputs: [['a'], ['b', 'b', 'c']], outputs: ['c', 'b', 'b'] }, 'send')
    expect(result.index).toBe(1)
    expect(result.alternatives).toBe(2)
    expect(result.rows.every((row) => row.status === 'matched')).toBe(true)
  })
  it('explains the closest alternative without changing the runner verdict', () => {
    const input = { test_passed: false, expected_outputs: [['a', 'a'], ['b']], outputs: ['b', 'c'] }
    expect(compareReferenceResult(input, 'send').index).toBe(1)
    expect(input.test_passed).toBe(false)
  })
  it('handles flat outputs and successful empty results', () => {
    expect(compareReferenceResult({ expected_outputs: ['a'], outputs: ['a'] }, 'send').rows[0].status).toBe('matched')
    expect(compareReferenceResult({ expected_outputs: [], outputs: [] }, 'send').rows).toEqual([])
    expect(compareReferenceResult({ expected_outputs: [[]], outputs: [] }, 'send').expected).toEqual([])
  })
  it('matches receiving keys and tweaks exactly, excluding randomized signatures from identity', () => {
    const a = { pub_key: 'a', priv_key_tweak: '1', signature: 'reference' }
    const b = { pub_key: 'b', priv_key_tweak: '2' }
    const result = compareReferenceResult({ expected_outputs: [a, b, a], outputs: [b, { ...a, signature: 'random' }, { ...a, signature: 'different' }] }, 'receive')
    expect(result.rows.every((row) => row.status === 'matched')).toBe(true)
    expect(result.rows[0].actual.signature).toBe('random')
    expect(compareReferenceResult({ expected_outputs: [a], outputs: [{ ...a, priv_key_tweak: '3' }] }, 'receive').rows.map((row) => row.status)).toEqual(['missing', 'unexpected'])
  })
  it('compares every receiving address in order and shows missing or additional addresses', () => {
    const result = compareReferenceResult({ expected_addresses: ['a', 'b', 'c'], addresses: ['b', 'a'] }, 'receive')
    expect(result.addresses.map((row) => row.status)).toEqual(['different', 'different', 'missing'])
    expect(compareReferenceResult({ expected_addresses: ['a'], addresses: ['a', 'b'] }, 'receive').addresses[1].status).toBe('unexpected')
  })
})

describe('reference links', () => {
  it('round trips selections while preserving unrelated parameters and fragments', () => {
    const url = referenceURL({ id: 18, direction: 'receive', subcase: 1 }, 'https://example.com/?campaign=workshop#demo')
    expect(validateReferenceLink(url.search, cases)).toEqual({ selection: { id: 18, direction: 'receive', subcase: 1 }, invalid: false })
    expect(url.searchParams.get('campaign')).toBe('workshop')
    expect(referenceURL(null, url.href).href).toBe('https://example.com/?campaign=workshop#demo')
    expect([...url.searchParams.keys()]).toEqual(['campaign', 'view', 'case', 'direction', 'subcase'])
  })
  it.each(['case=-1', 'case=28', 'case=wat', 'case=1.5', 'case=99999999999999999999', 'subcase=-1', 'subcase=1', 'subcase=0.5', 'direction=receiving', 'case=0&case=18', 'view=reference&view=reference'])('rejects invalid selection %s', (query) => {
    expect(validateReferenceLink('?view=reference&' + query, cases)).toEqual({ selection: DEFAULT_REFERENCE, invalid: true })
  })
  it('defaults missing selection fields and ordinary home URLs', () => {
    expect(validateReferenceLink('?view=reference', cases)).toEqual({ selection: DEFAULT_REFERENCE, invalid: false })
    expect(validateReferenceLink('?campaign=x', cases).invalid).toBe(false)
  })
  it('rejects a direction with no subcases', () => {
    expect(validateReferenceLink('?view=reference&direction=receive', [{ id: 0, case_counts: { sending: 1, receiving: 0 } }]).invalid).toBe(true)
  })
})

it('covers every pinned group in both languages and both directions', () => {
  expect(Object.keys(lessons)).toHaveLength(28)
  for (const group of provenance.scenario_mapping) {
    for (const locale of ['en', 'it']) {
      expect(Object.keys(lessons[group.id][locale]).sort()).toEqual(['demonstrates', 'receiving', 'sending', 'title', 'why'])
      for (const value of Object.values(lessons[group.id][locale])) expect(value.trim().length).toBeGreaterThan(10)
    }
  }
  expect(Object.keys(teaching.en).sort()).toEqual(Object.keys(teaching.it).sort())
})
