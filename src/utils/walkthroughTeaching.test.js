import { expect, it } from 'vitest'
import lessons from './walkthroughTeaching.json'
import { teaching } from '../i18n/teaching'
import { canRunReceiveCheck, isSendStepComplete } from './flowDisplay'

it('covers all four teaching stages and seven concepts in both languages', () => {
  for (const locale of ['en', 'it']) {
    expect(Object.keys(lessons[locale].stages)).toEqual(['bob', 'alice', 'derive', 'scan'])
    expect(Object.keys(lessons[locale].terms).sort()).toEqual(['inputs', 'labels', 'outputs', 'scan', 'secret', 'spend', 'tweak'])
    for (const stage of Object.values(lessons[locale].stages)) {
      expect(Object.keys(stage)).toEqual(['goal', 'knows', 'outcome'])
      for (const value of Object.values(stage)) expect(value.length).toBeGreaterThan(20)
    }
    for (const term of Object.values(lessons[locale].terms)) {
      expect(term.title.length).toBeGreaterThan(4)
      expect(term.definition.length).toBeGreaterThan(30)
    }
    expect(teaching[locale].learnSimulation).toBeTruthy()
  }
})

it('requires an authoritative passing sender check to unlock the group-0 receiving stage', () => {
  for (const result of [null, { test_passed: false }, { error: 'offline' }]) {
    expect(isSendStepComplete(result, 'linked')).toBe(false)
    expect(canRunReceiveCheck(result, 'linked')).toBe(false)
  }
  expect(canRunReceiveCheck({ test_passed: true }, 'linked')).toBe(true)
})
