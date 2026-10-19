import { expect, it } from 'vitest'
import { MAX_PAYMENTS, paymentModel } from './model'
import { privacyContent } from './content'

it('links repeated destinations without hiding public amounts', () => {
  const model = paymentModel('reuse', 4, 2)
  expect(model.unique).toBe(1)
  expect(model.matching).toEqual([0, 1, 2, 3])
  expect(model.rows.map((row) => row.amount)).toEqual([12000, 8000, 21000, 5000])
})
it.each(['fresh', 'silent'])('%s avoids equality links while preserving the payment scenario', (strategy) => {
  const model = paymentModel(strategy, 4, 2)
  expect(model.unique).toBe(4)
  expect(model.matching).toEqual([2])
  expect(model.rows.map((row) => row.amount)).toEqual(paymentModel('reuse', 4).rows.map((row) => row.amount))
})
it('bounds the teaching model and handles invalid selections', () => {
  expect(paymentModel('silent', 100).rows).toHaveLength(MAX_PAYMENTS)
  expect(paymentModel('fresh', 0, 99).matching).toEqual([0])
  expect(paymentModel('unknown', 2).unique).toBe(1)
})
it('provides matching bilingual teaching content', () => {
  function shape(value) { return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, typeof item === 'object' ? shape(item) : typeof item])) }
  expect(shape(privacyContent.it)).toEqual(shape(privacyContent.en))
})
