import { expect, it } from 'vitest'
import { evaluateGuess, investigation, publicOutputs } from './investigation'
import { investigationContent } from './investigationContent'

it('creates varied boards with three Bob payments and five unrelated payments', () => {
  const boards = [1, 23, 890, 4294967295].map(investigation)
  for (const rows of boards) {
    expect(rows).toHaveLength(8)
    expect(rows.filter((row) => row.owner === 'bob')).toHaveLength(3)
    expect(new Set(rows.map((row) => row.id)).size).toBe(8)
  }
  expect(boards[0]).toEqual(investigation(1))
  expect(boards[0]).not.toEqual(boards[1])
})
it('keeps ownership out of public projections and amounts stable across strategies', () => {
  const rows = investigation(23)
  const reuse = publicOutputs(rows, 'reuse')
  const silent = publicOutputs(rows, 'silent')
  expect(reuse.filter((row) => row.destination === 'BOB-A').map((row) => row.id)).toEqual(rows.filter((row) => row.owner === 'bob').map((row) => row.id))
  expect(new Set(silent.map((row) => row.destination)).size).toBe(8)
  expect(silent.map((row) => row.amount)).toEqual(reuse.map((row) => row.amount))
  for (const row of [...reuse, ...silent]) expect(row).not.toHaveProperty('owner')
})
it('reports missed and wrongly attributed outputs, not just a success count', () => {
  const rows = investigation(23)
  const bob = rows.filter((row) => row.owner === 'bob').map((row) => row.id)
  expect(evaluateGuess(rows, bob)).toEqual({ correct: 3, missed: 0, mistaken: 0 })
  expect(evaluateGuess(rows, [])).toEqual({ correct: 0, missed: 3, mistaken: 0 })
  expect(evaluateGuess(rows, rows.map((row) => row.id))).toEqual({ correct: 3, missed: 0, mistaken: 5 })
  expect(evaluateGuess(rows, [bob[0], bob[0]])).toEqual({ correct: 1, missed: 2, mistaken: 0 })
})
it('has complete bilingual challenge copy', () => {
  expect(Object.keys(investigationContent.en).sort()).toEqual(Object.keys(investigationContent.it).sort())
})
