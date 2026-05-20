/**
 * Curated demo scenarios for end users. Each maps to one official BIP-352 test vector.
 * @typedef {{
 *   id: string
 *   testId: number
 *   icon: 'donation' | 'silent' | 'wallet' | 'key'
 * }} DemoScenario
 */

export const HAPPY_PATH_SCENARIO_ID = 'donation'
export const HAPPY_PATH_TEST_ID = 0

/**
 * Main walkthrough: only vectors where build + scan pass in the normal path.
 * For now a single entry (donation); add more ids here when you want a wider random pool.
 */
/** @type {DemoScenario[]} */
export const FLOW_SCENARIOS = [{ id: HAPPY_PATH_SCENARIO_ID, testId: HAPPY_PATH_TEST_ID, icon: 'donation' }]

/** Appendix: edge cases (optional deep dive). */
/** @type {DemoScenario[]} */
export const EDGE_SCENARIOS = [
  { id: 'no_outputs', testId: 24, icon: 'wallet' },
  { id: 'zero_sum', testId: 25, icon: 'key' },
]

/** @type {DemoScenario[]} */
export const DEMO_SCENARIOS = [...FLOW_SCENARIOS, ...EDGE_SCENARIOS]

/**
 * @param {string} scenarioId
 */
export function getDemoScenario(scenarioId) {
  return DEMO_SCENARIOS.find((s) => s.id === scenarioId) ?? FLOW_SCENARIOS[0]
}

/**
 * Pick a passing scenario for the main demo (new draw on each modal open / “Another example”).
 * @param {string} [excludeId] Optional id to avoid picking the same scenario twice in a row.
 */
export function pickRandomFlowScenario(excludeId) {
  const pool = excludeId ? FLOW_SCENARIOS.filter((s) => s.id !== excludeId) : FLOW_SCENARIOS
  const list = pool.length ? pool : FLOW_SCENARIOS
  return list[Math.floor(Math.random() * list.length)]
}
