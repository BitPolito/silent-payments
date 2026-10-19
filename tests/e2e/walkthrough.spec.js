import { test, expect } from '@playwright/test'

async function open(page) {
  await page.goto('/')
  await page.getByRole('button', { name: /^Guided demo/ }).click()
  await expect(page.getByTestId('stage-teaching')).toBeVisible()
}
async function derive(page) {
  await page.getByRole('button', { name: 'Continue', exact: true }).click()
  await page.getByRole('button', { name: 'Continue', exact: true }).click()
}
async function send(page) {
  await page.getByRole('button', { name: 'Run sender check', exact: true }).click()
  await expect(page.getByTestId('comparison').getByRole('status')).toHaveText('Matches reference')
  await page.getByRole('button', { name: 'Continue', exact: true }).click()
}
async function receive(page) {
  await page.getByRole('button', { name: 'Run receiver check', exact: true }).click()
  await expect(page.getByTestId('walkthrough-recap')).toBeVisible()
}

test('walkthrough separates learning goals, conceptual explanations, expectations and real results', async ({ page }) => {
  await open(page)
  await expect(page.getByText(/This server runs both roles/)).toBeVisible()
  await expect(page.getByRole('button', { name: '4. 4 Receipt', exact: true })).toBeDisabled()
  await expect(page.getByTestId('stage-teaching')).toContainText('Alice needs only the public Silent Payments address')
  await page.getByText('How it works', { exact: true }).click()
  await expect(page.getByText('Scan key', { exact: true })).toBeVisible()
  await expect(page.getByText('Spend key', { exact: true })).toBeVisible()
  await expect(page.getByText(/Conceptual explanation/)).toBeVisible()
  await derive(page)
  await expect(page.getByTestId('comparison')).toHaveCount(0)
  await page.getByText('Reference values before execution', { exact: true }).click()
  await expect(page.getByTestId('stage-teaching').getByRole('button')).not.toHaveCount(0)
  await send(page)
  await expect(page.getByTestId('comparison')).toHaveCount(0)
  await receive(page)
  await expect(page.getByTestId('output-comparison')).not.toHaveCount(0)
  await expect(page.getByTestId('walkthrough-recap')).toContainText('reusable address and the payment output serve different purposes')
})

test('restart reloads the same fixture and clears results and progress', async ({ page }) => {
  await open(page)
  await derive(page)
  await send(page)
  await receive(page)
  const reload = page.waitForResponse((response) => response.url().endsWith('/api/test_case/0'))
  await page.getByRole('button', { name: 'Start again' }).click()
  await reload
  await expect(page.getByTestId('stage-teaching')).toContainText('Learn what Bob shares')
  await expect(page.getByTestId('comparison')).toHaveCount(0)
  await expect(page.getByTestId('walkthrough-recap')).toHaveCount(0)
  await expect(page.getByRole('button', { name: '4. 4 Receipt', exact: true })).toBeDisabled()
  await derive(page)
  await expect(page.getByRole('button', { name: 'Run sender check', exact: true })).toBeEnabled()
})

for (const [name, id, direction] of [
  ['Several payments to one recipient', 10, 'send'],
  ['A label with even parity', 12, 'receive'],
  ['Ignore unrelated outputs', 23, 'receive'],
  ['A zero final key sum', 25, 'send'],
]) {
  test(`recap opens ${name} without executing it`, async ({ page }) => {
    await open(page)
    await derive(page)
    await send(page)
    await receive(page)
    const executions = []
    page.on('request', (request) => { if (request.url().includes('/api/single_test/')) executions.push(request.url()) })
    await page.getByTestId('walkthrough-recap').getByRole('button', { name, exact: true }).click()
    await expect(page.getByLabel('Reference case', { exact: true })).toHaveValue(String(id))
    await expect(page.getByLabel('Direction', { exact: true })).toHaveValue(direction)
    await expect(page.getByRole('heading', { name, exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Run reference check' })).toBeEnabled()
    expect(executions).toEqual([])
    expect(new URL(page.url()).searchParams.get('case')).toBe(String(id))
  })
}

test('navigating away from a pending sender check discards its late response', async ({ page }) => {
  let release, started
  const gate = new Promise((resolve) => { release = resolve })
  const received = new Promise((resolve) => { started = resolve })
  await page.route('**/api/single_test/send/0', async (route) => {
    const response = await route.fetch()
    started()
    await gate
    await route.fulfill({ response }).catch(() => {})
  })
  await open(page)
  await derive(page)
  await page.getByRole('button', { name: 'Run sender check', exact: true }).click()
  await received
  await page.getByRole('button', { name: 'Previous step', exact: true }).click()
  release()
  await page.getByRole('button', { name: 'Continue', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Run sender check', exact: true })).toBeEnabled()
  await expect(page.getByTestId('comparison')).toHaveCount(0)
})

test('closing a pending receiver check cannot populate a reopened walkthrough', async ({ page }) => {
  let release, started
  const gate = new Promise((resolve) => { release = resolve })
  const received = new Promise((resolve) => { started = resolve })
  await page.route('**/api/single_test/receive/0', async (route) => {
    const response = await route.fetch()
    started()
    await gate
    await route.fulfill({ response }).catch(() => {})
  })
  await open(page)
  await derive(page)
  await send(page)
  await page.getByRole('button', { name: 'Run receiver check', exact: true }).click()
  await received
  await page.getByRole('button', { name: 'Close', exact: true }).click()
  await page.getByRole('button', { name: /^Guided demo/ }).click()
  release()
  await expect(page.getByTestId('stage-teaching')).toContainText('Learn what Bob shares')
  await expect(page.getByTestId('comparison')).toHaveCount(0)
  await expect(page.getByTestId('walkthrough-recap')).toHaveCount(0)
})

test('walkthrough request errors do not pretend to be reference mismatches', async ({ page }) => {
  await page.route('**/api/single_test/send/0', (route) => route.fulfill({ status: 503, json: { error: 'Offline', code: 'UNAVAILABLE' } }))
  await open(page)
  await derive(page)
  await page.getByRole('button', { name: 'Run sender check', exact: true }).click()
  await expect(page.getByRole('alert')).toHaveText('Request error: Offline')
  await expect(page.getByTestId('comparison')).toHaveCount(0)
  await expect(page.getByRole('button', { name: '4. 4 Receipt', exact: true })).toBeDisabled()
})

test('walkthrough Italian explanations support a narrow screen and keyboard navigation', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.addInitScript(() => { localStorage.setItem('sp-locale', 'it'); localStorage.setItem('theme', 'dark') })
  await page.goto('/')
  await page.getByRole('button', { name: /^Demo guidata/ }).click()
  await expect(page.getByRole('heading', { name: 'Obiettivo', exact: true })).toBeVisible()
  await page.getByText('Come funziona', { exact: true }).click()
  await expect(page.getByText('Chiave di scansione', { exact: true })).toBeVisible()
  await expect(page.getByText('Chiave di spesa', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Continua', exact: true }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByTestId('stage-teaching')).toContainText('input della transazione di Alice')
  expect(await page.getByRole('dialog').evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true)
})
