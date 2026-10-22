import { test, expect } from '@playwright/test'

async function open(page) {
  await page.goto('/')
  await page.getByRole('link', { name: /^Guided demo/ }).click()
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

test('walkthrough shows explanations and values directly, with one copy of matching results', async ({ page }) => {
  await open(page)
  await expect(page.getByText(/This server runs both roles/)).toBeVisible()
  await expect(page.getByRole('button', { name: '4 Receipt', exact: true })).toBeDisabled()
  await expect(page.getByRole('heading', { name: 'Bob shares an address', exact: true })).toBeVisible()
  await expect(page.getByTestId('stage-teaching')).toContainText('Alice needs only Bob’s public Silent Payments address')
  await expect(page.getByTestId('stage-teaching')).toContainText('a scan key to find payments and a spend key to unlock them')
  await expect(page.locator('.sp-demo-data').getByRole('button').first()).toBeVisible()
  await expect(page.locator('.sp-simple-demo details')).toHaveCount(0)
  await derive(page)
  await expect(page.getByTestId('comparison')).toHaveCount(0)
  await expect(page.getByTestId('demo-expectations').getByRole('button').first()).toBeVisible()
  const sending = page.waitForResponse(response => response.url().endsWith('/api/single_test/send/0'))
  await page.getByRole('button', { name: 'Run sender check', exact: true }).click()
  const sent = await (await sending).json()
  await expect(page.getByTestId('comparison').getByRole('status')).toHaveText('Matches reference')
  await expect(page.getByTestId('demo-expectations')).toHaveCount(0)
  await expect(page.getByRole('button', { name: new RegExp(sent.outputs[0]) })).toHaveCount(1)
  await page.getByRole('button', { name: 'Continue', exact: true }).click()
  await expect(page.getByTestId('demo-expectations')).toBeVisible()
  await receive(page)
  await expect(page.getByTestId('output-comparison').first()).toBeVisible()
  await expect(page.getByText('Generated signature evidence', { exact: true })).toBeVisible()
  await expect(page.locator('.sp-simple-demo details')).toHaveCount(0)
  await expect(page.getByTestId('walkthrough-recap')).toContainText('One reusable address; a distinct output for this payment.')
})

test('restart reloads the same fixture and clears results and progress', async ({ page }) => {
  await open(page)
  await derive(page)
  await send(page)
  await receive(page)
  const reload = page.waitForResponse((response) => response.url().endsWith('/api/test_case/0'))
  await page.getByRole('button', { name: 'Start again' }).click()
  await reload
  await expect(page.getByTestId('stage-teaching')).toContainText('Bob shares an address')
  await expect(page.getByTestId('comparison')).toHaveCount(0)
  await expect(page.getByTestId('walkthrough-recap')).toHaveCount(0)
  await expect(page.getByRole('button', { name: '4 Receipt', exact: true })).toBeDisabled()
  await derive(page)
  await expect(page.getByRole('button', { name: 'Run sender check', exact: true })).toBeEnabled()
})

test('completed demo has a concise recap without links to the removed explorer', async ({ page }) => {
  await open(page)
  await derive(page)
  await send(page)
  await receive(page)
  await expect(page.locator('a[href*="view=reference"]')).toHaveCount(0)
  await expect(page.getByTestId('walkthrough-recap').getByRole('button')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Start again' })).toBeVisible()
})

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

test('leaving a pending receiver check cannot populate a reopened walkthrough', async ({ page }) => {
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
  await page.getByRole('link', { name: 'Back to home', exact: false }).click()
  await page.getByRole('link', { name: /^Guided demo/ }).click()
  release()
  await expect(page.getByTestId('stage-teaching')).toContainText('Bob shares an address')
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
  await expect(page.getByRole('button', { name: '4 Receipt', exact: true })).toBeDisabled()
})

test('walkthrough Italian explanations support a narrow screen and keyboard navigation', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.addInitScript(() => { localStorage.setItem('sp-locale', 'it'); localStorage.setItem('theme', 'dark') })
  await page.goto('/')
  await page.getByRole('link', { name: /^Demo guidata/ }).click()
  await expect(page.getByRole('heading', { name: 'Bob condivide un indirizzo', exact: true })).toBeVisible()
  await expect(page.getByTestId('stage-teaching')).toContainText('la chiave di scansione per trovare i pagamenti e quella di spesa per spenderli')
  await expect(page.locator('.sp-demo-data').getByRole('button').first()).toBeVisible()
  await page.getByRole('button', { name: 'Continua', exact: true }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByTestId('stage-teaching')).toContainText('input della transazione')
  expect(await page.getByRole('main').evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true)
})
