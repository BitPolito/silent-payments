import { test, expect } from '@playwright/test'

test('home prioritizes the original tools and opens generation directly', async ({ page }) => {
  await page.goto('/?campaign=review')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Silent Payments')
  await expect(page.getByRole('link', { name: /^Guided demo/ })).toBeVisible()
  await expect(page.getByRole('link', { name: /All reference cases/ })).toBeVisible()
  await expect(page.locator('.sp-home-extras')).not.toHaveAttribute('open', '')
  await page.getByRole('button', { name: 'Generate address', exact: true }).click()
  await expect(page.getByRole('radio', { name: /^Testnet/ })).toBeChecked()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('button', { name: 'Generate address', exact: true })).toBeFocused()
  await page.getByRole('button', { name: /^Vanity address/ }).click()
  await expect(page.getByRole('textbox')).toBeVisible()
  await page.keyboard.press('Escape')
  expect(new URL(page.url()).search).toBe('?campaign=review')
})

test('the visual demo uses returned output counts and keeps a mismatch visible', async ({ page }) => {
  await page.route('**/api/single_test/send/0', route => route.fulfill({ json: {
    test_passed: false, outputs: [], expected_outputs: [['abcd']],
  } }))
  await page.goto('/?view=walkthrough')
  await expect(page.getByTestId('demo-visual')).toContainText('Illustration')
  await page.getByRole('button', { name: 'Continue', exact: true }).click()
  await page.getByRole('button', { name: 'Continue', exact: true }).click()
  await expect(page.getByTestId('comparison')).toHaveCount(0)
  await page.getByRole('button', { name: 'Run sender check', exact: true }).click()
  await expect(page.getByTestId('demo-visual')).toContainText('Payment outputs created: 0')
  await expect(page.getByRole('status')).toHaveText('Unexpected mismatch')
  await expect(page.getByRole('button', { name: '4 Receipt', exact: true })).toBeDisabled()
  await expect(page.getByTestId('output-comparison')).toContainText('Missing')
})
