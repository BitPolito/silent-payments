import { test, expect } from '@playwright/test'

for (const [width, locale, theme] of [[320, 'it', 'dark'], [1280, 'en', 'light']]) {
  test(`tools offer clear generation and vanity actions at ${width}px in ${locale}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await page.addInitScript(({ locale, theme }) => {
      localStorage.setItem('sp-locale', locale)
      localStorage.setItem('theme', theme)
    }, { locale, theme })
    await page.goto('/?view=tools')
    await expect(page.locator('.sp-tool-card')).toHaveCount(2)
    await expect(page.locator('.sp-tools-notice')).toContainText(locale === 'en' ? 'server sees the private keys' : 'server vede le chiavi private')
    for (const mode of ['random', 'vanity']) {
      const name = locale === 'en' ? (mode === 'random' ? /^Generate address/ : /^Vanity address/) : (mode === 'random' ? /^Genera indirizzo/ : /^Indirizzo vanity/)
      const action = page.getByRole('button', { name })
      await action.focus()
      await page.keyboard.press('Enter')
      const dialog = page.getByRole('dialog')
      await expect(dialog.getByRole('radio', { name: /^Testnet/ })).toBeChecked()
      await expect(dialog.getByRole('textbox')).toHaveCount(mode === 'vanity' ? 1 : 0)
      await page.keyboard.press('Escape')
      await expect(action).toBeFocused()
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
    await expect(page.locator('a[href*="view=reference"]')).toHaveCount(0)
  })
}

test('reference explorer is removed from navigation and old links fall back without running checks', async ({ page }) => {
  const referenceRequests = []
  page.on('request', request => {
    if (/\/api\/(reference_cases|test_case|single_test)/.test(request.url())) referenceRequests.push(request.url())
  })
  await page.goto('/?view=reference&case=18&direction=receive&subcase=1&campaign=old-link')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Silent Payments')
  await expect(page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link')).toHaveCount(3)
  await expect(page.locator('a[href*="view=reference"]')).toHaveCount(0)
  await page.getByRole('link', { name: 'Tools', exact: true }).click()
  expect(new URL(page.url()).search).toBe('?campaign=old-link&view=tools')
  expect(referenceRequests).toEqual([])
})
