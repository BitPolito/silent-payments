import { test, expect } from '@playwright/test'

async function mockCowSearch(page) {
  // Exercise the UI celebration without waiting for a random five-character search.
  const response = await page.request.post('/api/get_sp_address', { data: { testnet: true } })
  expect(response.ok()).toBe(true)
  const generated = await response.json()
  await page.route('**/api/vanity_address', route => route.fulfill({ json: generated }))
  await page.goto('/?view=tools')
  await page.getByRole('button', { name: /^Vanity address/ }).click()
  await page.getByRole('textbox').fill('mucca')
  await page.getByRole('button', { name: 'Generate', exact: true }).click()
  await expect(page.getByRole('button', { name: new RegExp(generated.addresses[0]) })).toBeVisible()
}

test('cow celebration paints in the top layer without blocking the generator and closes with it', async ({ page }) => {
  await mockCowSearch(page)
  const layer = page.locator('.sp-amb-layer')
  await expect(layer).toBeVisible()
  await expect.poll(() => layer.evaluate(element => getComputedStyle(element).overlay)).toBe('auto')
  await expect.poll(() => layer.locator('.sp-amb-item').count()).toBeGreaterThan(0)
  expect(await layer.evaluate(element => getComputedStyle(element).pointerEvents)).toBe('none')
  expect(await layer.evaluate(element => getComputedStyle(element).backgroundColor)).toBe('rgba(0, 0, 0, 0)')
  await expect(page.getByRole('heading', { name: 'Address', exact: true })).toBeFocused()
  // The decorative top layer must leave real controls usable and preserve Escape.
  const address = page.getByRole('dialog').getByRole('button', { name: /^tsp1/ })
  await address.click()
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toMatch(/^tsp1qq/)
  await page.getByRole('button', { name: /QR code \(PNG\)/ }).focus()
  await expect(page.getByRole('button', { name: /QR code \(PNG\)/ })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(layer).toHaveCount(0)
  await expect(page.getByRole('button', { name: /^Vanity address/ })).toBeFocused()
})

for (const width of [320, 1280]) {
  test(`cow rain is denser, lasts longer, and cleans up at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await page.clock.install()
    await page.clock.pauseAt(new Date())
    await mockCowSearch(page)
    const layer = page.locator('.sp-amb-layer')
    const first = await layer.locator('.sp-amb-item').first().elementHandle()
    const count = await layer.locator('.sp-amb-item').count()
    expect(count).toBeLessThanOrEqual(36)
    expect(count).toBeGreaterThan(18)
    const particles = await layer.locator('.sp-amb-item').evaluateAll(items => items.map(item => ({
      size: parseFloat(getComputedStyle(item).width),
      duration: parseFloat(getComputedStyle(item).animationDuration),
    })))
    expect(Math.min(...particles.map(item => item.size))).toBeLessThanOrEqual(64)
    expect(Math.max(...particles.map(item => item.size))).toBeGreaterThanOrEqual(96)
    expect(particles.every(item => item.duration >= 2 && item.duration <= 3.2)).toBe(true)
    await page.clock.runFor(10000)
    expect(await first.evaluate(element => element.isConnected)).toBe(true)
    await expect(layer.locator('.sp-amb-item')).toHaveCount(count)
    await page.clock.runFor(10000)
    await expect(layer).toHaveCount(0)
    await expect(page.getByRole('button', { name: /QR code \(PNG\)/ })).toBeVisible()
  })
}

test('changing to reduced motion during the cow burst stops it', async ({ page }) => {
  await page.clock.install()
  await page.clock.pauseAt(new Date())
  await mockCowSearch(page)
  await expect(page.locator('.sp-amb-layer')).toBeVisible()
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await expect(page.locator('.sp-amb-layer')).toHaveCount(0)
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
})

test('cow celebration respects reduced motion and leaves the result usable', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await mockCowSearch(page)
  await expect(page.locator('.sp-amb-layer')).not.toBeVisible()
  await expect(page.locator('.sp-amb-item')).toHaveCount(0)
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
})

for (const [width, locale, dark] of [[320, 'en', false], [390, 'it', true], [768, 'en', false], [1280, 'it', true]]) {
  test(`header controls stay compact and centered at ${width}px in ${locale}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await page.addInitScript(({locale,dark}) => { localStorage.setItem('sp-locale',locale); localStorage.setItem('theme',dark?'dark':'light') }, {locale,dark})
    await page.goto('/?view=walkthrough')
    const header = page.locator('.sp-site-header')
    const brand = await header.locator('.sp-brand').boundingBox()
    for (const selector of ['.sp-language-track', '.sp-theme-track']) {
      const track = await header.locator(selector).boundingBox()
      expect(track.height).toBe(36)
      expect(Math.abs(track.y + track.height / 2 - brand.y - brand.height / 2)).toBeLessThanOrEqual(1)
      const target = await header.locator(selector).locator('..').boundingBox()
      expect(target.height).toBeGreaterThanOrEqual(44)
      expect(target.width).toBeGreaterThanOrEqual(44)
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
    await page.evaluate(() => window.scrollTo(0,500))
    await expect.poll(async () => (await header.boundingBox()).y).toBe(0)
    // The step navigation must sit directly below the real header in each layout.
    await expect.poll(async () => {
      const bar = await header.boundingBox()
      const steps = await page.locator('.sp-stage-nav').boundingBox()
      return Math.abs(steps.y - bar.y - bar.height)
    }).toBeLessThanOrEqual(1)
    await header.getByRole('switch').click()
    await expect(header.getByRole('switch')).toHaveAttribute('aria-checked',String(!dark))
    await header.locator('.sp-language-control').click()
    await expect(page.locator('html')).toHaveAttribute('lang',locale==='en'?'it':'en')
  })
}
