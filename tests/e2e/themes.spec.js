import { test, expect } from '@playwright/test'

// Measure rendered colors, including translucent text over its parent surfaces.
async function colors(locator) {
  return locator.evaluate(element => {
    const canvas = document.createElement('canvas')
    canvas.width = canvas.height = 1
    const context = canvas.getContext('2d', { willReadFrequently: true })
    function rgba(value) {
      context.clearRect(0, 0, 1, 1)
      context.fillStyle = value
      context.fillRect(0, 0, 1, 1)
      const bytes = context.getImageData(0, 0, 1, 1).data
      return [bytes[0], bytes[1], bytes[2], bytes[3] / 255]
    }
    const blend = (top, bottom) => top.slice(0, 3).map((channel, i) => channel * top[3] + bottom[i] * (1 - top[3]))
    const ancestors = []
    for (let node = element; node; node = node.parentElement) ancestors.unshift(node)
    let background = [255, 255, 255]
    for (const node of ancestors) background = blend(rgba(getComputedStyle(node).backgroundColor), background)
    const style = getComputedStyle(element)
    const foreground = blend(rgba(style.color), background)
    const luminance = rgb => rgb.map(channel => {
      const value = channel / 255
      return value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4
    }).reduce((sum, value, i) => sum + value * [.2126, .7152, .0722][i], 0)
    const light = luminance(foreground), dark = luminance(background)
    return { foreground, background, contrast: (Math.max(light, dark) + .05) / (Math.min(light, dark) + .05), image: style.backgroundImage }
  })
}

for (const [width, locale] of [[320, 'it'], [1280, 'en']]) {
  for (const theme of ['light', 'dark']) {
    test(`card actions and reading surfaces stay consistent in ${theme} at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 })
      await page.addInitScript(({ locale, theme }) => {
        localStorage.setItem('sp-locale', locale)
        if (localStorage.getItem('theme') === null) localStorage.setItem('theme', theme)
      }, { locale, theme })
      for (const query of ['', '?view=tools']) {
        await page.goto(`/${query}`)
        const actions = page.locator('.sp-card .sp-btn-solid')
        await expect(actions).toHaveCount(2)
        for (const action of await actions.all()) {
          const palette = await colors(action)
          expect(palette.background).toEqual([0, 28, 224])
          expect(palette.foreground).toEqual([249, 249, 249])
          expect(palette.contrast).toBeGreaterThanOrEqual(4.5)
          await action.hover()
          await expect.poll(async () => (await colors(action)).contrast).toBeGreaterThanOrEqual(4.5)
        }
        for (const text of await page.locator('.sp-card h2, .sp-card .sp-description, .sp-tools-notice').all()) {
          expect((await colors(text)).contrast).toBeGreaterThanOrEqual(4.5)
        }
        if (theme === 'dark') {
          const app = await colors(page.locator('.sp-app'))
          const card = await colors(page.locator('.sp-card').first())
          expect(app.background).not.toEqual(card.background)
          expect(Math.max(...app.background)).toBeLessThan(60)
          expect(card.image).toBe('none')
        }
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
      }
      await page.getByRole('button', { name: locale === 'en' ? /^Generate address/ : /^Genera indirizzo/ }).click()
      const dialog = page.getByRole('dialog')
      const primary = dialog.getByRole('button', { name: locale === 'en' ? 'Generate' : 'Genera', exact: true })
      expect((await colors(primary)).contrast).toBeGreaterThanOrEqual(4.5)
      const input = dialog.getByRole('radio', { name: /^Testnet/ })
      await expect(input).toBeChecked()
      expect(await input.evaluate(element => getComputedStyle(element).colorScheme)).toBe(theme)
      await primary.click()
      await expect(dialog.locator('.sp-download-card')).toHaveCount(2)
      for (const text of await dialog.locator('.sp-download-card > span:nth-child(2) > span').all()) {
        expect((await colors(text)).contrast).toBeGreaterThanOrEqual(4.5)
      }
      await page.keyboard.press('Escape')
      await page.getByRole('switch').click()
      await expect.poll(() => page.locator('html').evaluate(element => getComputedStyle(element).colorScheme)).toBe(theme === 'dark' ? 'light' : 'dark')
      await page.reload()
      await expect(page.getByRole('switch')).toHaveAttribute('aria-checked', String(theme !== 'dark'))
    })
  }
}

test('initial dark system preference is respected, with saved light preference taking priority', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' })
  await page.goto('/')
  await expect(page.getByRole('switch')).toHaveAttribute('aria-checked', 'true')
  await page.getByRole('switch').click()
  await page.reload()
  await expect(page.getByRole('switch')).toHaveAttribute('aria-checked', 'false')
})
