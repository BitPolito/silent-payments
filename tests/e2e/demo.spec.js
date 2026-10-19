import { test, expect } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { getDocument } from 'pdfjs-dist/legacy/build/pdf.mjs'
import { BinaryBitmap, HybridBinarizer, RGBLuminanceSource, QRCodeReader } from '@zxing/library'

async function openGenerator(page) {
  await page.goto('/')
  await page.getByRole('button', { name: /^Generate address/ }).click()
  await expect(page.getByRole('checkbox')).toBeChecked()
}
async function generate(page) {
  const response = page.waitForResponse((r) => r.url().endsWith('/api/get_sp_address') && r.request().method() === 'POST')
  await page.getByRole('button', { name: 'Generate', exact: true }).click()
  const data = await (await response).json()
  await expect(page.getByRole('button', { name: new RegExp(data.addresses[0]) })).toBeVisible()
  return data
}

test('guided sender and receiver walkthrough', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /^Guided demo/ }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('button', { name: 'Continue', exact: true }).click()
  await dialog.getByRole('button', { name: 'Continue', exact: true }).click()
  await dialog.getByRole('button', { name: 'Run sender check', exact: true }).click()
  await expect(dialog.getByText('Matches reference', { exact: true })).toBeVisible()
  await dialog.getByRole('button', { name: 'Continue', exact: true }).click()
  await dialog.getByRole('button', { name: 'Run receiver check', exact: true }).click()
  await expect(dialog.getByText('Donation flow complete. Demo only.')).toBeVisible()
})

test('advanced cases include subcases and expected rejection', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /^Guided demo/ }).click()
  await page.getByRole('button', { name: 'All reference cases' }).click()
  await expect(page.getByRole('combobox', { name: 'Reference case', exact: true }).locator('option')).toHaveCount(28)
  await page.getByRole('combobox', { name: 'Reference case', exact: true }).selectOption('18')
  await page.getByLabel('Direction', { exact: true }).selectOption('receive')
  await page.getByLabel('Subcase', { exact: true }).selectOption('1')
  await page.getByRole('button', { name: 'Run reference check' }).click()
  await expect(page.getByTestId('reference-result').getByRole('status')).toHaveText('Passed')
  await page.getByRole('combobox', { name: 'Reference case', exact: true }).selectOption('25')
  await page.getByLabel('Direction', { exact: true }).selectOption('send')
  await page.getByRole('button', { name: 'Run reference check' }).click()
  await expect(page.getByTestId('reference-result').getByRole('status')).toContainText('Expected rejection')
})

test('generation, clipboard, QR, PDF and both networks', async ({ page }) => {
  await openGenerator(page)
  const data = await generate(page)
  await page.getByRole('button', { name: new RegExp(data.addresses[0]) }).click()
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(data.addresses[0])
  const qrDownload = page.waitForEvent('download')
  await page.getByRole('button', { name: /QR code \(PNG\)/ }).click()
  const png = await readFile(await (await qrDownload).path())
  const pixels = await page.evaluate(async (base64) => {
    const image = new Image()
    image.src = `data:image/png;base64,${base64}`
    await image.decode()
    const canvas = document.createElement('canvas')
    canvas.width=image.width; canvas.height=image.height
    const ctx=canvas.getContext('2d'); ctx.drawImage(image,0,0)
    const rgba=ctx.getImageData(0,0,image.width,image.height).data
    return {width:image.width,height:image.height,gray:Array.from({length:image.width*image.height},(_,i)=>rgba[i*4])}
  }, png.toString('base64'))
  const bitmap = new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(Uint8ClampedArray.from(pixels.gray),pixels.width,pixels.height)))
  expect(new QRCodeReader().decode(bitmap).getText()).toBe(data.addresses[0])
  const pdfDownload = page.waitForEvent('download')
  await page.getByRole('button', { name: /Backup \(PDF\)/ }).click()
  const pdf = await getDocument({data:new Uint8Array(await readFile(await (await pdfDownload).path())), useSystemFonts:true}).promise
  let content=''
  for(let n=1;n<=pdf.numPages;n++) content+=(await (await pdf.getPage(n)).getTextContent()).items.map((item)=>item.str).join('')
  const compact=content.replace(/\s/g,'')
  for(const value of [data.addresses[0],data.key_material.scan_priv_key,data.key_material.spend_priv_key]) expect(compact).toContain(value)
  await pdf.destroy()
  await page.getByRole('checkbox').uncheck()
  const mainnet=await generate(page)
  expect(mainnet.addresses[0]).toMatch(/^sp1qq/)
})

test('themes and languages persist after reload', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('switch').click()
  const dark=await page.locator('html').getAttribute('class')
  await page.getByRole('button', { name: 'Switch language between Italian and English' }).click()
  await expect(page.locator('html')).toHaveAttribute('lang','it')
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('lang','it')
  await expect(page.locator('html')).toHaveAttribute('class',dark || '')
  await page.getByRole('button', { name: /^Genera indirizzo/ }).click()
  await expect(page.getByText(/Il server genera e vede/)).toBeVisible()
})

test('vanity displays JSON timeout errors', async ({ page }) => {
  await page.route('**/api/vanity_address', (route) => route.fulfill({status:504,json:{error:'Vanity search timed out',code:'SEARCH_TIMEOUT'}}))
  await page.goto('/')
  await page.getByRole('button', { name: /^Vanity address/ }).click()
  await page.getByRole('textbox').fill('q')
  await page.getByRole('button', { name: 'Generate', exact: true }).click()
  await expect(page.getByText('Vanity search timed out', {exact:true})).toBeVisible()
})

test('closed or superseded generation cannot display stale results', async ({ page }) => {
  let release
  const gate=new Promise((resolve)=>{release=resolve})
  await page.route('**/api/get_sp_address', async(route)=>{
    const response=await route.fetch()
    await gate
    await route.fulfill({response}).catch(()=>{})
  })
  await openGenerator(page)
  await page.getByRole('button', { name: 'Generate', exact: true }).click()
  await expect(page.getByText(/Closing discards this result/)).toBeVisible()
  await page.getByRole('button', { name: 'Close', exact: true }).click()
  await page.getByRole('button', { name: /^Generate address/ }).click()
  release()
  await expect(page.getByRole('button', {name:/Backup \(PDF\)/})).toHaveCount(0)
  await expect(page.getByRole('checkbox')).toBeChecked()
})

test('short real vanity search returns a valid testnet export', async ({page})=>{
  await page.goto('/')
  await page.getByRole('button',{name:/^Vanity address/}).click()
  await page.getByRole('textbox').fill('q')
  const response=page.waitForResponse((r)=>r.url().endsWith('/api/vanity_address'))
  await page.getByRole('button',{name:'Generate',exact:true}).click()
  const data=await (await response).json()
  expect(data.network).toBe('testnet')
  expect(data.key_material.scan_priv_key).toMatch(/^[0-9a-f]{64}$/)
  await expect(page.getByRole('button',{name:new RegExp(data.addresses[0])})).toBeVisible()
})
