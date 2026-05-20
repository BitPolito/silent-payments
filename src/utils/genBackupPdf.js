import { jsPDF } from 'jspdf'

const CANVAS = [249, 249, 249]
const BP = [0, 28, 224]
const INK = [24, 28, 52]
const MUTED = [110, 115, 145]
const LINE = [224, 227, 247]

const MARGIN = 22
const LOGO_MAX_W = 88
const LOGO_TOP = 16
const FOOTER_ART_H = 20

const ASSETS = {
  logo: '/bitpolito/bitpolito-logo-blue.svg',
  lovingCows: '/bitpolito/loving-cows-blue.svg',
}

/**
 * @param {string} url
 * @param {number} maxW
 * @param {number} maxH
 */
function rasterizeSvgFit(url, maxW, maxH) {
  return fetch(url)
    .then((r) => r.text())
    .then(
      (svgText) =>
        new Promise((resolve, reject) => {
          const blob = new Blob([svgText], { type: 'image/svg+xml' })
          const objUrl = URL.createObjectURL(blob)
          const img = new Image()
          img.onload = () => {
            const scale = Math.min(maxW / img.naturalWidth, maxH / img.naturalHeight, 1)
            const w = Math.max(1, Math.round(img.naturalWidth * scale))
            const h = Math.max(1, Math.round(img.naturalHeight * scale))
            const canvas = document.createElement('canvas')
            canvas.width = w
            canvas.height = h
            const ctx = canvas.getContext('2d')
            if (!ctx) {
              URL.revokeObjectURL(objUrl)
              reject(new Error('canvas'))
              return
            }
            ctx.drawImage(img, 0, 0, w, h)
            URL.revokeObjectURL(objUrl)
            resolve({ dataUrl: canvas.toDataURL('image/png'), w, h })
          }
          img.onerror = () => {
            URL.revokeObjectURL(objUrl)
            reject(new Error('svg'))
          }
          img.src = objUrl
        }),
    )
}

/**
 * @param {{
 *   genResult: {
 *     addresses: string[]
 *     network?: string
 *     key_material?: { scan_priv_key?: string, spend_priv_key?: string } | null
 *     qr_png_base64?: string
 *   }
 *   tr: (key: string) => string
 * }} opts
 */
export async function buildAndSaveGenBackupPdf({ genResult, tr }) {
  const addr = genResult.addresses[0]
  const network =
    genResult.network === 'testnet' || addr.toLowerCase().startsWith('tsp1') ? 'testnet' : 'mainnet'
  const prefix = network === 'testnet' ? 'tsp1' : 'sp1'
  const networkLabel = network === 'testnet' ? tr('networkTestnet') : tr('networkMainnet')
  const stamp = new Date().toLocaleString()

  /** @type {{ logo?: { dataUrl: string, w: number, h: number }, loving?: { dataUrl: string, w: number, h: number } }} */
  const art = {}
  try {
    const [logo, loving] = await Promise.all([
      rasterizeSvgFit(ASSETS.logo, 640, 120),
      rasterizeSvgFit(ASSETS.lovingCows, 900, 240),
    ])
    art.logo = logo
    art.loving = loving
  } catch {
    /* optional */
  }

  const doc = new jsPDF({ unit: 'mm', format: 'a4' })
  const pageW = doc.internal.pageSize.getWidth()
  const pageH = doc.internal.pageSize.getHeight()
  const innerW = pageW - MARGIN * 2

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(7)
  const warnLines = doc.splitTextToSize(tr('pdfWarning'), innerW)
  const warnH = warnLines.length * 3.4
  let artWmm = 0
  let artHmm = 0
  if (art.loving) {
    artWmm = Math.min((art.loving.w / art.loving.h) * FOOTER_ART_H, innerW)
    artHmm = (art.loving.h / art.loving.w) * artWmm
  }
  const SEP_ABOVE = 10
  const BLOCK_GAP = 6
  const footH = SEP_ABOVE + artHmm + BLOCK_GAP + 2 + BLOCK_GAP + warnH + MARGIN
  const footTop = pageH - footH
  const cowsY = footTop + SEP_ABOVE
  const sepY = cowsY + artHmm + BLOCK_GAP
  const warnY = sepY + BLOCK_GAP + 1
  const bottomLimit = footTop - 6

  doc.setFillColor(...CANVAS)
  doc.rect(0, 0, pageW, pageH, 'F')

  let y = LOGO_TOP

  if (art.logo) {
    const logoWmm = Math.min(LOGO_MAX_W, (art.logo.w / art.logo.h) * 14)
    const logoHmm = (art.logo.h / art.logo.w) * logoWmm
    doc.addImage(art.logo.dataUrl, 'PNG', (pageW - logoWmm) / 2, y, logoWmm, logoHmm)
    y += logoHmm + 10
  } else {
    doc.setFont('helvetica', 'bold')
    doc.setFontSize(14)
    doc.setTextColor(...BP)
    doc.text(tr('pdfTitle'), pageW / 2, y + 6, { align: 'center' })
    y += 14
  }

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(8.5)
  doc.setTextColor(...MUTED)
  doc.text(tr('pdfSubtitle'), pageW / 2, y, { align: 'center' })
  y += 5
  doc.text(`${stamp} · ${networkLabel}`, pageW / 2, y, { align: 'center' })
  y += 12

  doc.setDrawColor(...LINE)
  doc.setLineWidth(0.2)
  doc.line(MARGIN, y, pageW - MARGIN, y)
  y += 10

  const ensureSpace = (need) => {
    if (y + need <= bottomLimit) return
    doc.addPage()
    doc.setFillColor(...CANVAS)
    doc.rect(0, 0, pageW, pageH, 'F')
    y = MARGIN
  }

  /**
   * @param {string} label
   * @param {string} formatNote
   * @param {string} value
   */
  const drawField = (label, formatNote, value) => {
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8)
    doc.setTextColor(...BP)
    const labelLines = doc.splitTextToSize(label, innerW)
    const labelH = labelLines.length * 3.6
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7)
    doc.setTextColor(...MUTED)
    const noteLines = doc.splitTextToSize(formatNote, innerW)
    doc.setFont('courier', 'normal')
    doc.setFontSize(9)
    const valLines = doc.splitTextToSize(String(value), innerW)
    const blockH = labelH + noteLines.length * 3.2 + valLines.length * 4.4 + 10
    ensureSpace(blockH)

    doc.setFont('helvetica', 'normal')
    doc.setFontSize(8)
    doc.setTextColor(...BP)
    doc.text(labelLines, MARGIN, y)
    y += labelH + 2

    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7)
    doc.setTextColor(...MUTED)
    doc.text(noteLines, MARGIN, y)
    y += noteLines.length * 3.2 + 3

    doc.setFont('courier', 'normal')
    doc.setFontSize(9)
    doc.setTextColor(...INK)
    doc.text(valLines, MARGIN, y)
    y += valLines.length * 4.4 + 9
  }

  drawField(tr('address'), tr('pdfAddressFormat').replace('{prefix}', prefix), addr)

  if (genResult.qr_png_base64) {
    const qr = 32
    ensureSpace(qr + 12)
    const qx = (pageW - qr) / 2
    doc.addImage(`data:image/png;base64,${genResult.qr_png_base64}`, 'PNG', qx, y, qr, qr)
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(7)
    doc.setTextColor(...MUTED)
    doc.text(tr('pdfQrCaption'), pageW / 2, y + qr + 4, { align: 'center' })
    y += qr + 12
  }

  const keyFormat = tr('pdfKeyFormat')
  if (genResult.key_material?.scan_priv_key) {
    drawField(tr('scanSk'), keyFormat, genResult.key_material.scan_priv_key)
  }
  if (genResult.key_material?.spend_priv_key) {
    drawField(tr('spendSk'), keyFormat, genResult.key_material.spend_priv_key)
  }

  if (art.loving) {
    doc.addImage(art.loving.dataUrl, 'PNG', (pageW - artWmm) / 2, cowsY, artWmm, artHmm)
  }

  doc.setDrawColor(...LINE)
  doc.setLineWidth(0.2)
  doc.line(MARGIN, sepY, pageW - MARGIN, sepY)

  doc.setFont('helvetica', 'normal')
  doc.setFontSize(7)
  doc.setTextColor(...MUTED)
  doc.text(warnLines, MARGIN, warnY)

  doc.save('bitpolito_silent_payment_backup.pdf')
}
