import { useCallback, useEffect, useRef, useState } from 'react'
import { ICON } from '../assets/icons'
import BpIcon from '../components/BpIcon'
import Bech32Alphabet from '../components/Bech32Alphabet'
import CopyableText from '../components/CopyableText'
import DownloadAction from '../components/DownloadAction'
import Collapsible from '../components/protocol/Collapsible'
import ModalShell from '../components/ModalShell'
import AmbientOverlay from '../components/AmbientOverlay'
import { useApiOnline } from '../hooks/useApiOnline'
import { useVanityLimits } from '../hooks/useVanityLimits'
import { useLocale } from '../i18n/LocaleContext'
import { fetchSpAddress, fetchVanityAddress, formatApiError } from '../utils/api'
import { buildAndSaveGenBackupPdf } from '../utils/genBackupPdf'
import { normalizeGenResponse, qrImageUrl } from '../utils/normalizeGen'
import {
  DEFAULT_VANITY_PATTERN,
  effectiveVanityPattern,
  isBech32m,
  parsePatternInput,
  patternValidationError,
  vanityContainsPreview,
  vanityPatternRange,
} from '../utils/bech32m'
import { resolveVanityFx } from '../utils/vanityFx'
import { preloadFxAssets } from '../fx/presets'

const alertIcon = '/bitpolito/alert.svg'

const BTN_PRIMARY =
  'rounded-md border border-bp-blue bg-bp-blue px-3 py-1.5 text-xs font-semibold text-bp-canvas transition hover:opacity-90 disabled:opacity-40 dark:border-bp-canvas dark:bg-bp-canvas dark:text-bp-blue'
const BTN_GHOST =
  'rounded-md border border-bp-200/80 px-2.5 py-1 text-[11px] font-semibold text-bp-blue transition hover:bg-bp-50 dark:border-bp-500/40 dark:text-bp-canvas dark:hover:bg-bp-700/50'
const INPUT =
  'rounded-md border border-bp-200 bg-white px-2.5 py-1.5 font-mono text-xs dark:border-bp-500/40 dark:bg-bp-800 dark:text-bp-canvas'
const COPY_COMPACT =
  'mt-0 !p-2 !text-[11px] !bg-bp-50 dark:!bg-bp-700/70 dark:!text-bp-canvas dark:hover:!bg-bp-700/90'
function downloadPngBase64(b64, filename) {
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  const blob = new Blob([bytes], { type: 'image/png' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  setTimeout(() => URL.revokeObjectURL(url), 100)
}

/**
 * @param {{ open: boolean, onClose: () => void, initialTab?: 'random' | 'vanity' }} props
 */
export default function GenerateAddrModal({ open, onClose, initialTab = 'random' }) {
  const { tr } = useLocale()
  const vanityLimits = useVanityLimits(open)
  const apiStatus = useApiOnline(open)
  const [tab, setTab] = useState(initialTab)
  const [loading, setLoading] = useState(false)
  const [genResult, setGenResult] = useState(null)
  const [pattern, setPattern] = useState('')
  const [lastVanityPattern, setLastVanityPattern] = useState('')
  const [testnet, setTestnet] = useState(false)
  const [error, setError] = useState('')
  const [patternError, setPatternError] = useState('')
  const [fxPreset, setFxPreset] = useState(/** @type {import('../fx/presets').FxPresetId | null} */ (null))
  const abortRef = useRef(/** @type {AbortController | null} */ (null))
  const patternRef = useRef(/** @type {HTMLInputElement | null} */ (null))

  const showResult = !!genResult?.addresses?.[0]

  const resetResults = useCallback(() => {
    abortRef.current?.abort()
    setGenResult(null)
    setLoading(false)
    setError('')
    setFxPreset(null)
  }, [])

  useEffect(() => {
    if (open) setTab(initialTab)
  }, [open, initialTab])

  useEffect(() => {
    if (!open) {
      abortRef.current?.abort()
      setPattern('')
      setLastVanityPattern('')
      setTestnet(false)
      setError('')
      setPatternError('')
      setGenResult(null)
      setLoading(false)
      setFxPreset(null)
    }
  }, [open])

  useEffect(() => {
    if (open) preloadFxAssets()
  }, [open])

  const applyResult = useCallback(
    (data) => {
      const normalized = normalizeGenResponse(data)
      if (!normalized) {
        const serverMsg = data?.error != null ? String(data.error) : ''
        setError(serverMsg || tr('apiError'))
        setGenResult(null)
        return
      }
      setGenResult(normalized)
      setError('')
    },
    [tr],
  )

  const runRandomGenerate = useCallback(() => {
    abortRef.current?.abort()
    const ac = new AbortController()
    abortRef.current = ac
    setLoading(true)
    setError('')
    setGenResult(null)
    fetchSpAddress({ testnet }, { signal: ac.signal })
      .then(applyResult)
      .catch((e) => {
        if (e.name !== 'AbortError') setError(formatApiError(e, tr))
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoading(false)
      })
  }, [applyResult, tr, testnet])

  const runVanitySearch = useCallback(() => {
    const p = effectiveVanityPattern(pattern, vanityLimits.maxPattern)
    if (!p || patternError) return
    abortRef.current?.abort()
    const ac = new AbortController()
    abortRef.current = ac
    setLoading(true)
    setError('')
    setGenResult(null)
    setLastVanityPattern(p)
    fetchVanityAddress(
      {
        pattern: p,
        mode: 'contains',
        testnet,
      },
      { signal: ac.signal },
    )
      .then((data) => {
        applyResult(data)
        const ok = !!normalizeGenResponse(data)?.addresses?.[0]
        const fx = resolveVanityFx(p)
        if (ok && fx) setFxPreset(fx)
      })
      .catch((e) => {
        if (e.name !== 'AbortError') setError(formatApiError(e, tr))
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoading(false)
      })
  }, [pattern, patternError, testnet, applyResult, tr, vanityLimits.maxPattern])

  const onPatternChange = (e) => {
    const { value } = parsePatternInput(e.target.value, vanityLimits.maxPattern)
    setPattern(value)
    setGenResult(null)
    const effective = effectiveVanityPattern(value, vanityLimits.maxPattern)
    setPatternError(patternValidationError(effective, tr, vanityLimits.maxPattern))
  }

  useEffect(() => {
    if (!open) return
    if (!pattern.trim()) return
    const trimmed = pattern.slice(0, vanityLimits.maxPattern)
    if (trimmed !== pattern) {
      setPattern(trimmed)
      setPatternError(patternValidationError(effectiveVanityPattern(trimmed, vanityLimits.maxPattern), tr, vanityLimits.maxPattern))
    }
  }, [open, vanityLimits.maxPattern, pattern, tr])

  const handleDownloadQr = async () => {
    const addr = genResult?.addresses?.[0]
    if (!addr) return
    if (genResult.qr_png_base64) {
      downloadPngBase64(genResult.qr_png_base64, 'silent_payment_qr.png')
      return
    }
    try {
      const res = await fetch(qrImageUrl(addr))
      if (!res.ok) throw new Error('QR fetch failed')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = 'silent_payment_qr.png'
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      setTimeout(() => URL.revokeObjectURL(url), 100)
    } catch {
      window.open(qrImageUrl(addr), '_blank', 'noopener,noreferrer')
    }
  }

  const handleDownloadResults = async () => {
    if (!genResult?.addresses?.[0]) return
    try {
      await buildAndSaveGenBackupPdf({ genResult, tr })
    } catch {
      window.alert(tr('pdfError'))
    }
  }

  useEffect(() => {
    if (open && tab === 'vanity' && !showResult && !loading) {
      patternRef.current?.focus()
    }
  }, [open, tab, showResult, loading])

  const modalTitle = tab === 'random' ? tr('modalGenTitle') : tr('modalVanityTitle')
  const modalSubtitle = tab === 'random' ? tr('modalGenSubtitle') : tr('modalVanitySubtitle')
  const vanityEffective = effectiveVanityPattern(pattern, vanityLimits.maxPattern)
  const vanityPatternLen = pattern.trim() ? pattern.length : vanityEffective.length
  const vanityPreviewLine = vanityContainsPreview(testnet, pattern, vanityLimits.maxPattern)

  const primaryDisabled =
    loading ||
    apiStatus === 'offline' ||
    (tab === 'vanity' &&
      (!!patternError || !isBech32m(vanityEffective) || vanityEffective.length > vanityLimits.maxPattern))

  const addr = genResult?.addresses?.[0]
  const isTestnetAddr =
    genResult?.network === 'testnet' || (addr && addr.toLowerCase().startsWith('tsp1'))
  const vanityHighlight =
    tab === 'vanity' && addr && lastVanityPattern
      ? vanityPatternRange(addr, lastVanityPattern, 'contains', isTestnetAddr)
      : null
  const qrSrc = genResult?.qr_png_base64
    ? `data:image/png;base64,${genResult.qr_png_base64}`
    : addr
      ? qrImageUrl(addr)
      : null

  const phase = loading ? 'loading' : showResult ? 'result' : 'form'

  return (
    <>
    <ModalShell open={open} onClose={onClose} title={modalTitle} subtitle={modalSubtitle} closeLabel={tr('close')}>
      <div className="flex gap-0.5 rounded-md border border-bp-200 bg-bp-50 p-0.5 dark:border-bp-500/30 dark:bg-bp-800/40">
        <button
          type="button"
          onClick={() => {
            setTab('random')
            resetResults()
          }}
          className={`flex-1 rounded px-2.5 py-1 text-[11px] font-semibold transition ${
            tab === 'random'
              ? 'bg-bp-blue text-bp-canvas dark:bg-bp-canvas dark:text-bp-blue'
              : 'text-bp-blue/60 hover:text-bp-blue dark:text-bp-canvas/60 dark:hover:text-bp-canvas'
          }`}
        >
          {tr('genTabRandom')}
        </button>
        <button
          type="button"
          onClick={() => {
            setTab('vanity')
            resetResults()
          }}
          className={`flex-1 rounded px-2.5 py-1 text-[11px] font-semibold transition ${
            tab === 'vanity'
              ? 'bg-bp-blue text-bp-canvas dark:bg-bp-canvas dark:text-bp-blue'
              : 'text-bp-blue/60 hover:text-bp-blue dark:text-bp-canvas/60 dark:hover:text-bp-canvas'
          }`}
        >
          {tr('genTabVanity')}
        </button>
      </div>

      {phase !== 'loading' ? (
        <label className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-md border border-bp-200/80 bg-bp-50/50 px-2.5 py-2 text-[11px] font-semibold text-bp-blue dark:border-bp-500/35 dark:bg-bp-800/30 dark:text-bp-canvas">
          <span className="inline-flex items-center gap-2">
            <input
              type="checkbox"
              checked={testnet}
              onChange={(e) => setTestnet(e.target.checked)}
              className="rounded border-bp-300"
            />
            {tr('testnet')}
          </span>
          <span className="font-normal text-bp-500 dark:text-bp-canvas/70">{tr('testnetHint')}</span>
        </label>
      ) : null}

      {apiStatus === 'offline' ? (
        <div className="mt-4 flex items-start gap-3 rounded-md border border-bp-200 bg-bp-50 p-2 dark:border-bp-500/40 dark:bg-bp-700/40">
          <img src={alertIcon} alt="" className="sp-icon-blue mt-0.5 h-5 w-5 shrink-0" />
          <p className="text-xs font-medium text-bp-blue dark:text-bp-canvas">
            {tr(import.meta.env.PROD ? 'apiOfflineProd' : 'apiOffline')}
          </p>
        </div>
      ) : null}

      {error ? (
        <div className="mt-4 flex items-start gap-3 rounded-md border border-red-200 bg-red-50 p-2 dark:border-red-900/40 dark:bg-red-950/30">
          <img src={alertIcon} alt="" className="sp-icon-blue mt-0.5 h-5 w-5 shrink-0" />
          <p className="text-xs font-medium text-red-800 dark:text-red-200">{error}</p>
        </div>
      ) : null}

      {phase === 'loading' ? (
        <div className="flex flex-col items-center justify-center gap-2 py-10">
          <div className="h-8 w-8 animate-spin rounded-full border-[3px] border-bp-blue border-t-transparent dark:border-bp-canvas dark:border-t-transparent" />
          <p className="text-xs font-semibold text-bp-blue dark:text-bp-canvas">
            {tab === 'vanity' ? tr('genSearching') : tr('generating')}
          </p>
          {tab === 'vanity' ? (
            <p className="max-w-md break-all text-center font-mono text-xs text-bp-500 dark:text-bp-canvas/80">{vanityPreviewLine}</p>
          ) : null}
        </div>
      ) : null}

      {phase === 'form' && tab === 'random' ? (
        <div className="mt-3 flex flex-col gap-2.5">
          <p className="text-xs leading-relaxed text-bp-blue/80 dark:text-bp-canvas/85">{tr('genRandomLead')}</p>
          <button
            type="button"
            onClick={runRandomGenerate}
            className={`w-full ${BTN_PRIMARY}`}
          >
            {tr('generate')}
          </button>
        </div>
      ) : null}

      {phase === 'form' && tab === 'vanity' ? (
        <div className="mt-3 flex flex-col gap-2.5">
          <p className="text-xs leading-relaxed text-bp-blue/90 dark:text-bp-canvas/90">{tr('genVanityLead')}</p>

          {!vanityLimits.isLocalApi ? (
            <p className="text-[10px] text-bp-500 dark:text-bp-canvas/65">
              {tr('vanityLimitVercel')
                .replace('{n}', String(vanityLimits.maxPattern))
                .replace('{s}', String(vanityLimits.timeoutSec))}
            </p>
          ) : null}

          <div className="flex items-baseline justify-between gap-2">
            <label htmlFor="vanity-pattern" className="text-[10px] font-semibold uppercase tracking-wide text-bp-500 dark:text-bp-canvas/75">
              {tr('patternLabel')}
            </label>
            <span className="font-mono text-[10px] font-semibold tabular-nums text-bp-500 dark:text-bp-canvas/70">
              {vanityPatternLen}/{vanityLimits.maxPattern}
            </span>
          </div>

          <div className="flex flex-col gap-2 sm:flex-row sm:items-stretch">
            <input
              ref={patternRef}
              id="vanity-pattern"
              type="text"
              value={pattern}
              onChange={onPatternChange}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !primaryDisabled) runVanitySearch()
              }}
              placeholder={DEFAULT_VANITY_PATTERN}
              autoComplete="off"
              spellCheck={false}
              className={`min-w-0 flex-1 ${INPUT} ${patternError ? 'border-red-400 dark:border-red-500/60' : ''}`}
            />
            <button
              type="button"
              disabled={primaryDisabled}
              onClick={runVanitySearch}
              className={`shrink-0 ${BTN_PRIMARY}`}
            >
              {tr('generate')}
            </button>
          </div>

          <p className="break-all font-mono text-[10px] leading-relaxed text-bp-500 dark:text-bp-canvas/75">
            <span className="text-bp-400 dark:text-bp-canvas/55">{tr('vanityPreview')}: </span>
            <span className="font-semibold text-bp-blue dark:text-bp-canvas">{vanityPreviewLine}</span>
          </p>

          {patternError ? <p className="text-xs font-medium text-red-600 dark:text-red-400">{patternError}</p> : null}

          <Bech32Alphabet />
        </div>
      ) : null}

      {phase === 'result' && addr ? (
        <div className="mt-5 flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="rounded bg-bp-100 px-2 py-0.5 text-[10px] font-semibold text-bp-600 dark:bg-bp-700/60 dark:text-bp-200">
                {isTestnetAddr ? tr('networkTestnet') : tr('networkMainnet')}
              </span>
              {tab === 'vanity' && genResult.elapsed != null ? (
                <span className="rounded bg-bp-100 px-2 py-0.5 text-[10px] font-semibold text-bp-600 dark:bg-bp-700/60 dark:text-bp-200">
                  {tr('elapsed')}: {Number(genResult.elapsed).toFixed(2)} s
                </span>
              ) : null}
            </div>
            <button
              type="button"
              onClick={resetResults}
              className={`${BTN_GHOST} ml-auto`}
            >
              {tr('genNewAddress')}
            </button>
          </div>

          <div className="rounded-md border border-bp-200 bg-bp-50/60 p-2.5 dark:border-bp-500/40 dark:bg-bp-700/30">
            <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
              {qrSrc ? (
                <div className="shrink-0 rounded-md border border-bp-200 bg-white p-1 dark:border-bp-500/30">
                  <img src={qrSrc} alt="" className="h-20 w-20" />
                </div>
              ) : null}
              <div className="min-w-0 flex-1 w-full">
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-bp-500 dark:text-bp-canvas/75">
                  {tr('address')}
                </p>
                <CopyableText value={addr} highlight={vanityHighlight} className={COPY_COMPACT} />
              </div>
            </div>
          </div>

          {genResult.key_material ? (
            <Collapsible title={tr('genFoldKeys')} nested>
              <div className="flex flex-col gap-2.5 pt-0.5">
                <div
                  className="flex gap-2.5 rounded-md border border-bp-200 bg-bp-50/80 p-2.5 dark:border-bp-500/40 dark:bg-bp-700/35"
                  role="alert"
                >
                  <BpIcon src={ICON.key} className="mt-0.5 h-5 w-5 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <p className="text-[11px] font-bold text-bp-blue dark:text-bp-canvas">{tr('genPrivateKeys')}</p>
                    <p className="mt-1 text-[10px] leading-relaxed text-bp-blue/85 dark:text-bp-canvas/85">{tr('genKeysWarning')}</p>
                    <p className="mt-1 text-[10px] leading-relaxed text-bp-500 dark:text-bp-300">{tr('genKeysShort')}</p>
                  </div>
                </div>
                <div>
                  <p className="mb-0.5 text-[10px] font-semibold text-bp-blue dark:text-bp-canvas/85">{tr('scanSk')}</p>
                  <CopyableText value={genResult.key_material.scan_priv_key} className={COPY_COMPACT} />
                </div>
                <div>
                  <p className="mb-0.5 text-[10px] font-semibold text-bp-blue dark:text-bp-canvas/85">{tr('spendSk')}</p>
                  <CopyableText value={genResult.key_material.spend_priv_key} className={COPY_COMPACT} />
                </div>
              </div>
            </Collapsible>
          ) : null}

          <div>
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-bp-500 dark:text-bp-canvas/75">
              {tr('downloadSection')}
            </p>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <DownloadAction
                icon={ICON.save}
                title={tr('downloadQr')}
                hint={tr('downloadQrHint')}
                onClick={handleDownloadQr}
              />
              <DownloadAction
                icon={ICON.save}
                title={tr('downloadPdf')}
                hint={tr('downloadPdfHint')}
                onClick={handleDownloadResults}
              />
            </div>
          </div>
        </div>
      ) : null}
    </ModalShell>
    <AmbientOverlay preset={fxPreset} active={open && !!fxPreset} onDone={() => setFxPreset(null)} />
    </>
  )
}