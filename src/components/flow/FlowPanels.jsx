import CopyableText from '../CopyableText'
import { formatTxidShort, scriptTypeLabel, silentAddressKind } from '../../utils/flowDisplay'

/**
 * @param {{ icon: string, title: string, children?: import('react').ReactNode }} props
 */
export function StepHeader({ icon, title, children }) {
  return (
    <header className="sp-flow-step-head">
      <img src={icon} alt="" className="sp-flow-step-icon" />
      <div className="min-w-0 flex-1">
        <h2 className="sp-flow-heading">{title}</h2>
        {children}
      </div>
    </header>
  )
}

/**
 * @param {{ icon: string, label: string, hint?: string, children?: import('react').ReactNode }} props
 */
/**
 * @param {{ title: string, items: string[] }} props
 */
export function DataLegend({ title, items }) {
  if (!items.length) return null
  return (
    <div className="sp-flow-legend">
      <p className="sp-flow-legend-title">{title}</p>
      <ul className="sp-flow-legend-list">
        {items.map((text) => (
          <li key={text}>{text}</li>
        ))}
      </ul>
    </div>
  )
}

/**
 * @param {{ address: string, notBc1Note: string, badgeSilent: string, badgeBc1: string }} props
 */
export function AddressKindNote({ address, notBc1Note, badgeSilent, badgeBc1 }) {
  const { kind, prefix } = silentAddressKind(address)
  const isBc1 = address.startsWith('bc1') || address.startsWith('tb1')
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center gap-1.5">
        {kind === 'silent' ? (
          <span className="sp-flow-badge is-silent">{badgeSilent.replace('{prefix}', prefix)}</span>
        ) : null}
        {isBc1 ? <span className="sp-flow-badge is-bc1">{badgeBc1}</span> : null}
        {kind !== 'silent' && !isBc1 && address ? (
          <span className="sp-flow-badge">{address.slice(0, 8)}…</span>
        ) : null}
      </div>
      <p className="text-xs leading-relaxed text-bp-600 dark:text-bp-canvas/70">{notBc1Note}</p>
    </div>
  )
}

/**
 * @param {{ value: string, className?: string, notBc1Note: string, badgeSilent: string, badgeBc1: string }} props
 */
export function SilentAddressField({ value, className, notBc1Note, badgeSilent, badgeBc1, compact = false }) {
  if (!value) return null
  return (
    <>
      {!compact ? (
        <AddressKindNote address={value} notBc1Note={notBc1Note} badgeSilent={badgeSilent} badgeBc1={badgeBc1} />
      ) : null}
      <CopyableText value={value} className={className} />
    </>
  )
}

export function DataBlock({ icon, label, hint, children }) {
  return (
    <div className="sp-flow-data">
      <div className="sp-flow-data-label">
        <img src={icon} alt="" className="sp-flow-data-icon" />
        <div className="min-w-0">
          <p className="sp-flow-data-title">
            {label}
          </p>
          {hint ? <p className="sp-flow-data-hint">{hint}</p> : null}
        </div>
      </div>
      {children ? <div className="sp-flow-data-body">{children}</div> : null}
    </div>
  )
}

/**
 * @param {{
 *   inputs: { txid: string, vout: number, script_pubkey?: string, has_sender_key?: boolean }[]
 *   signedLabel: string
 *   utxoLabel: string
 *   scriptLabel: string
 *   p2pkhNote?: string
 * }} props
 */
export function UtxoList({ inputs, signedLabel, utxoLabel, scriptLabel, p2pkhNote }) {
  if (!inputs?.length) return <p className="sp-flow-muted text-[11px]">—</p>
  return (
    <ul className="sp-utxo-list">
      {inputs.map((v, i) => {
        const scriptHex = v.script_pubkey || ''
        const type = scriptTypeLabel(scriptHex)
        return (
          <li key={`${v.txid}-${v.vout}-${i}`} className="sp-utxo-card">
            <div className="sp-utxo-card-head">
              <span className="sp-utxo-index">{utxoLabel.replace('{n}', String(i + 1))}</span>
              {v.has_sender_key ? <span className="sp-utxo-pill">{signedLabel}</span> : null}
            </div>
            <p className="sp-utxo-ref">
              <span className="font-semibold text-bp-600 dark:text-bp-canvas/80">{formatTxidShort(v.txid)}</span>
              <span className="inline-block whitespace-nowrap text-bp-500 dark:text-bp-200"> · vout {v.vout}</span>
            </p>
            {scriptHex ? (
              <div className="mt-1">
                {type === 'P2PKH' && p2pkhNote ? (
                  <p className="text-xs leading-relaxed text-bp-600 dark:text-bp-canvas/65">{p2pkhNote}</p>
                ) : null}
                <CopyableText label={type ? `${type} · ${scriptLabel}` : scriptLabel} value={scriptHex} />
              </div>
            ) : null}
          </li>
        )
      })}
    </ul>
  )
}

/**
 * @param {{ pubkey: string, label: string, hint?: string }} props
 */
export function PubkeyOutput({ pubkey, label, hint }) {
  if (!pubkey) return <p className="sp-flow-muted text-[11px]">—</p>
  return (
    <div>
      {hint ? <p className="mb-1 text-xs leading-relaxed text-bp-600 dark:text-bp-canvas/65">{hint}</p> : null}
      <CopyableText label={label} value={pubkey} />
    </div>
  )
}

/**
 * @param {{ outputs: string[], highlightSet: string[], matchedLabel: string, otherLabel: string }} props
 */
export function TxOutputList({ outputs, highlightSet, matchedLabel, otherLabel }) {
  if (!outputs?.length) return <p className="sp-flow-muted text-[11px]">—</p>
  const hi = new Set(highlightSet.map((h) => h.toLowerCase()))
  return (
    <ul className="space-y-1">
      {outputs.map((hex, i) => {
        const match = hi.has(hex.toLowerCase())
        return (
          <li key={`${hex}-${i}`}>
            <div className="mb-0.5 flex items-center gap-1.5">
              <span
                className={`rounded px-1.5 py-0.5 text-[11px] font-bold uppercase ${
                  match
                    ? 'bg-bp-blue/15 text-bp-blue dark:bg-bp-canvas/20 dark:text-bp-canvas'
                    : 'bg-bp-100 text-bp-500 dark:bg-bp-700/50 dark:text-bp-canvas/50'
                }`}
              >
                {match ? matchedLabel : otherLabel}
              </span>
            </div>
            <CopyableText
              value={hex}
              className={match ? 'ring-1 ring-bp-blue/20 dark:ring-bp-canvas/25' : ''}
            />
          </li>
        )
      })}
    </ul>
  )
}

/**
 * @param {{ steps: { icon: string, text: string }[] }} props
 */
export function ScanTimeline({ steps }) {
  return (
    <ol className="sp-scan-steps">
      {steps.map((s, i) => (
        <li key={i}>
          <img src={s.icon} alt="" className="sp-scan-step-icon" />
          <span className="text-[11px] leading-relaxed text-bp-700 dark:text-bp-canvas/85">{s.text}</span>
        </li>
      ))}
    </ol>
  )
}
