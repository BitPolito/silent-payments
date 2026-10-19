import { useLocale } from '../i18n/useLocale'
import { BECH32M_DIGITS, BECH32M_LETTERS } from '../utils/bech32m'

function CharRow({ label, chars }) {
  return (
    <div>
      <span className="text-[10px] font-medium text-bp-500 dark:text-bp-canvas/70">{label}</span>
      <p className="mt-0.5 font-mono text-[10px] leading-relaxed tracking-widest text-bp-blue/90 dark:text-bp-canvas/90">
        {chars.split('').join(' ')}
      </p>
    </div>
  )
}

export default function Bech32Alphabet() {
  const { tr } = useLocale()

  return (
    <div className="rounded-lg border border-bp-200/80 bg-bp-50/50 px-2.5 py-2 dark:border-bp-500/45 dark:bg-bp-800/40">
      <p className="border-b border-bp-200/80 pb-2 text-[11px] leading-relaxed text-bp-600 dark:border-bp-500/35 dark:text-bp-canvas/75">
        {tr('genVanityLeadNote')}
      </p>
      <div className="space-y-1.5 pt-2">
        <CharRow label={tr('bech32LettersLabel')} chars={BECH32M_LETTERS} />
        <CharRow label={tr('bech32DigitsLabel')} chars={BECH32M_DIGITS} />
      </div>
    </div>
  )
}
