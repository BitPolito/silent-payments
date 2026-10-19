import ObserverChallenge from './ObserverChallenge'
import { useState } from 'react'
import AppLink from '../../components/AppLink'
import { useLocale } from '../../i18n/useLocale'
import { pageURL } from '../../utils/navigation'
import { privacyContent } from './content'
import { MAX_PAYMENTS, paymentModel, STRATEGIES } from './model'

export default function PrivacyLab({ headingRef }) {
  const { locale, tr } = useLocale()
  const t = privacyContent[locale] || privacyContent.en
  const [strategy, setStrategy] = useState('reuse')
  const [count, setCount] = useState(2)
  const [selected, setSelected] = useState(0)
  const [perspective, setPerspective] = useState('observer')
  const [scanned, setScanned] = useState(0)
  const [answer, setAnswer] = useState(null)
  const [round, setRound] = useState(0)
  const [observerOpen, setObserverOpen] = useState(() => window.location.hash === '#observer')
  const model = paymentModel(strategy, count, selected)
  const reset = () => { setStrategy('reuse'); setCount(2); setSelected(0); setPerspective('observer'); setScanned(0); setAnswer(null); setRound((value) => value + 1) }
  return <>
    <div className="sp-page-header"><div>
      <AppLink className="sp-back-link" href={pageURL('home').href}>← {tr('uiBackHome')}</AppLink>
      <h1 ref={headingRef} tabIndex={-1}>{t.title}</h1><p className="sp-description">{t.intro}</p>
    </div><span className="sp-page-badge">01 / 03 · {tr('uiDemoOnly')}</span></div>
    <div className="sp-lab-layout">
      <section className="sp-lab-controls sp-surface" aria-labelledby="lab-strategy">
        <h2 id="lab-strategy" className="text-lg font-bold">{t.strategy}</h2>
        <div className="sp-lab-strategies" role="group" aria-label={t.strategy}>
          {STRATEGIES.map((mode, index) => <button key={mode} aria-pressed={mode === strategy} onClick={() => { setStrategy(mode); setScanned(0) }}><span aria-hidden>{index + 1}</span>{t.modes[mode]}</button>)}
        </div>
        <p className="sp-description text-sm">{t.descriptions[strategy]}</p>
        <div className="sp-notice mt-5"><p className="sp-eyebrow">{t.shared}</p><p className="mt-2 font-bold">{t.destinations[strategy]}</p></div>
        <details className="sp-studio-details"><summary>{locale === 'it' ? 'Dettagli e limiti' : 'Details and limits'}</summary><p className="text-xs">{t.disclosure}</p></details>
        <a className="sp-back-link" href="https://bips.dev/352/#overview" target="_blank" rel="noopener noreferrer">{t.source} ↗</a>
      </section>
      <section className="sp-lab-workbench" aria-labelledby="lab-stage">
        <div className="flex flex-wrap items-center justify-between gap-3"><h2 id="lab-stage" className="text-lg font-bold">{t.stage}</h2><button className="sp-back-link" onClick={reset}>{t.reset} ↺</button></div>
        <div className="sp-lab-toolbar"><div role="group" aria-label={t.viewpoint} className="sp-mode-switch">
          {['observer', 'receiver'].map((view) => <button key={view} aria-pressed={perspective === view} onClick={() => setPerspective(view)}>{t[view]}</button>)}
        </div><button className="sp-btn-solid" disabled={count >= MAX_PAYMENTS} onClick={() => setCount((value) => Math.min(MAX_PAYMENTS, value + 1))}>+ {t.add}</button></div>
        {count === MAX_PAYMENTS && <p role="status" className="sp-description text-sm">{t.limit}</p>}
        <div className="sp-lab-stats" aria-live="polite" aria-atomic="true">
          {[[count, t.count], [model.unique, t.unique], [model.matching.length, t.matches]].map(([value, label]) => <div key={label}><strong>{value}</strong><span>{label}</span></div>)}
        </div>
        <h3 className="font-bold">{t.ledger}</h3><p className="sp-description text-sm">{t.hint}</p>
        <div className="sp-lab-ledger">{model.rows.map((row) => {
          const match = model.matching.includes(row.id)
          const known = perspective === 'receiver' && (strategy !== 'silent' || row.id < scanned)
          return <button key={row.id} className="sp-lab-payment" data-linked={match || undefined} aria-pressed={row.id === selected} aria-label={`${t.select} ${row.id + 1}`} onClick={() => setSelected(row.id)}>
            <span className="sp-lab-payment-id">{String(row.id + 1).padStart(2, '0')}</span>
            <span><span className="sp-description block text-xs">{t.output}</span><strong className="font-mono">{row.destination}</strong></span>
            <span><span className="sp-description block text-xs">{t.amount}</span><strong>{row.amount.toLocaleString(locale)} sats</strong></span>
            <span className="sp-lab-link-label">{perspective === 'receiver' ? (known ? `✓ ${t.recognized}` : t.unscanned) : (row.id === selected ? t.selected : match ? t.linked : t.distinct)}</span>
          </button>
        })}</div>
        <p className="sp-notice" role="status">{t[`${strategy}Insight`]}</p>
        {perspective === 'receiver' && <div className="sp-surface rounded-xl p-5 space-y-3"><p className="text-sm">{t.walletInsight}</p>{strategy === 'silent' && <>
          <p className="sp-description text-sm">{t.scanHint}</p><button className="sp-btn-solid" onClick={() => setScanned(count)} disabled={scanned === count}>{t.scan}</button><p role="status">{scanned} / {count} {t.scanned}</p>
        </>}</div>}
      </section>
    </div>
    <details id="observer" open={observerOpen} onToggle={(event) => setObserverOpen(event.currentTarget.open)} className="sp-studio-details"><summary>{locale === 'it' ? 'Prova la vista dell’osservatore' : 'Try the observer’s view'}</summary><ObserverChallenge key={round} /></details>
    <section className="sp-lab-check sp-surface" aria-labelledby="lab-quiz"><div><p className="sp-eyebrow">{t.quizTitle}</p><h2 id="lab-quiz" className="text-xl font-bold mt-3">{t.question}</h2><div className="flex flex-wrap gap-3 mt-5">
      {['yes', 'no'].map((choice) => <button className="sp-btn-outline" aria-pressed={answer === choice} key={choice} onClick={() => setAnswer(choice)}>{t[choice]}</button>)}
    </div>{answer && <p className="sp-notice mt-4" role="status">{t[answer === 'no' ? 'correct' : 'incorrect']}</p>}</div>
    <div><p className="sp-description mb-4">{t.nextHint}</p><AppLink className="sp-btn-solid" href={pageURL('walkthrough').href}>{t.next} →</AppLink></div></section>
  </>
}
