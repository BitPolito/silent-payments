import { useRef, useState } from 'react'
import { useLocale } from '../../i18n/useLocale'
import { evaluateGuess, investigation, publicOutputs } from './investigation'
import { investigationContent } from './investigationContent'
const newBoard = () => investigation(crypto.getRandomValues(new Uint32Array(1))[0])

export default function ObserverChallenge() {
  const { locale } = useLocale()
  const t = investigationContent[locale] || investigationContent.en
  const [rows, setRows] = useState(newBoard)
  const [mode, setMode] = useState('reuse')
  const [guesses, setGuesses] = useState([])
  const [receipt, setReceipt] = useState(false)
  const [revealed, setRevealed] = useState(false)
  const resultRef = useRef(null)
  const clue = rows.find((row) => row.owner === 'bob').id
  const score = evaluateGuess(rows, guesses)
  function reset(nextMode = mode, nextRows = rows) { setMode(nextMode); setRows(nextRows); setGuesses([]); setReceipt(false); setRevealed(false) }
  function toggle(id) { setGuesses((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]) }
  return <section className="sp-observer-challenge" aria-labelledby="challenge-heading">
    <div className="sp-challenge-heading"><div><p className="sp-eyebrow">{t.kicker}</p><h2 id="challenge-heading" className="text-3xl font-bold mt-3">{t.title}</h2><p className="sp-description mt-3">{t.intro}</p></div><button className="sp-btn-outline" onClick={() => reset('reuse', newBoard())}>{t.again} ↻</button></div>
    <div className="sp-challenge-controls"><div className="sp-mode-switch" role="group" aria-label={t.modes}>{['reuse', 'silent'].map((value) => <button key={value} aria-pressed={mode === value} onClick={() => reset(value)}>{t[value]}</button>)}</div>
      <label className="sp-challenge-receipt"><input type="checkbox" checked={receipt} disabled={revealed} onChange={(event) => setReceipt(event.target.checked)} />{t.receipt}</label>
    </div>
    <p className="sp-notice">{mode === 'reuse' ? t.known : t.unknown}</p>
    {receipt && <p className="sp-notice" role="status">{t.receiptText} <strong>#{clue + 1}</strong>. {t.receiptHint}</p>}
    <div className="sp-investigation-board">{publicOutputs(rows, mode).map((row) => <button key={row.id} className="sp-evidence-card" aria-label={`${t.select} ${row.id + 1}`} aria-pressed={guesses.includes(row.id)} disabled={revealed} onClick={() => toggle(row.id)}>
      <span className="flex justify-between items-center gap-2"><span className="sp-eyebrow">{t.output} #{row.id + 1}</span><span aria-hidden className="sp-evidence-mark">{guesses.includes(row.id) ? '✓' : '+'}</span></span>
      <strong className="sp-evidence-key">{row.destination}</strong><span className="sp-description text-xs">{t.amount}</span><span className="font-bold">{row.amount.toLocaleString(locale)} sats</span>
      {revealed && <span className="sp-evidence-answer">{rows[row.id].owner === 'bob' ? `● ${t.bob}` : `○ ${t.other}`}</span>}
    </button>)}</div>
    <div className="sp-challenge-controls"><p role="status">{guesses.length} {t.guesses}</p><button className="sp-btn-solid" disabled={revealed} onClick={() => { setRevealed(true); requestAnimationFrame(() => resultRef.current?.focus()) }}>{t.reveal} →</button></div>
    {!revealed && <p className="sp-description text-sm">{t.empty}</p>}
    {revealed && <div className="sp-challenge-result" ref={resultRef} tabIndex={-1} role="region" aria-label={t.result}>
      <h3 className="text-xl font-bold">{t.result}</h3><dl className="sp-lab-stats">{['correct', 'missed', 'mistaken'].map((key) => <div key={key}><dt>{t[key]}</dt><dd className="text-3xl font-bold">{score[key]}</dd></div>)}</dl>
      <p>{mode === 'reuse' ? t.lessonReuse : t.lessonSilent}</p><p className="sp-description mt-3 text-sm">{t.explanation}</p>
    </div>}
    <p className="sp-description text-xs mt-4">{t.note}</p>
  </section>
}
