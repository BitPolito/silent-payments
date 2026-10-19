export default function FlowProgress({ steps, maxIndex, onSelect, ariaLabel = 'Progress' }) {
  return <nav className="sp-stage-nav" aria-label={ariaLabel}>
    <ol>{steps.map((step, index) => <li key={step.id}>
      <button type="button" className="sp-stage-step" disabled={index > maxIndex} onClick={() => onSelect(step.id)} aria-label={step.label} aria-current={step.current ? 'step' : undefined} data-done={step.done || undefined}>
        <span className="sp-stage-number" aria-hidden>{step.done ? '✓' : index + 1}</span>
        <span>{step.label.replace(/^\d+\s*/, '')}</span>
      </button>
    </li>)}</ol>
  </nav>
}
