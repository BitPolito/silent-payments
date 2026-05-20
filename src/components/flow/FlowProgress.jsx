/**
 * @param {{ steps: { id: string, label: string, done: boolean, current: boolean }[], maxIndex: number, onSelect: (id: string) => void }} props
 */
export default function FlowProgress({ steps, maxIndex, onSelect }) {
  return (
    <nav className="sp-flow-rail" aria-label="Progress">
      <ol className="flex items-center gap-0">
        {steps.map((step, i) => {
          const reachable = i <= maxIndex
          const isLast = i === steps.length - 1
          return (
            <li key={step.id} className={`flex min-w-0 flex-1 items-center ${isLast ? 'flex-none' : ''}`}>
              <button
                type="button"
                disabled={!reachable}
                onClick={() => reachable && onSelect(step.id)}
                aria-current={step.current ? 'step' : undefined}
                className={`sp-flow-rail-dot ${step.current ? 'is-current' : ''} ${step.done ? 'is-done' : ''} ${reachable ? '' : 'is-locked'}`}
                title={step.label}
              >
                <span className="sr-only">
                  {i + 1}. {step.label}
                </span>
              </button>
              {!isLast ? <span className={`sp-flow-rail-line ${step.done ? 'is-done' : ''}`} aria-hidden /> : null}
            </li>
          )
        })}
      </ol>
      <div className="mt-1.5 flex justify-between gap-1 px-0.5">
        {steps.map((step) => (
          <span
            key={step.id}
            className={`min-w-0 flex-1 text-center text-[9px] font-semibold leading-tight ${
              step.current ? 'text-bp-blue dark:text-bp-canvas' : 'text-bp-400 dark:text-bp-canvas/45'
            } ${step.id === steps[steps.length - 1].id ? 'flex-none' : ''}`}
          >
            {step.label}
          </span>
        ))}
      </div>
    </nav>
  )
}
