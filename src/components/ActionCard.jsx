/**
 * @param {{
 *   title: string
 *   description: string
 *   onClick: () => void
 *   icon?: import('react').ReactNode
 * }} props
 */
export default function ActionCard({ title, description, onClick, icon }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="sp-surface sp-action-card group flex w-full items-center gap-3.5 rounded-xl px-4 py-4 text-left transition hover:border-bp-blue/30 hover:shadow-md active:scale-[0.99] dark:hover:border-bp-canvas/45 sm:px-5"
    >
      {icon ? (
        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-bp-50 text-bp-blue ring-1 ring-bp-200 transition group-hover:bg-bp-100 dark:bg-bp-600/70 dark:text-bp-canvas dark:ring-bp-canvas/25 dark:group-hover:bg-bp-600/90">
          {icon}
        </span>
      ) : null}
      <span className="min-w-0 flex-1">
        <span className="block text-[15px] font-semibold leading-snug tracking-tight text-bp-blue dark:text-bp-canvas">{title}</span>
        <span className="mt-0.5 block text-xs font-medium leading-snug text-bp-600 dark:text-bp-200 sm:text-[13px]">{description}</span>
      </span>
      <span
        className="shrink-0 text-bp-400 transition group-hover:translate-x-0.5 group-hover:text-bp-blue dark:text-bp-400 dark:group-hover:text-bp-canvas"
        aria-hidden
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M9 18l6-6-6-6" />
        </svg>
      </span>
    </button>
  )
}
