import BpIcon from './BpIcon'

const DOWNLOAD_CARD =
  'group flex w-full items-start gap-3 rounded-lg border border-bp-200 bg-white p-3 text-left transition hover:border-bp-blue/35 hover:bg-bp-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-bp-blue dark:border-bp-500/40 dark:bg-bp-800/50 dark:hover:border-bp-canvas/30 dark:hover:bg-bp-700/45 dark:focus-visible:ring-bp-canvas'

/**
 * @param {{ icon: string, title: string, hint: string, onClick: () => void }} props
 */
export default function DownloadAction({ icon, title, hint, onClick }) {
  return (
    <button type="button" onClick={onClick} className={DOWNLOAD_CARD}>
      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-bp-100 text-bp-blue dark:bg-bp-700/70 dark:text-bp-canvas">
        <BpIcon src={icon} className="h-4 w-4" />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-xs font-semibold text-bp-blue dark:text-bp-canvas">{title}</span>
        <span className="mt-0.5 block text-[10px] leading-snug text-bp-500 dark:text-bp-300">{hint}</span>
      </span>
      <span
        className="mt-0.5 shrink-0 text-sm font-bold text-bp-300 transition group-hover:translate-y-0.5 group-hover:text-bp-blue dark:text-bp-500 dark:group-hover:text-bp-canvas"
        aria-hidden
      >
        ↓
      </span>
    </button>
  )
}
