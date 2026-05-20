import { useEffect, useState } from 'react'
import { ICON } from '../assets/icons'
import BpIcon from './BpIcon'

export default function ThemeToggle({ ariaLabel }) {
  const [mounted, setMounted] = useState(false)
  const [dark, setDark] = useState(false)

  useEffect(() => {
    setMounted(true)
    const saved = localStorage.getItem('theme')
    const isDark = saved === 'dark' || document.documentElement.classList.contains('dark')
    setDark(isDark)
  }, [])

  const toggle = () => {
    const next = !dark
    setDark(next)
    if (next) {
      document.documentElement.classList.add('dark')
      localStorage.setItem('theme', 'dark')
    } else {
      document.documentElement.classList.remove('dark')
      localStorage.setItem('theme', 'light')
    }
  }

  if (!mounted) {
    return <div className="h-8 w-14 shrink-0 rounded-full border border-bp-200 bg-bp-canvas dark:border-bp-500/45 dark:bg-bp-800/80" aria-hidden />
  }

  return (
    <button
      type="button"
      role="switch"
      aria-checked={dark}
      aria-label={ariaLabel}
      onClick={toggle}
      className="relative flex h-8 w-14 shrink-0 items-center rounded-full border border-bp-200 bg-bp-canvas px-1 shadow-sm transition hover:border-bp-300 dark:border-bp-500/45 dark:bg-bp-800/80 dark:hover:border-bp-400/60"
    >
      <span
        className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-bp-200 bg-bp-canvas shadow-md transition-[margin] duration-200 ease-out dark:border-bp-canvas/30 dark:bg-bp-canvas ${
          dark ? 'ml-auto' : 'mr-auto'
        }`}
      >
        <BpIcon src={dark ? ICON.moon : ICON.sun} className="h-3.5 w-3.5 text-bp-blue dark:text-bp-blue" />
      </span>
    </button>
  )
}
